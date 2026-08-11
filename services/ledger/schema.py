"""Runtime table definitions for the ledger (`data-model.md` §2.1-§2.3, §2.6).

The migrations are the authority on what exists in the database; these
objects are how application code addresses it. `test_schema_matches_database`
reflects the live schema and compares, so the two cannot drift apart
unnoticed.

Note what is **not** here: a `Table` for the parent `evidence_records`.
Application code is given a handle to one tenant's partition and no way to
name the parent, so a cross-tenant query is not merely refused at execution
time -- it has nothing to be written against (SE-011).
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ENUM, JSONB, TIMESTAMP, UUID

from .naming import (
    EVIDENCE_PARENT_TABLE,
    POPULATION_PARENT_TABLE,
    TENANT_ID_SQL_PATTERN,
    partition_name,
    population_partition_name,
    validate_tenant_id,
)

metadata = MetaData()

deployment_profile = ENUM(
    "p1_hosted", "p2_vpc", "p3_sidecar", name="deployment_profile", create_type=False
)
key_custody = ENUM("client_held", "hosted_kms", name="key_custody", create_type=False)
collector_mode = ENUM(
    "checkpoint", "third_party", "observation_only", name="collector_mode",
    create_type=False,
)
key_namespace = ENUM("evidence", "issuer", name="key_namespace", create_type=False)


tenants = Table(
    "tenants",
    metadata,
    Column("tenant_id", Text, primary_key=True),
    Column("name", Text, nullable=False),
    Column("deployment_profile", deployment_profile, nullable=False),
    Column("key_custody", key_custody, nullable=False),
    Column("evidence_region", Text, nullable=False),
    Column("created_at", TIMESTAMP(timezone=True), nullable=False),
    CheckConstraint(
        f"tenant_id ~ '{TENANT_ID_SQL_PATTERN}'", name="ck_tenants_tenant_id_identifier"
    ),
)

collectors = Table(
    "collectors",
    metadata,
    Column("collector_id", Text, primary_key=True),
    # RESTRICT, never CASCADE (DM-007): deleting a tenant must not silently
    # take its collectors -- and through them the meaning of its evidence.
    Column(
        "tenant_id",
        Text,
        ForeignKey("tenants.tenant_id", ondelete="RESTRICT", onupdate="RESTRICT"),
        nullable=False,
    ),
    Column("implementation", Text, nullable=False),
    Column("version", Text, nullable=False),
    Column("mode", collector_mode, nullable=False),
    Column("expected_cadence_s", Integer, nullable=True),
    Column("registered_at", TIMESTAMP(timezone=True), nullable=False),
    Column("revoked_at", TIMESTAMP(timezone=True), nullable=True),
    UniqueConstraint("tenant_id", "collector_id", name="uq_collectors_tenant_collector"),
)

keys = Table(
    "keys",
    metadata,
    Column("key_id", Text, primary_key=True),
    Column(
        "tenant_id",
        Text,
        ForeignKey("tenants.tenant_id", ondelete="RESTRICT", onupdate="RESTRICT"),
        nullable=False,
    ),
    # DM-008: the namespace is a column, not a convention. Migration 0010
    # includes it in both evidence-record key FKs, with fixed discriminator
    # columns enforcing evidence for the customer proof and issuer for the
    # hosted receipt proof.
    Column("namespace", key_namespace, nullable=False),
    Column("collector_id", Text, nullable=True),
    Column("public_key", LargeBinary, nullable=False),
    Column("custody", key_custody, nullable=False),
    Column("valid_from", TIMESTAMP(timezone=True), nullable=False),
    Column("valid_until", TIMESTAMP(timezone=True), nullable=True),
    Column("continuity_signature", LargeBinary, nullable=True),
    Column(
        "predecessor_key_id",
        Text,
        ForeignKey("keys.key_id", ondelete="RESTRICT", onupdate="RESTRICT"),
        nullable=True,
    ),
    Column("compromised_from", TIMESTAMP(timezone=True), nullable=True),
    UniqueConstraint("tenant_id", "key_id", name="uq_keys_tenant_key"),
    ForeignKeyConstraint(
        ["tenant_id", "collector_id"],
        ["collectors.tenant_id", "collectors.collector_id"],
        name="fk_keys_collector",
        ondelete="RESTRICT",
        onupdate="RESTRICT",
    ),
)


#: Columns of `evidence_records` that are a cache over `canonical_bytes` and
#: may be dropped and rebuilt at will (DM-005, DM-013, AC-015).
PROJECTION_COLUMNS: tuple[str, ...] = ("body", "action_id", "action_family")

#: Derived from `canonical_bytes` and repairable in place. They carry no
#: identity, partition or uniqueness guarantee, so `rebuild_projection` may
#: recompute them without dropping a constraint to do it (DM-005).
REPAIRABLE_DERIVED_COLUMNS: tuple[str, ...] = (
    "prev_digest",
    "record_digest",
    "collector_id",
    "source_time",
    "authoritative_time",
)

#: Ingestion observations derived from the separately issuer-signed receipt
#: attached to a customer-origin record (ES-019, ES-030, DM-024).
RECEIPT_DERIVED_COLUMNS: tuple[str, ...] = ("ingest_time", "clock_skew_ms")

#: Columns parsed from `canonical_bytes` that carry constraints the ledger's
#: integrity depends on -- the partition key, the record identity, and the
#: fork-detection unique constraint (ES-006). They are verified against the
#: canonical bytes but never rewritten: rewriting the partition key would
#: move rows between partitions, and rewriting (stream_id, sequence) could
#: silently resolve a fork that ES-006 says must be reported. A mismatch
#: here is an integrity failure to surface, not a cache miss to repair.
VERIFIED_HEADER_COLUMNS: tuple[str, ...] = (
    "record_id",
    "tenant_id",
    "record_type",
    "schema_version",
    "boundary_ref",
    "stream_id",
    "sequence",
)

#: Every column either authoritative signed byte string determines. DM-005
#: says each one must be reproducible from its actual attestor's bytes.
CANONICAL_DERIVED_COLUMNS: tuple[str, ...] = (
    *VERIFIED_HEADER_COLUMNS,
    *REPAIRABLE_DERIVED_COLUMNS,
    *RECEIPT_DERIVED_COLUMNS,
    *PROJECTION_COLUMNS,
)


def _evidence_columns() -> list[Column[Any]]:
    """The `evidence_records` column list (`data-model.md` §2.6).

    Fresh objects each call: a `Column` belongs to one `Table`.
    """
    return [
        Column("record_id", UUID(as_uuid=True), nullable=False),
        Column("tenant_id", Text, nullable=False),
        Column("record_type", Text, nullable=False),
        Column("schema_version", Text, nullable=False),
        Column("boundary_ref", Text, nullable=False),
        Column("stream_id", Text, nullable=False),
        Column("sequence", BigInteger, nullable=False),
        Column("prev_digest", LargeBinary, nullable=True),
        Column("record_digest", LargeBinary, nullable=False),
        Column("collector_id", Text, nullable=True),
        Column("key_id", Text, nullable=False),
        Column(
            "record_key_namespace",
            key_namespace,
            nullable=False,
            server_default="evidence",
        ),
        Column("signature", LargeBinary, nullable=False),
        Column("source_time", TIMESTAMP(timezone=True), nullable=False),
        Column("ingest_time", TIMESTAMP(timezone=True), nullable=True),
        Column("authoritative_time", TIMESTAMP(timezone=True), nullable=True),
        Column("clock_skew_ms", Integer, nullable=True),
        # Authoritative. Everything else about the record is derived from it.
        Column("canonical_bytes", LargeBinary, nullable=False),
        # Exact canonical full record, including its primary signature member.
        # Customer-ingestion receipts bind this byte string.
        Column("received_wire_bytes", LargeBinary, nullable=False),
        Column("receipt_key_id", Text, nullable=True),
        Column(
            "receipt_key_namespace",
            key_namespace,
            nullable=True,
        ),
        Column("receipt_signature", LargeBinary, nullable=True),
        Column("receipt_canonical_bytes", LargeBinary, nullable=True),
        # Projection (PROJECTION_COLUMNS) -- rebuildable, never trusted.
        Column("body", JSONB, nullable=False),
        Column("action_id", UUID(as_uuid=True), nullable=True),
        Column("action_family", Text, nullable=True),
    ]


def _integrity_event_columns() -> list[Column[Any]]:
    return [
        Column("event_id", UUID(as_uuid=True), nullable=False),
        Column("tenant_id", Text, nullable=False),
        Column("event_type", Text, nullable=False),
        Column("record_id", UUID(as_uuid=True), nullable=False),
        Column("conflicting_record_id", UUID(as_uuid=True), nullable=True),
        Column("stream_id", Text, nullable=False),
        Column("sequence", BigInteger, nullable=False),
        Column("submitted_wire_bytes", LargeBinary, nullable=False),
        Column("existing_wire_bytes", LargeBinary, nullable=True),
        Column("occurred_at", TIMESTAMP(timezone=True), nullable=False),
        Column("surfaced_to_tenant_at", TIMESTAMP(timezone=True), nullable=False),
    ]


def _population_columns() -> list[Column[Any]]:
    return [
        Column("population_ref", Text, nullable=False),
        Column("tenant_id", Text, nullable=False),
        Column("boundary_ref", Text, nullable=False),
        Column("stream_id", Text, nullable=False),
        Column("sequence", BigInteger, nullable=False),
        Column("prev_digest", LargeBinary, nullable=True),
        Column("record_digest", LargeBinary, nullable=False),
        Column("action_family", Text, nullable=False),
        Column("destination_system", Text, nullable=False),
        Column("window_start", TIMESTAMP(timezone=True), nullable=False),
        Column("window_end", TIMESTAMP(timezone=True), nullable=False),
        Column("enumeration_query", JSONB, nullable=False),
        Column("identifier_digest", LargeBinary, nullable=True),
        Column("identifiers", JSONB, nullable=True),
        Column("count", BigInteger, nullable=False),
        Column("pagination_complete", Boolean, nullable=False),
        Column("result_cap_hit", Boolean, nullable=False),
        Column("retrieved_at", TIMESTAMP(timezone=True), nullable=False),
        Column("authoritative_timestamps", JSONB, nullable=False),
        Column("source_time", TIMESTAMP(timezone=True), nullable=False),
        Column("authoritative_time", TIMESTAMP(timezone=True), nullable=True),
        Column("key_id", Text, nullable=False),
        Column("key_namespace", key_namespace, nullable=False, server_default="issuer"),
        Column("signature", LargeBinary, nullable=False),
        Column("canonical_bytes", LargeBinary, nullable=False),
        Column("received_wire_bytes", LargeBinary, nullable=False),
    ]


_partition_cache: dict[str, Table] = {}


def evidence_partition(tenant_id: str) -> Table:
    """Return a `Table` addressing exactly one tenant's evidence partition.

    This is the only handle on evidence that application code is given. It
    names a single partition, so a query written against it cannot reach
    another tenant, and the role assumed to execute it holds privileges on
    nothing else besides.
    """
    validate_tenant_id(tenant_id)
    name = partition_name(tenant_id)
    cached = _partition_cache.get(name)
    if cached is not None:
        return cached
    table = Table(
        name,
        MetaData(),
        *_evidence_columns(),
        # The partition key must appear in every unique constraint, so the
        # primary key is (tenant_id, record_id) rather than record_id alone.
        # That is also what the envelope specifies: record_id is "unique
        # within tenant" (evidence-spec.md §3).
        UniqueConstraint("tenant_id", "record_id"),
        # Fork detection as a database guarantee, not application logic
        # (ES-006).
        UniqueConstraint("tenant_id", "stream_id", "sequence"),
        Index(None, "tenant_id", "action_id"),
        Index(None, "tenant_id", "action_family", "source_time"),
        Index(None, "tenant_id", "record_type", "ingest_time"),
    )
    _partition_cache[name] = table
    return table


def integrity_event_partition(tenant_id: str) -> Table:
    """Return the tenant-scoped append-only integrity-event relation."""

    from .naming import integrity_event_partition_name

    name = integrity_event_partition_name(tenant_id)
    cached = _partition_cache.get(name)
    if cached is not None:
        return cached
    table = Table(
        name,
        MetaData(),
        *_integrity_event_columns(),
        UniqueConstraint("tenant_id", "event_id"),
        Index(None, "tenant_id", "occurred_at"),
    )
    _partition_cache[name] = table
    return table


def population_partition(tenant_id: str) -> Table:
    """Return the tenant-scoped issuer-observation denominator relation."""

    name = population_partition_name(tenant_id)
    cached = _partition_cache.get(name)
    if cached is not None:
        return cached
    table = Table(
        name,
        MetaData(),
        *_population_columns(),
        UniqueConstraint("tenant_id", "population_ref"),
        UniqueConstraint("tenant_id", "stream_id", "sequence"),
        Index(
            None,
            "tenant_id",
            "action_family",
            "destination_system",
            "window_start",
            "window_end",
        ),
    )
    _partition_cache[name] = table
    return table


__all__ = [
    "EVIDENCE_PARENT_TABLE",
    "POPULATION_PARENT_TABLE",
    "PROJECTION_COLUMNS",
    "RECEIPT_DERIVED_COLUMNS",
    "VERIFIED_HEADER_COLUMNS",
    "collectors",
    "evidence_partition",
    "integrity_event_partition",
    "population_partition",
    "keys",
    "metadata",
    "tenants",
]
