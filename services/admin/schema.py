"""Runtime table definitions for the boundary and qualification relations.

Migration 0012 is the authority on what exists in the database; these objects
are how application code addresses it, and
`tests/unit/test_boundary_schema_invariants.py` reflects the live schema and
compares, so the two cannot drift apart unnoticed.

Deliberately separate from `services.ledger.schema` rather than appended to
it. That module belongs to EV-06 and describes the evidence path; this one
describes the administrative path, and the two are reached by different
credentials (SE-012 §6).
"""

from __future__ import annotations

from sqlalchemy import (
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
from sqlalchemy.dialects.postgresql import ENUM, JSONB, TIMESTAMP

metadata = MetaData()

#: Declaration order is strength order, strongest first
#: (`coverage-methodology.md` §3). Postgres orders enum labels by declaration,
#: so `'c1' < 'c2'` in SQL means "stronger than" without a lookup table.
DENOMINATOR_CLASS_LABELS: tuple[str, ...] = ("c1", "c2", "c3", "c4", "c5")

denominator_class = ENUM(
    *DENOMINATOR_CLASS_LABELS, name="denominator_class", create_type=False
)
key_namespace = ENUM("evidence", "issuer", name="key_namespace", create_type=False)

#: Tenant-scoped relations this story adds. Each carries row-level security
#: for DM-022's reason; `assert_boundary_tables_isolated` checks it.
ADMIN_TABLES: tuple[str, ...] = (
    "boundaries",
    "qualification_records",
    "boundary_action_families",
)

#: The trigger name suffixes migration 0012 attaches to every relation above.
IMMUTABILITY_TRIGGER_SUFFIX = "_refuse_mutation"
TRUNCATE_TRIGGER_SUFFIX = "_refuse_truncate"


qualification_records = Table(
    "qualification_records",
    metadata,
    Column("qualification_ref", Text, primary_key=True),
    Column(
        "tenant_id",
        Text,
        ForeignKey("tenants.tenant_id", ondelete="RESTRICT", onupdate="RESTRICT"),
        nullable=False,
    ),
    Column("action_family", Text, nullable=False),
    Column("destination_system", Text, nullable=False),
    Column("assigned_class", denominator_class, nullable=False),
    # CM-010 / AC-008: independent capabilities, recorded independently.
    Column("enumeration_capable", Boolean, nullable=False),
    Column("confirmation_capable", Boolean, nullable=False),
    Column("identity_isolation_attribute", Text, nullable=True),
    Column("identity_vendor_settable", Boolean, nullable=False),
    Column("authoritative_time_available", Boolean, nullable=False),
    Column("settlement_lag_s", Integer, nullable=False),
    Column("source_retention_days", Integer, nullable=False),
    Column("deletion_traceless_possible", Boolean, nullable=False),
    # Authoritative (ES-021, DM-023). Every projected column above is
    # rebuildable from it.
    Column("canonical_bytes", LargeBinary, nullable=False),
    Column("body", JSONB, nullable=False),
    Column("key_id", Text, nullable=False),
    Column("key_namespace", key_namespace, nullable=False, server_default="evidence"),
    Column("signature", LargeBinary, nullable=False),
    Column("qualified_at", TIMESTAMP(timezone=True), nullable=False),
    Column("revalidate_after", TIMESTAMP(timezone=True), nullable=False),
    ForeignKeyConstraint(
        ["tenant_id", "key_id", "key_namespace"],
        ["keys.tenant_id", "keys.key_id", "keys.namespace"],
        name="fk_qualification_records_key",
        ondelete="RESTRICT",
        onupdate="RESTRICT",
    ),
    CheckConstraint(
        "key_namespace = 'evidence'::key_namespace",
        name="ck_qualification_records_key_namespace_evidence",
    ),
    UniqueConstraint(
        "tenant_id",
        "qualification_ref",
        "action_family",
        "destination_system",
        name="uq_qualification_records_scope",
    ),
    UniqueConstraint(
        "tenant_id",
        "action_family",
        "destination_system",
        "qualified_at",
        name="uq_qualification_records_triple_instant",
    ),
    Index(
        "ix_qualification_records_triple",
        "tenant_id",
        "action_family",
        "destination_system",
        "qualified_at",
    ),
)


boundaries = Table(
    "boundaries",
    metadata,
    Column("boundary_ref", Text, primary_key=True),
    Column(
        "tenant_id",
        Text,
        ForeignKey("tenants.tenant_id", ondelete="RESTRICT", onupdate="RESTRICT"),
        nullable=False,
    ),
    Column("name", Text, nullable=False),
    Column("version", Integer, nullable=False),
    Column("canonical_bytes", LargeBinary, nullable=False),
    Column("body", JSONB, nullable=False),
    Column("key_id", Text, nullable=False),
    Column("key_namespace", key_namespace, nullable=False, server_default="evidence"),
    Column("signature", LargeBinary, nullable=False),
    Column("window_start", TIMESTAMP(timezone=True), nullable=False),
    Column("window_end", TIMESTAMP(timezone=True), nullable=False),
    # Hosted observation, never read from the signed body (AR-027).
    Column("recorded_at", TIMESTAMP(timezone=True), nullable=False),
    ForeignKeyConstraint(
        ["tenant_id", "key_id", "key_namespace"],
        ["keys.tenant_id", "keys.key_id", "keys.namespace"],
        name="fk_boundaries_key",
        ondelete="RESTRICT",
        onupdate="RESTRICT",
    ),
    UniqueConstraint("tenant_id", "name", "version", name="uq_boundaries_version"),
    UniqueConstraint("tenant_id", "boundary_ref", name="uq_boundaries_tenant_ref"),
    Index("ix_boundaries_tenant_name_version", "tenant_id", "name", "version"),
)


boundary_action_families = Table(
    "boundary_action_families",
    metadata,
    Column("tenant_id", Text, primary_key=True),
    Column("boundary_ref", Text, primary_key=True),
    Column("action_family", Text, primary_key=True),
    # ES-009 as a NOT NULL: a family without a qualification reference has no
    # row it could occupy.
    Column("qualification_ref", Text, nullable=False),
    Column("destination_system", Text, nullable=False),
    Column("fail_behaviour", Text, nullable=False),
    ForeignKeyConstraint(
        ["tenant_id", "boundary_ref"],
        ["boundaries.tenant_id", "boundaries.boundary_ref"],
        name="fk_boundary_action_families_boundary",
        ondelete="RESTRICT",
        onupdate="RESTRICT",
    ),
    ForeignKeyConstraint(
        ["tenant_id", "qualification_ref", "action_family", "destination_system"],
        [
            "qualification_records.tenant_id",
            "qualification_records.qualification_ref",
            "qualification_records.action_family",
            "qualification_records.destination_system",
        ],
        name="fk_boundary_action_families_qualification",
        ondelete="RESTRICT",
        onupdate="RESTRICT",
    ),
    Index(
        "ix_boundary_action_families_qualification",
        "tenant_id",
        "qualification_ref",
    ),
)


__all__ = [
    "ADMIN_TABLES",
    "DENOMINATOR_CLASS_LABELS",
    "IMMUTABILITY_TRIGGER_SUFFIX",
    "TRUNCATE_TRIGGER_SUFFIX",
    "boundaries",
    "boundary_action_families",
    "metadata",
    "qualification_records",
]
