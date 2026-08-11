"""EV-40 0013: structural record-origin namespace dispatch.

Claimed in ``docs/data-model.md`` before this file existed (DM-001/DM-025).

Revision ID: 0013
Revises: 0012
"""

from __future__ import annotations

import re
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

EVIDENCE = "evidence_records"
POPULATION = "population_records"
TENANT_ROLE_PREFIX = "evidence_tenant_"
_TENANT_ID = re.compile(r"^[a-z0-9](?:[a-z0-9_]{0,44}[a-z0-9])?$")
KEY_NAMESPACE = postgresql.ENUM(
    "evidence", "issuer", name="key_namespace", create_type=False
)


def _drop_old_receipt_checks() -> None:
    op.drop_constraint(
        "ck_evidence_records_key_namespace_evidence", EVIDENCE, type_="check"
    )
    op.drop_constraint(
        "ck_evidence_records_receipt_key_namespace_issuer", EVIDENCE, type_="check"
    )
    op.drop_constraint(
        "ck_evidence_records_receipt_signature_ed25519", EVIDENCE, type_="check"
    )
    op.drop_constraint(
        "ck_evidence_records_receipt_bytes_present", EVIDENCE, type_="check"
    )


def upgrade() -> None:
    _drop_old_receipt_checks()
    for column in (
        "collector_id",
        "ingest_time",
        "clock_skew_ms",
        "receipt_key_id",
        "receipt_key_namespace",
        "receipt_signature",
        "receipt_canonical_bytes",
    ):
        op.alter_column(EVIDENCE, column, nullable=True)

    # PopulationRecord has its own append-only denominator table. Allowing it
    # into the generic customer-ingestion table would restore a second storage
    # path with different namespace and receipt invariants.
    op.create_check_constraint(
        "ck_evidence_records_origin_namespace",
        EVIDENCE,
        "("
        "(record_type IN ('ExternalConfirmation', 'RevocationRecord') "
        " AND record_key_namespace = 'issuer'::key_namespace) OR "
        "(record_type IN ("
        "'AssuranceBoundary', 'QualificationRecord', 'AgentIdentity', "
        "'ActionProposal', 'AuthorityDecision', 'HumanReview', "
        "'ExecutionReceipt', 'FinalityRecord', 'OutcomeRecord', "
        "'CoverageGap', 'AttestationWindow') "
        " AND record_key_namespace = 'evidence'::key_namespace))",
    )
    op.create_check_constraint(
        "ck_evidence_records_origin_metadata",
        EVIDENCE,
        "(record_key_namespace = 'issuer'::key_namespace "
        " AND collector_id IS NULL AND ingest_time IS NULL AND clock_skew_ms IS NULL "
        " AND receipt_key_id IS NULL AND receipt_key_namespace IS NULL "
        " AND receipt_signature IS NULL AND receipt_canonical_bytes IS NULL) OR "
        "(record_key_namespace = 'evidence'::key_namespace "
        " AND collector_id IS NOT NULL AND ingest_time IS NOT NULL "
        " AND clock_skew_ms IS NOT NULL AND receipt_key_id IS NOT NULL "
        " AND receipt_key_namespace = 'issuer'::key_namespace "
        " AND octet_length(receipt_signature) = 64 "
        " AND octet_length(receipt_canonical_bytes) > 0)",
    )

    op.create_table(
        POPULATION,
        sa.Column("population_ref", sa.Text(), nullable=False),
        sa.Column("tenant_id", sa.Text(), nullable=False),
        sa.Column("boundary_ref", sa.Text(), nullable=False),
        sa.Column("stream_id", sa.Text(), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("prev_digest", sa.LargeBinary(), nullable=True),
        sa.Column("record_digest", sa.LargeBinary(), nullable=False),
        sa.Column("action_family", sa.Text(), nullable=False),
        sa.Column("destination_system", sa.Text(), nullable=False),
        sa.Column("window_start", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("window_end", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("enumeration_query", postgresql.JSONB(), nullable=False),
        sa.Column("identifier_digest", sa.LargeBinary(), nullable=True),
        sa.Column("identifiers", postgresql.JSONB(), nullable=True),
        sa.Column("count", sa.BigInteger(), nullable=False),
        sa.Column("pagination_complete", sa.Boolean(), nullable=False),
        sa.Column("result_cap_hit", sa.Boolean(), nullable=False),
        sa.Column("retrieved_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("authoritative_timestamps", postgresql.JSONB(), nullable=False),
        sa.Column("source_time", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("authoritative_time", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("key_id", sa.Text(), nullable=False),
        sa.Column(
            "key_namespace",
            KEY_NAMESPACE,
            nullable=False,
            server_default=sa.text("'issuer'::key_namespace"),
        ),
        sa.Column("signature", sa.LargeBinary(), nullable=False),
        sa.Column("canonical_bytes", sa.LargeBinary(), nullable=False),
        sa.Column("received_wire_bytes", sa.LargeBinary(), nullable=False),
        sa.PrimaryKeyConstraint(
            "tenant_id", "population_ref", name="pk_population_records"
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "stream_id",
            "sequence",
            name="uq_population_records_stream_sequence",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.tenant_id"],
            name="fk_population_records_tenant",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "boundary_ref"],
            ["boundaries.tenant_id", "boundaries.boundary_ref"],
            name="fk_population_records_boundary",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "key_id", "key_namespace"],
            ["keys.tenant_id", "keys.key_id", "keys.namespace"],
            name="fk_population_records_key",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.CheckConstraint(
            "key_namespace = 'issuer'::key_namespace",
            name="ck_population_records_key_namespace_issuer",
        ),
        sa.CheckConstraint(
            "octet_length(record_digest) = 32",
            name="ck_population_records_digest_sha256",
        ),
        sa.CheckConstraint(
            "prev_digest IS NULL OR octet_length(prev_digest) = 32",
            name="ck_population_records_prev_digest_sha256",
        ),
        sa.CheckConstraint(
            "octet_length(signature) = 64",
            name="ck_population_records_signature_ed25519",
        ),
        sa.CheckConstraint(
            "octet_length(canonical_bytes) > 0 AND octet_length(received_wire_bytes) > 0",
            name="ck_population_records_canonical_bytes_present",
        ),
        sa.CheckConstraint("sequence >= 1", name="ck_population_records_sequence_positive"),
        sa.CheckConstraint("count >= 0", name="ck_population_records_count_nonnegative"),
        sa.CheckConstraint(
            "window_start < window_end", name="ck_population_records_window_order"
        ),
        sa.CheckConstraint(
            "(identifiers IS NULL) <> (identifier_digest IS NULL)",
            name="ck_population_records_identifier_representation",
        ),
        postgresql_partition_by="LIST (tenant_id)",
    )
    op.create_index(
        "ix_population_records_tenant_window",
        POPULATION,
        ["tenant_id", "action_family", "destination_system", "window_start", "window_end"],
    )
    op.execute(f"REVOKE ALL ON TABLE {POPULATION} FROM PUBLIC")

    bind = op.get_bind()
    for (tenant_id,) in bind.execute(sa.text("SELECT tenant_id FROM tenants")):
        if _TENANT_ID.fullmatch(tenant_id) is None:  # pragma: no cover - DB CHECK
            raise RuntimeError(f"unsafe tenant identifier in registry: {tenant_id!r}")
        partition = f"population_{tenant_id}"
        role = f"{TENANT_ROLE_PREFIX}{tenant_id}"
        op.execute(
            f'CREATE TABLE "{partition}" PARTITION OF "{POPULATION}" '
            f"FOR VALUES IN ('{tenant_id}')"
        )
        op.execute(f'GRANT INSERT, SELECT ON TABLE "{partition}" TO "{role}"')
        op.execute(
            f'REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER '
            f'ON TABLE "{partition}" FROM "{role}"'
        )


def downgrade() -> None:
    op.drop_table(POPULATION)
    op.drop_constraint("ck_evidence_records_origin_metadata", EVIDENCE, type_="check")
    op.drop_constraint("ck_evidence_records_origin_namespace", EVIDENCE, type_="check")
    # Revision 0012 cannot represent a primary issuer observation: all rows
    # require a customer collector and a separately signed receipt. Downgrade
    # is therefore necessarily lossy for the newly introduced category, just
    # as dropping population_records is. Remove those rows before restoring
    # the old NOT NULL shape so a full test teardown remains executable.
    op.execute(
        "DELETE FROM evidence_records "
        "WHERE record_key_namespace = 'issuer'::key_namespace"
    )
    for column in (
        "collector_id",
        "ingest_time",
        "clock_skew_ms",
        "receipt_key_id",
        "receipt_key_namespace",
        "receipt_signature",
        "receipt_canonical_bytes",
    ):
        op.alter_column(EVIDENCE, column, nullable=False)
    op.create_check_constraint(
        "ck_evidence_records_key_namespace_evidence",
        EVIDENCE,
        "record_key_namespace = 'evidence'::key_namespace",
    )
    op.create_check_constraint(
        "ck_evidence_records_receipt_key_namespace_issuer",
        EVIDENCE,
        "receipt_key_namespace = 'issuer'::key_namespace",
    )
    op.create_check_constraint(
        "ck_evidence_records_receipt_signature_ed25519",
        EVIDENCE,
        "octet_length(receipt_signature) = 64",
    )
    op.create_check_constraint(
        "ck_evidence_records_receipt_bytes_present",
        EVIDENCE,
        "octet_length(receipt_canonical_bytes) > 0",
    )
