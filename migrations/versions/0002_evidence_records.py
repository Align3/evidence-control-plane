"""EV-06 0002: evidence_records, per-tenant partitioning, and role grants.

Claimed in `docs/data-model.md` §3 before this file existed (DM-001).

This migration is the whole of AC-012, AC-014 and SE-011/SE-012 as far as the
schema can carry them. Three things are load-bearing, and each is a decision
rather than a default:

1. **No grant is issued on the parent table, to any role.** Naming
   ``evidence_records`` is how a cross-tenant read would be written; because
   no application role holds a privilege on it, that query is refused before
   a predicate is ever evaluated. Per-tenant grants are issued against the
   partition, by `provision_tenant`.

2. **No DEFAULT partition.** Evidence for a tenant that has not been
   provisioned has nowhere to land and is rejected outright, rather than
   accumulating in a shared relation that no tenant role could safely be
   granted.

3. **UPDATE and DELETE are granted to nobody.** Not revoked-after-granting;
   never granted. The owner retains them, and the owner is the migrator
   credential (SE-012 §6, SE-024).

Deliberately absent: the foreign key from ``boundary_ref`` to ``boundaries``.
That table is created by EV-12 in migration 0003 and building it here would
cross this story's Touches set. The column exists and is NOT NULL; the
reference becomes enforceable when 0003 lands.

Revision ID: 0002
Revises: 0001
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLE = "evidence_records"
TENANT_ROLE_PREFIX = "evidence_tenant_"


def upgrade() -> None:
    op.create_table(
        TABLE,
        sa.Column("record_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", sa.Text(), nullable=False),
        sa.Column("record_type", sa.Text(), nullable=False),
        sa.Column("schema_version", sa.Text(), nullable=False),
        # FK to boundaries deferred to 0003 (EV-12) -- see module docstring.
        sa.Column("boundary_ref", sa.Text(), nullable=False),
        sa.Column("stream_id", sa.Text(), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("prev_digest", sa.LargeBinary(), nullable=True),
        sa.Column("record_digest", sa.LargeBinary(), nullable=False),
        sa.Column("collector_id", sa.Text(), nullable=False),
        sa.Column("key_id", sa.Text(), nullable=False),
        sa.Column("signature", sa.LargeBinary(), nullable=False),
        sa.Column("source_time", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("ingest_time", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("authoritative_time", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("clock_skew_ms", sa.Integer(), nullable=False),
        # Authoritative (DM-005, AC-015).
        sa.Column("canonical_bytes", sa.LargeBinary(), nullable=False),
        # Projection over canonical_bytes. Droppable and rebuildable; see
        # services/ledger/projection.py.
        sa.Column("body", postgresql.JSONB(), nullable=False),
        sa.Column("action_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("action_family", sa.Text(), nullable=True),
        # The partition key must appear in every unique constraint. record_id
        # is specified as unique *within tenant* anyway (evidence-spec §3), so
        # (tenant_id, record_id) is the correct key, not a compromise.
        sa.PrimaryKeyConstraint("tenant_id", "record_id", name="pk_evidence_records"),
        # ES-006: two records sharing (stream_id, sequence) are a fork, and a
        # fork is a fatal integrity failure that must be reported rather than
        # resolved. Enforcing it here makes detection a database guarantee
        # that no ingestion path can forget.
        sa.UniqueConstraint("tenant_id", "stream_id", "sequence",
                            name="uq_evidence_records_stream_sequence"),
        # Composite FKs: a record cannot cite a collector or key belonging to
        # another tenant. RESTRICT throughout -- DM-007 forbids any cascade
        # touching evidence.
        sa.ForeignKeyConstraint(
            ["tenant_id", "collector_id"],
            ["collectors.tenant_id", "collectors.collector_id"],
            name="fk_evidence_records_collector",
            ondelete="RESTRICT", onupdate="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "key_id"],
            ["keys.tenant_id", "keys.key_id"],
            name="fk_evidence_records_key",
            ondelete="RESTRICT", onupdate="RESTRICT",
        ),
        sa.CheckConstraint("octet_length(record_digest) = 32",
                           name="ck_evidence_records_digest_sha256"),
        sa.CheckConstraint(
            "prev_digest IS NULL OR octet_length(prev_digest) = 32",
            name="ck_evidence_records_prev_digest_sha256",
        ),
        # ES-006: sequence is monotonic within a stream, starting at 1.
        sa.CheckConstraint("sequence >= 1", name="ck_evidence_records_sequence_positive"),
        postgresql_partition_by="LIST (tenant_id)",
    )

    op.create_index("ix_evidence_records_tenant_action", TABLE,
                    ["tenant_id", "action_id"])
    op.create_index("ix_evidence_records_tenant_family_time", TABLE,
                    ["tenant_id", "action_family", "source_time"])
    op.create_index("ix_evidence_records_tenant_type_ingest", TABLE,
                    ["tenant_id", "record_type", "ingest_time"])

    # Nothing is granted on the parent -- deliberately. Revoking anyway so a
    # default privilege configured on the database cannot quietly supply one.
    op.execute(f"REVOKE ALL ON TABLE {TABLE} FROM PUBLIC")


def downgrade() -> None:
    # Tenant roles are created at provisioning time, not by a migration, so
    # they are discovered rather than listed. Leaving them behind would make
    # `downgrade` followed by `upgrade` land on a half-provisioned cluster.
    bind = op.get_bind()
    roles = [
        row[0]
        for row in bind.execute(
            sa.text("SELECT rolname FROM pg_roles WHERE rolname LIKE :pattern"),
            {"pattern": f"{TENANT_ROLE_PREFIX}%"},
        )
    ]
    op.drop_table(TABLE)  # partitions go with the parent
    for role in roles:
        if not role.replace(TENANT_ROLE_PREFIX, "", 1).replace("_", "").isalnum():
            continue  # pragma: no cover -- not a role this story created
        op.execute(f'DROP OWNED BY "{role}"')
        op.execute(f'DROP ROLE "{role}"')
