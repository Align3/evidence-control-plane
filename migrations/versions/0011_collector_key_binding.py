"""EV-07 0011: collector keys, received wire retention, integrity events.

Claimed in `docs/data-model.md` before this file existed (DM-001).

An evidence key without a collector binding is a tenant-wide impersonation
credential. Existing bindings cannot be inferred honestly, so this migration
refuses registries that already contain evidence keys rather than assigning
them to a guessed collector.

Revision ID: 0011
Revises: 0010
"""

from __future__ import annotations

import re
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

INTEGRITY_EVENTS = "ingestion_integrity_events"
_TENANT_ID = re.compile(r"^[a-z0-9](?:[a-z0-9_]{0,44}[a-z0-9])?$")


def upgrade() -> None:
    bind = op.get_bind()
    # Any accepted evidence row necessarily references an evidence-namespace
    # key through 0010's composite FK, so this also proves evidence_records is
    # empty before adding the NOT NULL received-wire column below.
    if bind.execute(
        sa.text("SELECT EXISTS (SELECT 1 FROM keys WHERE namespace = 'evidence')")
    ).scalar_one():
        raise RuntimeError(
            "migration 0011 refuses existing evidence keys: their collector "
            "bindings cannot be inferred (SE-018)"
        )

    op.add_column("keys", sa.Column("collector_id", sa.Text(), nullable=True))
    op.create_foreign_key(
        "fk_keys_collector",
        "keys",
        "collectors",
        ["tenant_id", "collector_id"],
        ["tenant_id", "collector_id"],
        ondelete="RESTRICT",
        onupdate="RESTRICT",
    )
    op.create_check_constraint(
        "ck_keys_collector_binding",
        "keys",
        "(namespace = 'evidence' AND collector_id IS NOT NULL) OR "
        "(namespace = 'issuer' AND collector_id IS NULL)",
    )
    op.create_index("ix_keys_tenant_collector", "keys", ["tenant_id", "collector_id"])

    # F4: retain the complete canonical request exactly as received. DM-023's
    # signature-excluded canonical_bytes remains the customer signing input;
    # the issuer receipt binds this full wire byte string instead.
    op.add_column(
        "evidence_records",
        sa.Column("received_wire_bytes", sa.LargeBinary(), nullable=False),
    )

    # F5: rejected forks and content substitutions are tenant-visible,
    # append-only integrity events. They are deliberately not evidence record
    # types; whether they should acquire a signed evidence representation is a
    # separate specification question.
    op.create_table(
        INTEGRITY_EVENTS,
        sa.Column("event_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", sa.Text(), nullable=False),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("record_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("conflicting_record_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("stream_id", sa.Text(), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("submitted_wire_bytes", sa.LargeBinary(), nullable=False),
        sa.Column("existing_wire_bytes", sa.LargeBinary(), nullable=True),
        sa.Column("occurred_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("surfaced_to_tenant_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("tenant_id", "event_id", name="pk_ingestion_integrity_events"),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.tenant_id"],
            name="fk_ingestion_integrity_events_tenant",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.CheckConstraint(
            "event_type IN ('stream_fork', 'content_substitution')",
            name="ck_ingestion_integrity_events_type",
        ),
        postgresql_partition_by="LIST (tenant_id)",
    )
    op.create_index(
        "ix_ingestion_integrity_events_tenant_occurred",
        INTEGRITY_EVENTS,
        ["tenant_id", "occurred_at"],
    )
    op.execute(f"REVOKE ALL ON TABLE {INTEGRITY_EVENTS} FROM PUBLIC")

    for (tenant_id,) in bind.execute(sa.text("SELECT tenant_id FROM tenants")):
        if _TENANT_ID.fullmatch(tenant_id) is None:  # pragma: no cover - DB CHECK
            raise RuntimeError(f"unsafe tenant identifier in registry: {tenant_id!r}")
        partition = f"integrity_events_{tenant_id}"
        role = f"evidence_tenant_{tenant_id}"
        op.execute(
            f'CREATE TABLE "{partition}" PARTITION OF "{INTEGRITY_EVENTS}" '
            f"FOR VALUES IN ('{tenant_id}')"
        )
        op.execute(f'GRANT INSERT, SELECT ON TABLE "{partition}" TO "{role}"')
        op.execute(
            f'REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER '
            f'ON TABLE "{partition}" FROM "{role}"'
        )


def downgrade() -> None:
    # These two names existed briefly while 0011 was still unreleased. Keep
    # the idempotent cleanup so a developer database stamped by that draft can
    # still downgrade; a fresh upgrade never creates either constraint.
    op.execute(
        "ALTER TABLE evidence_records DROP CONSTRAINT IF EXISTS "
        "fk_evidence_records_collector_key_binding"
    )
    op.drop_table(INTEGRITY_EVENTS)
    op.drop_column("evidence_records", "received_wire_bytes")
    op.execute(
        "ALTER TABLE keys DROP CONSTRAINT IF EXISTS uq_keys_tenant_key_collector"
    )
    op.drop_index("ix_keys_tenant_collector", table_name="keys")
    op.drop_constraint("ck_keys_collector_binding", "keys", type_="check")
    op.drop_constraint("fk_keys_collector", "keys", type_="foreignkey")
    op.drop_column("keys", "collector_id")
