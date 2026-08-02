"""EV-07 0011: bind evidence signing keys to collector instances.

Claimed in `docs/data-model.md` before this file existed (DM-001).

An evidence key without a collector binding is a tenant-wide impersonation
credential. Existing bindings cannot be inferred honestly, so this migration
refuses registries that already contain evidence keys rather than assigning
them to a guessed collector.

Revision ID: 0011
Revises: 0010
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
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


def downgrade() -> None:
    # These two names existed briefly while 0011 was still unreleased. Keep
    # the idempotent cleanup so a developer database stamped by that draft can
    # still downgrade; a fresh upgrade never creates either constraint.
    op.execute(
        "ALTER TABLE evidence_records DROP CONSTRAINT IF EXISTS "
        "fk_evidence_records_collector_key_binding"
    )
    op.execute(
        "ALTER TABLE keys DROP CONSTRAINT IF EXISTS uq_keys_tenant_key_collector"
    )
    op.drop_index("ix_keys_tenant_collector", table_name="keys")
    op.drop_constraint("ck_keys_collector_binding", "keys", type_="check")
    op.drop_constraint("fk_keys_collector", "keys", type_="foreignkey")
    op.drop_column("keys", "collector_id")
