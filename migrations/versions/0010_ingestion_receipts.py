"""EV-27 0010: issuer-signed ingestion receipts.

Claimed in `docs/data-model.md` before this file existed (DM-001).

The migration deliberately refuses a non-empty ledger. Existing rows have no
honest hosted receipt observation, and fabricating one during migration would
turn missing evidence into issuer-signed fiction (DM-024).

Revision ID: 0010
Revises: 0002
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLE = "evidence_records"


def upgrade() -> None:
    bind = op.get_bind()
    if bind.execute(
        sa.text(f'SELECT EXISTS (SELECT 1 FROM "{TABLE}")')  # noqa: S608 -- constant
    ).scalar_one():
        raise RuntimeError(
            "migration 0010 refuses a non-empty ledger: historical rows have no "
            "issuer-observed ingestion receipt (DM-024)"
        )

    op.add_column(TABLE, sa.Column("receipt_key_id", sa.Text(), nullable=False))
    op.add_column(TABLE, sa.Column("receipt_signature", sa.LargeBinary(), nullable=False))
    op.add_column(
        TABLE, sa.Column("receipt_canonical_bytes", sa.LargeBinary(), nullable=False)
    )
    op.create_foreign_key(
        "fk_evidence_records_receipt_key",
        TABLE,
        "keys",
        ["tenant_id", "receipt_key_id"],
        ["tenant_id", "key_id"],
        ondelete="RESTRICT",
        onupdate="RESTRICT",
    )
    op.create_check_constraint(
        "ck_evidence_records_receipt_signature_ed25519",
        TABLE,
        "octet_length(receipt_signature) = 64",
    )
    op.create_check_constraint(
        "ck_evidence_records_receipt_bytes_present",
        TABLE,
        "octet_length(receipt_canonical_bytes) > 0",
    )
    # A server default can create a timestamp without a matching signed
    # receipt. EV-07 supplies both in one INSERT after signing the receipt.
    op.alter_column(TABLE, "ingest_time", server_default=None)


def downgrade() -> None:
    op.alter_column(TABLE, "ingest_time", server_default=sa.text("now()"))
    op.drop_constraint("ck_evidence_records_receipt_bytes_present", TABLE, type_="check")
    op.drop_constraint(
        "ck_evidence_records_receipt_signature_ed25519", TABLE, type_="check"
    )
    op.drop_constraint("fk_evidence_records_receipt_key", TABLE, type_="foreignkey")
    op.drop_column(TABLE, "receipt_canonical_bytes")
    op.drop_column(TABLE, "receipt_signature")
    op.drop_column(TABLE, "receipt_key_id")
