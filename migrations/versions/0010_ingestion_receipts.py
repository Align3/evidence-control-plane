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
from sqlalchemy.dialects import postgresql

revision: str = "0010"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLE = "evidence_records"
KEY_NAMESPACE = postgresql.ENUM(
    "evidence", "issuer", name="key_namespace", create_type=False
)


def upgrade() -> None:
    bind = op.get_bind()
    if bind.execute(
        sa.text(f'SELECT EXISTS (SELECT 1 FROM "{TABLE}")')  # noqa: S608 -- constant
    ).scalar_one():
        raise RuntimeError(
            "migration 0010 refuses a non-empty ledger: historical rows have no "
            "issuer-observed ingestion receipt (DM-024)"
        )

    # PostgreSQL has no constant predicate in FK syntax. Fixed discriminator
    # columns plus CHECKs make the namespace predicates structural: callers
    # cannot turn an issuer key into an evidence key (or vice versa) by
    # choosing which keyring to place it in.
    op.add_column(
        TABLE,
        sa.Column(
            "record_key_namespace",
            KEY_NAMESPACE,
            nullable=False,
            server_default=sa.text("'evidence'::key_namespace"),
        ),
    )
    op.add_column(TABLE, sa.Column("receipt_key_id", sa.Text(), nullable=False))
    op.add_column(
        TABLE,
        sa.Column(
            "receipt_key_namespace",
            KEY_NAMESPACE,
            nullable=False,
            server_default=sa.text("'issuer'::key_namespace"),
        ),
    )
    op.add_column(TABLE, sa.Column("receipt_signature", sa.LargeBinary(), nullable=False))
    op.add_column(
        TABLE, sa.Column("receipt_canonical_bytes", sa.LargeBinary(), nullable=False)
    )
    op.create_unique_constraint(
        "uq_keys_tenant_key_namespace",
        "keys",
        ["tenant_id", "key_id", "namespace"],
    )
    op.drop_constraint("fk_evidence_records_key", TABLE, type_="foreignkey")
    op.create_foreign_key(
        "fk_evidence_records_key",
        TABLE,
        "keys",
        ["tenant_id", "key_id", "record_key_namespace"],
        ["tenant_id", "key_id", "namespace"],
        ondelete="RESTRICT",
        onupdate="RESTRICT",
    )
    op.create_foreign_key(
        "fk_evidence_records_receipt_key",
        TABLE,
        "keys",
        ["tenant_id", "receipt_key_id", "receipt_key_namespace"],
        ["tenant_id", "key_id", "namespace"],
        ondelete="RESTRICT",
        onupdate="RESTRICT",
    )
    op.create_check_constraint(
        "ck_evidence_records_key_namespace_evidence",
        TABLE,
        "record_key_namespace = 'evidence'::key_namespace",
    )
    op.create_check_constraint(
        "ck_evidence_records_receipt_key_namespace_issuer",
        TABLE,
        "receipt_key_namespace = 'issuer'::key_namespace",
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
    # During review the pre-namespace form of 0010 may already exist in a
    # developer database under the same unreleased revision ID. IF EXISTS
    # keeps downgrade usable for both shapes; a released migration would
    # instead require a new revision.
    op.execute(
        f'ALTER TABLE "{TABLE}" DROP CONSTRAINT IF EXISTS '
        "ck_evidence_records_receipt_key_namespace_issuer"  # noqa: S608 -- constant
    )
    op.execute(
        f'ALTER TABLE "{TABLE}" DROP CONSTRAINT IF EXISTS '
        "ck_evidence_records_key_namespace_evidence"  # noqa: S608 -- constant
    )
    op.drop_constraint("fk_evidence_records_receipt_key", TABLE, type_="foreignkey")
    op.drop_constraint("fk_evidence_records_key", TABLE, type_="foreignkey")
    op.create_foreign_key(
        "fk_evidence_records_key",
        TABLE,
        "keys",
        ["tenant_id", "key_id"],
        ["tenant_id", "key_id"],
        ondelete="RESTRICT",
        onupdate="RESTRICT",
    )
    op.drop_column(TABLE, "receipt_canonical_bytes")
    op.drop_column(TABLE, "receipt_signature")
    op.execute(
        f'ALTER TABLE "{TABLE}" DROP COLUMN IF EXISTS receipt_key_namespace'  # noqa: S608 -- constant
    )
    op.drop_column(TABLE, "receipt_key_id")
    op.execute(
        f'ALTER TABLE "{TABLE}" DROP COLUMN IF EXISTS record_key_namespace'  # noqa: S608 -- constant
    )
    op.execute(
        "ALTER TABLE keys DROP CONSTRAINT IF EXISTS uq_keys_tenant_key_namespace"
    )
