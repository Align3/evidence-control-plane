"""EV-31 0014: issuer receipts for constitutive records.

Historical EV-12 rows cannot be assigned an honest hosted receipt after the
fact.  The receipt columns are therefore nullable for those rows, while a
``NOT VALID`` check is enforced for every new insert.  PostgreSQL does not
scan old rows when adding that check, but it does reject every future row
that omits any receipt component.  This preserves the evidence absence
instead of fabricating it and closes the write path going forward (ES-032).

Revision ID: 0014
Revises: 0013
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLES = ("qualification_records", "boundaries")
KEY_NAMESPACE = postgresql.ENUM(
    "evidence", "issuer", name="key_namespace", create_type=False
)


def _add_receipt(table: str) -> None:
    op.add_column(table, sa.Column("receipt_key_id", sa.Text(), nullable=True))
    op.add_column(
        table,
        sa.Column("receipt_key_namespace", KEY_NAMESPACE, nullable=True),
    )
    op.add_column(table, sa.Column("receipt_signature", sa.LargeBinary(), nullable=True))
    op.add_column(
        table,
        sa.Column("receipt_canonical_bytes", sa.LargeBinary(), nullable=True),
    )
    op.add_column(
        table,
        sa.Column("received_wire_bytes", sa.LargeBinary(), nullable=True),
    )
    op.create_foreign_key(
        f"fk_{table}_receipt_key",
        table,
        "keys",
        ["tenant_id", "receipt_key_id", "receipt_key_namespace"],
        ["tenant_id", "key_id", "namespace"],
        ondelete="RESTRICT",
        onupdate="RESTRICT",
    )
    op.create_check_constraint(
        f"ck_{table}_receipt_key_namespace_issuer",
        table,
        "receipt_key_id IS NULL OR receipt_key_namespace = 'issuer'::key_namespace",
    )
    op.create_check_constraint(
        f"ck_{table}_receipt_signature_ed25519",
        table,
        "receipt_signature IS NULL OR octet_length(receipt_signature) = 64",
    )
    op.create_check_constraint(
        f"ck_{table}_receipt_bytes_present",
        table,
        "receipt_canonical_bytes IS NULL OR octet_length(receipt_canonical_bytes) > 0",
    )
    op.create_check_constraint(
        f"ck_{table}_received_wire_bytes_present",
        table,
        "received_wire_bytes IS NULL OR octet_length(received_wire_bytes) > 0",
    )
    # NOT VALID is the migration-safe form of "required from now on": legacy
    # rows remain truthful nulls, but every INSERT after this constraint exists
    # must carry the complete receipt tuple.
    op.execute(
        f'ALTER TABLE "{table}" ADD CONSTRAINT '
        f'"ck_{table}_receipt_required" CHECK ('
        "receipt_key_id IS NOT NULL AND "
        "receipt_key_namespace IS NOT NULL AND "
        "receipt_signature IS NOT NULL AND "
        "receipt_canonical_bytes IS NOT NULL AND "
        "received_wire_bytes IS NOT NULL) NOT VALID"
    )


def upgrade() -> None:
    for table in TABLES:
        _add_receipt(table)


def _drop_receipt(table: str) -> None:
    op.drop_constraint(f"ck_{table}_receipt_required", table, type_="check")
    op.drop_constraint(
        f"ck_{table}_received_wire_bytes_present", table, type_="check"
    )
    op.drop_constraint(f"ck_{table}_receipt_bytes_present", table, type_="check")
    op.drop_constraint(f"ck_{table}_receipt_signature_ed25519", table, type_="check")
    op.drop_constraint(
        f"ck_{table}_receipt_key_namespace_issuer", table, type_="check"
    )
    op.drop_constraint(f"fk_{table}_receipt_key", table, type_="foreignkey")
    op.drop_column(table, "received_wire_bytes")
    op.drop_column(table, "receipt_canonical_bytes")
    op.drop_column(table, "receipt_signature")
    op.drop_column(table, "receipt_key_namespace")
    op.drop_column(table, "receipt_key_id")


def downgrade() -> None:
    for table in reversed(TABLES):
        _drop_receipt(table)
