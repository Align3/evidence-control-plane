"""EV-18 0015: persistent attestation lifecycle and live-attestation guard.

Attestations and issuer-signed revocation records are append-only.  Lifecycle
state is derived from those immutable rows; no status column on an issued
attestation can be rewritten.  A database trigger refuses deletion of evidence
covered by a live attestation until an effective revocation or supersession
exists (DM-012).

This migration does not implement the SE-017 / DM-014 retention floor --
attestation validity plus the dispute window.  The trigger stops refusing at
expiry, so nothing here retains evidence *after* an attestation lapses.  EV-42
owns that.

Revision ID: 0015
Revises: 0014
"""

# ruff: noqa: S608 -- every interpolated identifier/value is a module constant

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ATTESTATIONS = "attestations"
REVOCATIONS = "revocations"
EVIDENCE = "evidence_records"
POPULATION = "population_records"
REGISTRY_READER_ROLE = "evidence_registry_reader"
APP_LOGIN_ROLE = "evidence_app"
TENANT_ROLE_PREFIX = "evidence_tenant_"
POLICY_NAME = "tenant_isolation"
REFUSE_MUTATION_FUNCTION = "evidence_refuse_row_mutation"
EVIDENCE_RETENTION_FUNCTION = "evidence_refuse_live_attestation_delete"
POPULATION_RETENTION_FUNCTION = "population_refuse_live_attestation_delete"
REVOCATION_VALIDATION_FUNCTION = "validate_attestation_lifecycle_transition"

KEY_NAMESPACE = postgresql.ENUM(
    "evidence", "issuer", name="key_namespace", create_type=False
)
DENOMINATOR_CLASS = postgresql.ENUM(
    "c1", "c2", "c3", "c4", "c5", name="denominator_class", create_type=False
)
NOTIFICATION_STATUS = ("pending", "notified", "failed")
REVOCATION_REASONS = (
    "discovered_computation_defect",
    "evidence_integrity_failure",
    "qualification_invalid",
    "customer_misrepresentation",
    "late_evidence",
)


def _create_notification_status() -> None:
    values = ", ".join(f"'{value}'" for value in NOTIFICATION_STATUS)
    op.execute(  # noqa: S608 -- values are the static tuple above
        "DO $$ BEGIN"
        " IF NOT EXISTS (SELECT 1 FROM pg_type"
        "                WHERE typname = 'notification_status') THEN"
        f"   CREATE TYPE notification_status AS ENUM ({values});"
        " END IF;"
        "END $$;"
    )


def _create_attestations() -> None:
    op.create_table(
        ATTESTATIONS,
        sa.Column("attestation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", sa.Text(), nullable=False),
        sa.Column("boundary_ref", sa.Text(), nullable=False),
        sa.Column("stream_id", sa.Text(), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("window_start", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("window_end", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("methodology_version", sa.Text(), nullable=False),
        sa.Column("denominator_class", DENOMINATOR_CLASS, nullable=False),
        sa.Column("coverage_level", sa.Text(), nullable=False),
        sa.Column("capped_by_class", sa.Boolean(), nullable=True),
        sa.Column("verification_status", sa.Text(), nullable=False),
        sa.Column("coverage_ratio", sa.Numeric(), nullable=True),
        sa.Column("counts", postgresql.JSONB(), nullable=False),
        sa.Column("assertions", postgresql.JSONB(), nullable=False),
        sa.Column("exclusions", postgresql.JSONB(), nullable=False),
        sa.Column("population_record_refs", postgresql.JSONB(), nullable=False),
        sa.Column("relying_parties", postgresql.JSONB(), nullable=False),
        sa.Column("purpose", sa.Text(), nullable=True),
        sa.Column("validity_from", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("validity_until", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("liability_ref", sa.Text(), nullable=False),
        sa.Column("evidence_key_id", sa.Text(), nullable=False),
        sa.Column(
            "evidence_key_namespace",
            KEY_NAMESPACE,
            nullable=False,
            server_default=sa.text("'evidence'::key_namespace"),
        ),
        sa.Column("customer_signature", sa.LargeBinary(), nullable=False),
        sa.Column("issuer_key_id", sa.Text(), nullable=False),
        sa.Column(
            "issuer_key_namespace",
            KEY_NAMESPACE,
            nullable=False,
            server_default=sa.text("'issuer'::key_namespace"),
        ),
        sa.Column("signature", sa.LargeBinary(), nullable=False),
        sa.Column("canonical_bytes", sa.LargeBinary(), nullable=False),
        sa.Column("bundle_digest", sa.LargeBinary(), nullable=True),
        sa.Column("issued_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("attestation_id", name="pk_attestations"),
        sa.UniqueConstraint(
            "tenant_id", "attestation_id", name="uq_attestations_tenant_id"
        ),
        sa.UniqueConstraint(
            "tenant_id", "stream_id", "sequence", name="uq_attestations_stream"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.tenant_id"],
            name="fk_attestations_tenant",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "boundary_ref"],
            ["boundaries.tenant_id", "boundaries.boundary_ref"],
            name="fk_attestations_boundary",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "evidence_key_id", "evidence_key_namespace"],
            ["keys.tenant_id", "keys.key_id", "keys.namespace"],
            name="fk_attestations_evidence_key",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "issuer_key_id", "issuer_key_namespace"],
            ["keys.tenant_id", "keys.key_id", "keys.namespace"],
            name="fk_attestations_issuer_key",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.CheckConstraint(
            "evidence_key_namespace = 'evidence'::key_namespace",
            name="ck_attestations_evidence_namespace",
        ),
        sa.CheckConstraint(
            "issuer_key_namespace = 'issuer'::key_namespace",
            name="ck_attestations_issuer_namespace",
        ),
        sa.CheckConstraint(
            "octet_length(customer_signature) = 64 AND octet_length(signature) = 64",
            name="ck_attestations_signatures_ed25519",
        ),
        sa.CheckConstraint(
            "octet_length(canonical_bytes) > 0",
            name="ck_attestations_canonical_bytes_present",
        ),
        sa.CheckConstraint("sequence >= 1", name="ck_attestations_sequence_positive"),
        sa.CheckConstraint(
            "window_start < window_end", name="ck_attestations_window_order"
        ),
        sa.CheckConstraint(
            "validity_from < validity_until", name="ck_attestations_validity_order"
        ),
        sa.CheckConstraint(
            "verification_status IN ('self_computed', 'independently_reproduced')",
            name="ck_attestations_verification_status",
        ),
    )
    op.create_index(
        "ix_attestations_scope_window",
        ATTESTATIONS,
        ["tenant_id", "boundary_ref", "window_start", "window_end"],
    )
    op.create_index(
        "ix_attestations_validity",
        ATTESTATIONS,
        ["tenant_id", "validity_from", "validity_until"],
    )


def _create_revocations() -> None:
    status_type = postgresql.ENUM(
        *NOTIFICATION_STATUS, name="notification_status", create_type=False
    )
    op.create_table(
        REVOCATIONS,
        sa.Column("revocation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", sa.Text(), nullable=False),
        sa.Column("attestation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "superseding_attestation_id", postgresql.UUID(as_uuid=True), nullable=True
        ),
        sa.Column("stream_id", sa.Text(), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("prev_digest", sa.LargeBinary(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("effective_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("notified_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("notification_status", status_type, nullable=False),
        sa.Column("issuer_key_id", sa.Text(), nullable=False),
        sa.Column(
            "issuer_key_namespace",
            KEY_NAMESPACE,
            nullable=False,
            server_default=sa.text("'issuer'::key_namespace"),
        ),
        sa.Column("signature", sa.LargeBinary(), nullable=False),
        sa.Column("canonical_bytes", sa.LargeBinary(), nullable=False),
        sa.Column(
            "recorded_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("clock_timestamp()"),
        ),
        sa.PrimaryKeyConstraint("revocation_id", name="pk_revocations"),
        sa.UniqueConstraint(
            "tenant_id", "revocation_id", name="uq_revocations_tenant_id"
        ),
        sa.UniqueConstraint(
            "tenant_id", "stream_id", "sequence", name="uq_revocations_stream"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "attestation_id"],
            ["attestations.tenant_id", "attestations.attestation_id"],
            name="fk_revocations_attestation",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "superseding_attestation_id"],
            ["attestations.tenant_id", "attestations.attestation_id"],
            name="fk_revocations_superseding_attestation",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "issuer_key_id", "issuer_key_namespace"],
            ["keys.tenant_id", "keys.key_id", "keys.namespace"],
            name="fk_revocations_issuer_key",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.CheckConstraint(
            "issuer_key_namespace = 'issuer'::key_namespace",
            name="ck_revocations_issuer_namespace",
        ),
        sa.CheckConstraint(
            "octet_length(signature) = 64",
            name="ck_revocations_signature_ed25519",
        ),
        sa.CheckConstraint(
            "octet_length(canonical_bytes) > 0",
            name="ck_revocations_canonical_bytes_present",
        ),
        sa.CheckConstraint("sequence >= 1", name="ck_revocations_sequence_positive"),
        sa.CheckConstraint(
            "prev_digest IS NULL OR octet_length(prev_digest) = 32",
            name="ck_revocations_prev_digest_sha256",
        ),
        sa.CheckConstraint(
            "reason IN (" + ", ".join(f"'{value}'" for value in REVOCATION_REASONS) + ")",
            name="ck_revocations_reason",
        ),
        sa.CheckConstraint(
            "(superseding_attestation_id IS NOT NULL) = (reason = 'late_evidence')",
            name="ck_revocations_supersession_reason",
        ),
        sa.CheckConstraint(
            "(notification_status = 'notified' AND notified_at IS NOT NULL) OR "
            "(notification_status <> 'notified' AND notified_at IS NULL)",
            name="ck_revocations_notification_time",
        ),
    )
    op.create_index(
        "ix_revocations_attestation_effective",
        REVOCATIONS,
        ["tenant_id", "attestation_id", "effective_at"],
    )


def _create_functions_and_triggers() -> None:
    op.execute(  # noqa: S608 -- migration-owned identifiers only
        f"""
        CREATE FUNCTION {REVOCATION_VALIDATION_FUNCTION}()
        RETURNS trigger LANGUAGE plpgsql AS $fn$
        DECLARE
            original {ATTESTATIONS}%ROWTYPE;
            replacement {ATTESTATIONS}%ROWTYPE;
        BEGIN
            SELECT * INTO STRICT original FROM {ATTESTATIONS}
             WHERE tenant_id = NEW.tenant_id
               AND attestation_id = NEW.attestation_id;

            IF NEW.superseding_attestation_id IS NOT NULL THEN
                IF NEW.superseding_attestation_id = NEW.attestation_id THEN
                    RAISE EXCEPTION 'an attestation cannot supersede itself'
                        USING ERRCODE = '23514';
                END IF;
                SELECT * INTO STRICT replacement FROM {ATTESTATIONS}
                 WHERE tenant_id = NEW.tenant_id
                   AND attestation_id = NEW.superseding_attestation_id;
                IF replacement.boundary_ref <> original.boundary_ref
                   OR replacement.window_start <> original.window_start
                   OR replacement.window_end <> original.window_end THEN
                    RAISE EXCEPTION
                        'superseding attestation must retain the original boundary and window'
                        USING ERRCODE = '23514';
                END IF;
            END IF;

            IF EXISTS (
                SELECT 1 FROM {REVOCATIONS}
                 WHERE tenant_id = NEW.tenant_id
                   AND attestation_id = NEW.attestation_id
                   AND (reason, effective_at, superseding_attestation_id)
                       IS DISTINCT FROM
                       (NEW.reason, NEW.effective_at, NEW.superseding_attestation_id)
            ) THEN
                RAISE EXCEPTION
                    'attestation already has a different immutable lifecycle transition'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END;
        $fn$;
        """
    )
    op.execute(  # noqa: S608 -- migration-owned identifiers only
        f"""
        CREATE FUNCTION {EVIDENCE_RETENTION_FUNCTION}()
        RETURNS trigger LANGUAGE plpgsql AS $fn$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM {ATTESTATIONS} a
                 WHERE a.tenant_id = OLD.tenant_id
                   AND a.boundary_ref = OLD.boundary_ref
                   AND a.validity_from <= clock_timestamp()
                   AND a.validity_until > clock_timestamp()
                   AND NOT EXISTS (
                       SELECT 1 FROM {REVOCATIONS} r
                        WHERE r.tenant_id = a.tenant_id
                          AND r.attestation_id = a.attestation_id
                          AND r.effective_at <= clock_timestamp()
                   )
                   AND OLD.source_time >= a.window_start
                   AND OLD.source_time < a.window_end
            ) THEN
                RAISE EXCEPTION
                    'evidence deletion refused: covering attestation must be revoked first (SE-017)'
                    USING ERRCODE = '23514';
            END IF;
            RETURN OLD;
        END;
        $fn$;
        """
    )
    op.execute(  # noqa: S608 -- migration-owned identifiers only
        f"""
        CREATE FUNCTION {POPULATION_RETENTION_FUNCTION}()
        RETURNS trigger LANGUAGE plpgsql AS $fn$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM {ATTESTATIONS} a
                 WHERE a.tenant_id = OLD.tenant_id
                   AND a.boundary_ref = OLD.boundary_ref
                   AND a.validity_from <= clock_timestamp()
                   AND a.validity_until > clock_timestamp()
                   AND a.population_record_refs ? OLD.population_ref
                   AND NOT EXISTS (
                       SELECT 1 FROM {REVOCATIONS} r
                        WHERE r.tenant_id = a.tenant_id
                          AND r.attestation_id = a.attestation_id
                          AND r.effective_at <= clock_timestamp()
                   )
            ) THEN
                RAISE EXCEPTION
                    'evidence deletion refused: covering attestation must be revoked first (SE-017)'
                    USING ERRCODE = '23514';
            END IF;
            RETURN OLD;
        END;
        $fn$;
        """
    )
    for table in (ATTESTATIONS, REVOCATIONS):
        op.execute(
            f"CREATE TRIGGER {table}_refuse_mutation"
            f" BEFORE UPDATE OR DELETE ON {table}"
            f" FOR EACH ROW EXECUTE FUNCTION {REFUSE_MUTATION_FUNCTION}()"
        )
        op.execute(
            f"CREATE TRIGGER {table}_refuse_truncate"
            f" BEFORE TRUNCATE ON {table}"
            f" FOR EACH STATEMENT EXECUTE FUNCTION {REFUSE_MUTATION_FUNCTION}()"
        )
    op.execute(
        f"CREATE TRIGGER {REVOCATIONS}_validate_transition"
        f" BEFORE INSERT ON {REVOCATIONS}"
        f" FOR EACH ROW EXECUTE FUNCTION {REVOCATION_VALIDATION_FUNCTION}()"
    )
    op.execute(
        f"CREATE TRIGGER {EVIDENCE}_protect_live_attestation"
        f" BEFORE DELETE ON {EVIDENCE}"
        f" FOR EACH ROW EXECUTE FUNCTION {EVIDENCE_RETENTION_FUNCTION}()"
    )
    op.execute(
        f"CREATE TRIGGER {POPULATION}_protect_live_attestation"
        f" BEFORE DELETE ON {POPULATION}"
        f" FOR EACH ROW EXECUTE FUNCTION {POPULATION_RETENTION_FUNCTION}()"
    )


def _isolate() -> None:
    for table in (ATTESTATIONS, REVOCATIONS):
        op.execute(f"REVOKE ALL ON TABLE {table} FROM PUBLIC")
        op.execute(f'GRANT SELECT ON TABLE {table} TO "{REGISTRY_READER_ROLE}"')
        op.execute(
            f"REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLE {table} "
            f'FROM "{REGISTRY_READER_ROLE}", "{APP_LOGIN_ROLE}"'
        )
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY {POLICY_NAME} ON {table} FOR SELECT "
            f"USING (current_user = '{TENANT_ROLE_PREFIX}' || tenant_id)"
        )


def upgrade() -> None:
    _create_notification_status()
    _create_attestations()
    _create_revocations()
    _create_functions_and_triggers()
    _isolate()


def downgrade() -> None:
    for table in (EVIDENCE, POPULATION):
        op.execute(f"DROP TRIGGER IF EXISTS {table}_protect_live_attestation ON {table}")
    op.execute(
        f"DROP TRIGGER IF EXISTS {REVOCATIONS}_validate_transition "
        f"ON {REVOCATIONS}"
    )
    op.execute(f"DROP FUNCTION IF EXISTS {POPULATION_RETENTION_FUNCTION}()")
    op.execute(f"DROP FUNCTION IF EXISTS {EVIDENCE_RETENTION_FUNCTION}()")
    op.execute(f"DROP FUNCTION IF EXISTS {REVOCATION_VALIDATION_FUNCTION}()")
    op.drop_table(REVOCATIONS)
    op.drop_table(ATTESTATIONS)
    op.execute("DROP TYPE IF EXISTS notification_status")
