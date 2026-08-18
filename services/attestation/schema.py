"""Runtime SQLAlchemy declarations for EV-18 lifecycle persistence."""

from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    ForeignKeyConstraint,
    Index,
    LargeBinary,
    MetaData,
    Numeric,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ENUM, JSONB, TIMESTAMP, UUID

metadata = MetaData()

key_namespace = ENUM("evidence", "issuer", name="key_namespace", create_type=False)
denominator_class = ENUM(
    "c1", "c2", "c3", "c4", "c5", name="denominator_class", create_type=False
)
notification_status = ENUM(
    "pending", "notified", "failed", name="notification_status", create_type=False
)

attestations = Table(
    "attestations",
    metadata,
    Column("attestation_id", UUID(as_uuid=True), primary_key=True),
    Column("tenant_id", Text, nullable=False),
    Column("boundary_ref", Text, nullable=False),
    Column("stream_id", Text, nullable=False),
    Column("sequence", BigInteger, nullable=False),
    Column("window_start", TIMESTAMP(timezone=True), nullable=False),
    Column("window_end", TIMESTAMP(timezone=True), nullable=False),
    Column("methodology_version", Text, nullable=False),
    Column("denominator_class", denominator_class, nullable=False),
    Column("coverage_level", Text, nullable=False),
    Column("capped_by_class", Boolean, nullable=True),
    Column("verification_status", Text, nullable=False),
    Column("coverage_ratio", Numeric, nullable=True),
    Column("counts", JSONB, nullable=False),
    Column("assertions", JSONB, nullable=False),
    Column("exclusions", JSONB, nullable=False),
    Column("population_record_refs", JSONB, nullable=False),
    Column("relying_parties", JSONB, nullable=False),
    Column("purpose", Text, nullable=True),
    Column("validity_from", TIMESTAMP(timezone=True), nullable=False),
    Column("validity_until", TIMESTAMP(timezone=True), nullable=False),
    Column("liability_ref", Text, nullable=False),
    Column("evidence_key_id", Text, nullable=False),
    Column("evidence_key_namespace", key_namespace, nullable=False, server_default="evidence"),
    Column("customer_signature", LargeBinary, nullable=False),
    Column("issuer_key_id", Text, nullable=False),
    Column("issuer_key_namespace", key_namespace, nullable=False, server_default="issuer"),
    Column("signature", LargeBinary, nullable=False),
    Column("canonical_bytes", LargeBinary, nullable=False),
    Column("bundle_digest", LargeBinary, nullable=True),
    Column("issued_at", TIMESTAMP(timezone=True), nullable=False),
    UniqueConstraint("tenant_id", "attestation_id", name="uq_attestations_tenant_id"),
    UniqueConstraint("tenant_id", "stream_id", "sequence", name="uq_attestations_stream"),
    ForeignKeyConstraint(
        ["tenant_id", "boundary_ref"],
        ["boundaries.tenant_id", "boundaries.boundary_ref"],
        name="fk_attestations_boundary",
        ondelete="RESTRICT",
        onupdate="RESTRICT",
    ),
    ForeignKeyConstraint(
        ["tenant_id", "evidence_key_id", "evidence_key_namespace"],
        ["keys.tenant_id", "keys.key_id", "keys.namespace"],
        name="fk_attestations_evidence_key",
        ondelete="RESTRICT",
        onupdate="RESTRICT",
    ),
    ForeignKeyConstraint(
        ["tenant_id", "issuer_key_id", "issuer_key_namespace"],
        ["keys.tenant_id", "keys.key_id", "keys.namespace"],
        name="fk_attestations_issuer_key",
        ondelete="RESTRICT",
        onupdate="RESTRICT",
    ),
    CheckConstraint(
        "evidence_key_namespace = 'evidence'::key_namespace",
        name="ck_attestations_evidence_namespace",
    ),
    CheckConstraint(
        "issuer_key_namespace = 'issuer'::key_namespace",
        name="ck_attestations_issuer_namespace",
    ),
    Index(
        "ix_attestations_scope_window",
        "tenant_id",
        "boundary_ref",
        "window_start",
        "window_end",
    ),
)

revocations = Table(
    "revocations",
    metadata,
    Column("revocation_id", UUID(as_uuid=True), primary_key=True),
    Column("tenant_id", Text, nullable=False),
    Column("attestation_id", UUID(as_uuid=True), nullable=False),
    Column("superseding_attestation_id", UUID(as_uuid=True), nullable=True),
    Column("stream_id", Text, nullable=False),
    Column("sequence", BigInteger, nullable=False),
    Column("prev_digest", LargeBinary, nullable=True),
    Column("reason", Text, nullable=False),
    Column("effective_at", TIMESTAMP(timezone=True), nullable=False),
    Column("notified_at", TIMESTAMP(timezone=True), nullable=True),
    Column("notification_status", notification_status, nullable=False),
    Column("issuer_key_id", Text, nullable=False),
    Column("issuer_key_namespace", key_namespace, nullable=False, server_default="issuer"),
    Column("signature", LargeBinary, nullable=False),
    Column("canonical_bytes", LargeBinary, nullable=False),
    Column("recorded_at", TIMESTAMP(timezone=True), nullable=False),
    UniqueConstraint("tenant_id", "revocation_id", name="uq_revocations_tenant_id"),
    UniqueConstraint("tenant_id", "stream_id", "sequence", name="uq_revocations_stream"),
    ForeignKeyConstraint(
        ["tenant_id", "attestation_id"],
        ["attestations.tenant_id", "attestations.attestation_id"],
        name="fk_revocations_attestation",
        ondelete="RESTRICT",
        onupdate="RESTRICT",
    ),
    ForeignKeyConstraint(
        ["tenant_id", "superseding_attestation_id"],
        ["attestations.tenant_id", "attestations.attestation_id"],
        name="fk_revocations_superseding_attestation",
        ondelete="RESTRICT",
        onupdate="RESTRICT",
    ),
    ForeignKeyConstraint(
        ["tenant_id", "issuer_key_id", "issuer_key_namespace"],
        ["keys.tenant_id", "keys.key_id", "keys.namespace"],
        name="fk_revocations_issuer_key",
        ondelete="RESTRICT",
        onupdate="RESTRICT",
    ),
    Index(
        "ix_revocations_attestation_effective",
        "tenant_id",
        "attestation_id",
        "effective_at",
    ),
)

__all__ = ["attestations", "metadata", "notification_status", "revocations"]
