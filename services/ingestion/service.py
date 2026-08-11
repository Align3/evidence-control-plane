"""Synchronous, authenticated evidence ingestion (EV-07).

The acknowledgment is constructed only after the tenant transaction exits
cleanly. There is no broker, outbox, or deferred write: customer record and
issuer receipt are one INSERT and one durable PostgreSQL commit (AC-001,
IN-003, ES-030).
"""

from __future__ import annotations

import base64
import binascii
import hmac
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from sqlalchemy import Connection, RowMapping, or_, select, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from sdk_python.evidence.origin import primary_signer_namespace
from sdk_python.evidence.schema import EvidenceRecord
from sdk_python.evidence.signing import SignatureError
from services.ledger import (
    TenantEngines,
    collectors,
    digest_bytes,
    digest_ref,
    evidence_partition,
    integrity_event_partition,
    parse_digest_ref,
    tenant_connection,
    validate_tenant_id,
)

from .receipts import (
    KeyNamespaceError,
    RegisteredPublicKey,
    create_ingestion_receipt,
    parse_canonical_record_wire,
    parse_timestamp,
    verify_evidence_record_signature,
    verify_ingestion_receipt,
)

_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")


class IngestionError(ValueError):
    """A submission must be refused without entering the ledger."""


class CollectorAuthenticationError(IngestionError):
    """The record is not authenticated as its declared collector."""


class ChainConflictError(IngestionError):
    """The submitted stream position or digest link conflicts with the ledger."""

    error_code = "chain.conflict"


class ReplayError(ChainConflictError):
    """The exact accepted wire artifact was submitted again."""

    error_code = "ingestion.replay"


class IntegrityConflictError(ChainConflictError):
    """A rejected integrity event that is persisted and surfaced to the tenant."""

    event_type: str

    def __init__(self, message: str, *, existing: RowMapping) -> None:
        super().__init__(message)
        self.event_id = uuid4()
        self.existing_record_id = existing["record_id"]
        self.existing_wire_bytes = bytes(existing["received_wire_bytes"])


class ForkIntegrityError(IntegrityConflictError):
    """A different record identity occupies the submitted stream position."""

    error_code = "integrity.stream_fork"
    event_type = "stream_fork"


class ContentSubstitutionError(IntegrityConflictError):
    """An accepted record identity was resubmitted with different content."""

    error_code = "integrity.content_substitution"
    event_type = "content_substitution"


class LedgerUnavailableError(RuntimeError):
    """No durable acknowledgment can be made because the commit failed."""


@dataclass(frozen=True, slots=True)
class IssuerSigningKey:
    """Hosted receipt signer selected explicitly per tenant."""

    key_id: str
    private_key: Ed25519PrivateKey


@dataclass(frozen=True, slots=True)
class IngestionAcknowledgement:
    """Returned only after commit; digest is the ES-006a next-link value."""

    record_id: str
    record_digest: str
    sequence: int


def _required_source_text(record: EvidenceRecord, field: str) -> str:
    value = record.source.get(field)
    if not isinstance(value, str) or not value:
        raise CollectorAuthenticationError(
            f"source.{field} is required for collector authentication"
        )
    return value


def _signature_key_id(record: EvidenceRecord) -> str:
    value = record.signature.get("key_id")
    if not isinstance(value, str) or not value:
        raise CollectorAuthenticationError("signature.key_id is required")
    return value


def _raw_signature(record: EvidenceRecord) -> bytes:
    value = record.signature.get("sig")
    if not isinstance(value, str) or not value or _BASE64URL.fullmatch(value) is None:
        raise CollectorAuthenticationError("signature.sig must be unpadded base64url")
    try:
        raw = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, binascii.Error) as exc:
        raise CollectorAuthenticationError(
            "signature.sig must be unpadded base64url"
        ) from exc
    if len(raw) != 64:
        raise CollectorAuthenticationError("signature.sig has the wrong Ed25519 length")
    return raw


def _registered_collector(
    connection: Connection, *, collector_id: str, record: EvidenceRecord
) -> RowMapping:
    row = connection.execute(
        select(
            collectors.c.collector_id,
            collectors.c.implementation,
            collectors.c.version,
            collectors.c.revoked_at,
        ).where(collectors.c.collector_id == collector_id)
    ).mappings().one_or_none()
    if row is None:
        raise CollectorAuthenticationError("unregistered collector")

    source_time = parse_timestamp(record.clocks.source_time)
    revoked_at = row["revoked_at"]
    if revoked_at is not None and source_time >= revoked_at:
        raise CollectorAuthenticationError("collector credential was revoked")
    if _required_source_text(record, "version") != row["version"]:
        raise CollectorAuthenticationError("collector version does not match registration")
    implementation = record.source.get("implementation")
    if implementation is not None and implementation != row["implementation"]:
        raise CollectorAuthenticationError(
            "collector implementation does not match registration"
        )
    return row


def _registered_key(
    connection: Connection,
    *,
    key_id: str,
) -> tuple[RowMapping, RegisteredPublicKey]:
    row = connection.execute(
        text(
            "SELECT namespace, collector_id, public_key, valid_from, valid_until,"
            " compromised_from FROM keys WHERE key_id = :key_id"
        ),
        {"key_id": key_id},
    ).mappings().one_or_none()
    if row is None:
        raise CollectorAuthenticationError("unknown registered signing key")
    try:
        public_key = Ed25519PublicKey.from_public_bytes(bytes(row["public_key"]))
    except ValueError as exc:
        raise CollectorAuthenticationError(
            "registered key is not a valid Ed25519 public key"
        ) from exc
    return row, RegisteredPublicKey(namespace=row["namespace"], public_key=public_key)


def _validate_evidence_key_registration(
    row: RowMapping,
    *,
    collector_id: str,
    record: EvidenceRecord,
) -> None:
    if row["collector_id"] != collector_id:
        raise CollectorAuthenticationError(
            "evidence signing key is bound to a different collector"
        )

    signed_at = parse_timestamp(record.clocks.source_time)
    if signed_at < row["valid_from"]:
        raise CollectorAuthenticationError("evidence signing key was not yet valid")
    if row["valid_until"] is not None and signed_at >= row["valid_until"]:
        raise CollectorAuthenticationError("evidence signing key had expired")
    if row["compromised_from"] is not None and signed_at >= row["compromised_from"]:
        raise CollectorAuthenticationError("evidence signing key was compromised")


def _validate_issuer_key_registration(
    row: RowMapping,
    registered_key: RegisteredPublicKey,
    *,
    signer: IssuerSigningKey,
    observed_at: datetime,
) -> None:
    if observed_at < row["valid_from"]:
        raise IngestionError("receipt issuer key is not yet valid")
    if row["valid_until"] is not None and observed_at >= row["valid_until"]:
        raise IngestionError("receipt issuer key has expired")
    if row["compromised_from"] is not None and observed_at >= row["compromised_from"]:
        raise IngestionError("receipt issuer key is compromised")
    if (
        registered_key.public_key.public_bytes_raw()
        != signer.private_key.public_key().public_bytes_raw()
    ):
        raise IngestionError("configured receipt private key does not match the registry")


def _action_id(record: EvidenceRecord) -> UUID | None:
    value = getattr(record.body, "action_id", None)
    if value is None:
        return None
    try:
        return UUID(value)
    except (TypeError, ValueError) as exc:
        raise IngestionError("body.action_id must be a UUID for ledger projection") from exc


def _lock_and_classify_existing(
    connection: Connection,
    *,
    record: EvidenceRecord,
    received_wire_bytes: bytes,
) -> None:
    """Serialize identity/position checks and distinguish every collision.

    Digest-link verification is deliberately a read-time verifier concern
    (AC-013). Ingestion enforces the sequence domain and the database's unique
    stream position, but does not confuse absence-by-arrival-order with a gap.
    The database constraints remain the backstop; this classification is what
    makes replay, fork, and content substitution externally distinguishable.
    """

    if record.sequence == 1 and record.prev_digest is not None:
        raise ChainConflictError("sequence 1 must have null prev_digest")
    if record.sequence > 1 and record.prev_digest is None:
        raise ChainConflictError("sequence greater than 1 must name prev_digest")
    locks = sorted(
        (
            f"record:{record.tenant_id}:{record.record_id}",
            f"position:{record.tenant_id}:{record.stream_id}:{record.sequence}",
        )
    )
    for lock in locks:
        connection.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:lock, 0))"),
            {"lock": lock},
        )

    partition = evidence_partition(record.tenant_id)
    rows = connection.execute(
        select(
            partition.c.record_id,
            partition.c.stream_id,
            partition.c.sequence,
            partition.c.received_wire_bytes,
        ).where(
            or_(
                partition.c.record_id == UUID(record.record_id),
                (partition.c.stream_id == record.stream_id)
                & (partition.c.sequence == record.sequence),
            )
        )
    ).mappings().all()
    position = next(
        (
            row
            for row in rows
            if row["stream_id"] == record.stream_id
            and row["sequence"] == record.sequence
        ),
        None,
    )
    identity = next(
        (row for row in rows if str(row["record_id"]) == record.record_id),
        None,
    )
    if position is not None and str(position["record_id"]) != record.record_id:
        raise ForkIntegrityError(
            "fatal stream fork: another record occupies this stream position",
            existing=position,
        )
    if identity is not None:
        if hmac.compare_digest(
            bytes(identity["received_wire_bytes"]), received_wire_bytes
        ):
            raise ReplayError("exact record replay")
        raise ContentSubstitutionError(
            "record identity was resubmitted with different content",
            existing=identity,
        )


class IngestionService:
    """Validate, authenticate, receipt, and durably append one record."""

    def __init__(
        self,
        *,
        tenant_engines: TenantEngines,
        issuer_signers: Mapping[str, IssuerSigningKey],
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._tenant_engines = tenant_engines
        self._issuer_signers = dict(issuer_signers)
        self._clock = clock or (lambda: datetime.now(UTC))

    def _record_integrity_event(
        self,
        *,
        record: EvidenceRecord,
        received_wire_bytes: bytes,
        observed_at: datetime,
        error: IntegrityConflictError,
    ) -> None:
        """Persist a rejected integrity attempt after its ledger txn rolls back."""

        row = {
            "event_id": error.event_id,
            "tenant_id": record.tenant_id,
            "event_type": error.event_type,
            "record_id": UUID(record.record_id),
            "conflicting_record_id": error.existing_record_id,
            "stream_id": record.stream_id,
            "sequence": record.sequence,
            "submitted_wire_bytes": received_wire_bytes,
            "existing_wire_bytes": error.existing_wire_bytes,
            "occurred_at": observed_at,
            # The same response carries event_id and the distinct error code,
            # so persistence and tenant surfacing are one synchronous action.
            "surfaced_to_tenant_at": observed_at,
        }
        try:
            with tenant_connection(self._tenant_engines, record.tenant_id) as connection:
                connection.execute(
                    integrity_event_partition(record.tenant_id).insert(), row
                )
        except SQLAlchemyError as exc:
            raise LedgerUnavailableError(
                "integrity failure was detected but its tenant audit event could not commit"
            ) from exc

    def ingest(self, raw_record: bytes) -> IngestionAcknowledgement:
        """Return only after a synchronous customer-record + receipt commit."""

        record, signing_bytes = parse_canonical_record_wire(raw_record)
        try:
            validate_tenant_id(record.tenant_id)
        except ValueError as exc:
            raise IngestionError("record names an invalid or unprovisioned tenant") from exc
        if primary_signer_namespace(record.record_type) != "evidence":
            raise CollectorAuthenticationError(
                "customer ingestion accepts only customer-origin evidence records"
            )
        collector_id = _required_source_text(record, "collector_id")
        key_id = _signature_key_id(record)
        signer = self._issuer_signers.get(record.tenant_id)
        if signer is None:
            raise IngestionError("no receipt signer configured for tenant")
        observed_at = self._clock()
        if observed_at.tzinfo is None or observed_at.utcoffset() is None:
            raise IngestionError("ingestion clock returned a naive timestamp")

        try:
            with tenant_connection(self._tenant_engines, record.tenant_id) as connection:
                connection.execute(text("SET LOCAL synchronous_commit = on"))
                _registered_collector(connection, collector_id=collector_id, record=record)
                evidence_row, evidence_key = _registered_key(
                    connection, key_id=key_id
                )
                try:
                    verify_evidence_record_signature(
                        record,
                        verification_keys={key_id: evidence_key},
                        signing_bytes=signing_bytes,
                    )
                except (SignatureError, KeyNamespaceError) as exc:
                    raise CollectorAuthenticationError(
                        "record signature verification failed"
                    ) from exc
                _validate_evidence_key_registration(
                    evidence_row,
                    collector_id=collector_id,
                    record=record,
                )

                issuer_row, issuer_key = _registered_key(
                    connection, key_id=signer.key_id
                )
                _validate_issuer_key_registration(
                    issuer_row,
                    issuer_key,
                    signer=signer,
                    observed_at=observed_at,
                )
                _lock_and_classify_existing(
                    connection,
                    record=record,
                    received_wire_bytes=raw_record,
                )
                receipt = create_ingestion_receipt(
                    record,
                    ingest_time=observed_at,
                    issuer_key_id=signer.key_id,
                    issuer_private_key=signer.private_key,
                    received_wire_bytes=raw_record,
                )
                try:
                    verify_ingestion_receipt(
                        receipt,
                        record=record,
                        verification_keys={signer.key_id: issuer_key},
                        received_wire_bytes=raw_record,
                    )
                except KeyNamespaceError as exc:
                    raise IngestionError(
                        "receipt signer is not a registered issuer key"
                    ) from exc

                signed_digest_bytes = digest_bytes(signing_bytes)
                wire_digest_bytes = digest_bytes(raw_record)
                body = record.body.model_dump(mode="json", exclude_unset=True)
                row: dict[str, Any] = {
                    "record_id": UUID(record.record_id),
                    "tenant_id": record.tenant_id,
                    "record_type": record.record_type,
                    "schema_version": record.schema_version,
                    "boundary_ref": record.boundary_ref,
                    "stream_id": record.stream_id,
                    "sequence": record.sequence,
                    "prev_digest": (
                        None
                        if record.prev_digest is None
                        else parse_digest_ref(record.prev_digest)
                    ),
                    "record_digest": signed_digest_bytes,
                    "collector_id": collector_id,
                    "key_id": key_id,
                    "signature": _raw_signature(record),
                    "source_time": parse_timestamp(record.clocks.source_time),
                    "ingest_time": parse_timestamp(receipt.payload.ingest_time),
                    "authoritative_time": (
                        None
                        if record.clocks.authoritative_time is None
                        else parse_timestamp(record.clocks.authoritative_time)
                    ),
                    "clock_skew_ms": receipt.payload.clock_skew_ms,
                    "canonical_bytes": signing_bytes,
                    "received_wire_bytes": raw_record,
                    "receipt_key_id": receipt.key_id,
                    "receipt_signature": receipt.signature,
                    "receipt_canonical_bytes": receipt.canonical_bytes,
                    "body": body,
                    "action_id": _action_id(record),
                    "action_family": getattr(record.body, "action_family", None),
                }
                connection.execute(evidence_partition(record.tenant_id).insert(), row)
        except IntegrityConflictError as exc:
            self._record_integrity_event(
                record=record,
                received_wire_bytes=raw_record,
                observed_at=observed_at,
                error=exc,
            )
            raise
        except (CollectorAuthenticationError, ChainConflictError, IngestionError):
            raise
        except IntegrityError as exc:
            raise ChainConflictError("record conflicts with the append-only ledger") from exc
        except SQLAlchemyError as exc:
            raise LedgerUnavailableError(
                "record was not acknowledged because durable commit failed"
            ) from exc

        return IngestionAcknowledgement(
            record_id=record.record_id,
            # The customer needs the complete-record ES-006a digest to form
            # the next prev_digest. The ledger's record_digest remains the
            # signature-excluded DM-023 digest used by signed_digest.
            record_digest=digest_ref(wire_digest_bytes),
            sequence=record.sequence,
        )
