"""Append-only attestation revocation, supersession, and expiry (EV-18)."""

from __future__ import annotations

import base64
import binascii
import os
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Any, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import Connection, select

from sdk_python.evidence.canonical import canonicalize
from sdk_python.evidence.schema import (
    AttestationWindowRecord,
    JsonValue,
    RevocationRecord,
    parse_record,
    validate_record,
)
from sdk_python.evidence.signing import (
    SignatureError,
    record_signature_bytes,
    sign_record,
    signing_digest,
    verify_attestation_signatures,
)
from services.ingestion.receipts import (
    RegisteredPublicKey,
    parse_timestamp,
    verify_record_origin_signature,
)
from services.ledger.schema import keys

from .issuance import IssuerSigner
from .schema import attestations, revocations

NotificationSink = Callable[[Mapping[str, JsonValue]], None]


class AttestationLifecycleError(ValueError):
    """Lifecycle input cannot support the requested factual transition."""


class LifecycleStatus(StrEnum):
    NOT_YET_VALID = "not_yet_valid"
    VALID = "valid"
    EXPIRED = "expired"
    REVOKED = "revoked"
    SUPERSEDED = "superseded"


class NotificationStatus(StrEnum):
    PENDING = "pending"
    NOTIFIED = "notified"
    FAILED = "failed"


class RevocationGround(StrEnum):
    DISCOVERED_COMPUTATION_DEFECT = "discovered_computation_defect"
    EVIDENCE_INTEGRITY_FAILURE = "evidence_integrity_failure"
    QUALIFICATION_INVALID = "qualification_invalid"
    CUSTOMER_MISREPRESENTATION = "customer_misrepresentation"


class _TransitionReason(StrEnum):
    LATE_EVIDENCE = "late_evidence"


@dataclass(frozen=True, slots=True)
class LifecycleTransition:
    record: RevocationRecord
    delivery_errors: tuple[str, ...] = ()


def _uuid7() -> str:
    unix_ms = int(time.time() * 1_000)
    random = os.urandom(10)
    value = (
        unix_ms.to_bytes(6, "big")
        + bytes([0x70 | (random[0] & 0x0F), random[1]])
        + bytes([0x80 | (random[2] & 0x3F)])
        + random[3:10]
    )
    return str(uuid.UUID(bytes=value))


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise AttestationLifecycleError("lifecycle timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _signature_member(signature: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(signature, dict):
        raise AttestationLifecycleError(f"{label} signature must be an object")
    return signature


def _key_id(signature: Mapping[str, object], *, label: str) -> str:
    value = signature.get("key_id")
    if not isinstance(value, str) or not value:
        raise AttestationLifecycleError(f"{label} signature has no key_id")
    return value


def _proof_bytes(signature: Mapping[str, object], *, label: str) -> bytes:
    encoded = signature.get("sig")
    if not isinstance(encoded, str):
        raise AttestationLifecycleError(f"{label} signature has no proof")
    try:
        return base64.b64decode(
            encoded + "=" * (-len(encoded) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error) as exc:
        raise AttestationLifecycleError(f"{label} signature is not base64url") from exc


def _registered_key(
    connection: Connection,
    *,
    tenant_id: str,
    key_id: str,
    namespace: str,
) -> Ed25519PublicKey:
    raw = connection.execute(
        select(keys.c.public_key).where(
            keys.c.tenant_id == tenant_id,
            keys.c.key_id == key_id,
            keys.c.namespace == namespace,
        )
    ).scalar_one_or_none()
    if raw is None:
        raise AttestationLifecycleError(
            f"unknown {namespace} key for tenant {tenant_id!r}: {key_id}"
        )
    try:
        return Ed25519PublicKey.from_public_bytes(bytes(raw))
    except ValueError as exc:
        raise AttestationLifecycleError(
            f"registered {namespace} key {key_id!r} is not Ed25519"
        ) from exc


def _attestation_signers(
    connection: Connection, record: AttestationWindowRecord
) -> tuple[str, str, bytes, bytes]:
    customer = _signature_member(record.signature, label="customer")
    issuer = _signature_member(customer.get("issuer"), label="issuer")
    customer_key_id = _key_id(customer, label="customer")
    issuer_key_id = _key_id(issuer, label="issuer")
    customer_key = _registered_key(
        connection,
        tenant_id=record.tenant_id,
        key_id=customer_key_id,
        namespace="evidence",
    )
    issuer_key = _registered_key(
        connection,
        tenant_id=record.tenant_id,
        key_id=issuer_key_id,
        namespace="issuer",
    )
    try:
        verify_attestation_signatures(
            record,
            evidence_public_keys={customer_key_id: customer_key},
            issuer_public_keys={issuer_key_id: issuer_key},
        )
    except SignatureError as exc:
        raise AttestationLifecycleError(f"attestation signature refused: {exc}") from exc
    return (
        customer_key_id,
        issuer_key_id,
        record_signature_bytes(record),
        _proof_bytes(issuer, label="issuer"),
    )


def _attestation_payload(record: AttestationWindowRecord) -> dict[str, Any]:
    body = record.body
    customer_key_id = _key_id(
        _signature_member(record.signature, label="customer"), label="customer"
    )
    issuer_signature = _signature_member(
        _signature_member(record.signature, label="customer").get("issuer"),
        label="issuer",
    )
    ratio = Decimal(body.coverage_ratio) if body.coverage_ratio is not None else None
    extra = body.model_extra or {}
    return {
        "attestation_id": uuid.UUID(record.record_id),
        "tenant_id": record.tenant_id,
        "boundary_ref": record.boundary_ref,
        "stream_id": record.stream_id,
        "sequence": record.sequence,
        "window_start": parse_timestamp(body.window_start),
        "window_end": parse_timestamp(body.window_end),
        "methodology_version": body.methodology_version,
        "denominator_class": body.denominator_class.lower(),
        "coverage_level": body.coverage_level,
        "capped_by_class": extra.get("capped_by_class"),
        "verification_status": body.verification_status,
        "coverage_ratio": ratio,
        "counts": body.counts,
        "assertions": body.assertions,
        "exclusions": body.exclusions,
        "population_record_refs": body.population_record_refs,
        "relying_parties": body.relying_parties,
        "purpose": extra.get("purpose"),
        "validity_from": parse_timestamp(body.validity_from),
        "validity_until": parse_timestamp(body.validity_until),
        "liability_ref": body.liability_ref,
        "evidence_key_id": customer_key_id,
        "evidence_key_namespace": "evidence",
        "customer_signature": record_signature_bytes(record),
        "issuer_key_id": _key_id(issuer_signature, label="issuer"),
        "issuer_key_namespace": "issuer",
        "signature": _proof_bytes(issuer_signature, label="issuer"),
        "canonical_bytes": canonicalize(record),
        # EV-24 owns the complete bundle and its digest. Absence is truthful.
        "bundle_digest": None,
        "issued_at": parse_timestamp(body.issued_at),
    }


def record_attestation(
    connection: Connection, record: AttestationWindowRecord
) -> str:
    """Verify both proofs and append one immutable issued attestation."""

    _attestation_signers(connection, record)
    payload = _attestation_payload(record)
    existing = connection.execute(
        select(attestations.c.canonical_bytes).where(
            attestations.c.tenant_id == record.tenant_id,
            attestations.c.attestation_id == uuid.UUID(record.record_id),
        )
    ).scalar_one_or_none()
    if existing is not None:
        if bytes(existing) != payload["canonical_bytes"]:
            raise AttestationLifecycleError(
                "attestation_id already names different canonical bytes"
            )
        return record.record_id
    connection.execute(attestations.insert().values(**payload))
    return record.record_id


def _attestation_row(
    connection: Connection, *, tenant_id: str, attestation_id: str
) -> Mapping[str, Any]:
    try:
        identifier = uuid.UUID(attestation_id)
    except ValueError as exc:
        raise AttestationLifecycleError("attestation_id must be a UUID") from exc
    row = connection.execute(
        select(attestations).where(
            attestations.c.tenant_id == tenant_id,
            attestations.c.attestation_id == identifier,
        )
    ).mappings().one_or_none()
    if row is None:
        raise AttestationLifecycleError(
            f"unknown attestation for tenant {tenant_id!r}: {attestation_id}"
        )
    return cast(Mapping[str, Any], row)


def _attestation_record(row: Mapping[str, Any]) -> AttestationWindowRecord:
    record = parse_record(bytes(row["canonical_bytes"]))
    if not isinstance(record, AttestationWindowRecord):  # pragma: no cover
        raise AttestationLifecycleError("stored lifecycle subject is not an attestation")
    return record


def _notification_result(
    parties: list[JsonValue], notify: NotificationSink | None
) -> tuple[NotificationStatus, datetime | None, tuple[str, ...]]:
    if notify is None:
        return NotificationStatus.PENDING, None, ()
    errors: list[str] = []
    for party in parties:
        if not isinstance(party, dict):
            errors.append("relying party is not an object")
            continue
        try:
            notify(party)
        except Exception as exc:  # noqa: BLE001 -- status must record delivery failure
            errors.append(str(exc) or type(exc).__name__)
    if errors:
        return NotificationStatus.FAILED, None, tuple(errors)
    return NotificationStatus.NOTIFIED, datetime.now(UTC), ()


def _next_revocation_position(
    connection: Connection, *, tenant_id: str, attestation_id: str
) -> tuple[int, str | None]:
    row = connection.execute(
        select(revocations.c.sequence, revocations.c.canonical_bytes)
        .where(
            revocations.c.tenant_id == tenant_id,
            revocations.c.attestation_id == uuid.UUID(attestation_id),
        )
        .order_by(revocations.c.sequence.desc())
        .limit(1)
    ).one_or_none()
    if row is None:
        return 1, None
    previous = parse_record(bytes(row.canonical_bytes))
    if not isinstance(previous, RevocationRecord):  # pragma: no cover
        raise AttestationLifecycleError("stored lifecycle row is not a revocation")
    return int(row.sequence) + 1, signing_digest(previous)


def _record_transition(
    connection: Connection,
    *,
    tenant_id: str,
    attestation_id: str,
    reason: str,
    effective_at: datetime,
    signer: IssuerSigner,
    superseding_ref: str | None,
    notify: NotificationSink | None,
) -> LifecycleTransition:
    original_row = _attestation_row(
        connection, tenant_id=tenant_id, attestation_id=attestation_id
    )
    original = _attestation_record(original_row)
    status, notified_at, delivery_errors = _notification_result(
        original.body.relying_parties, notify
    )
    sequence, prev_digest = _next_revocation_position(
        connection, tenant_id=tenant_id, attestation_id=attestation_id
    )
    source_time = datetime.now(UTC)
    unsigned = validate_record(
        {
            "record_id": _uuid7(),
            "record_type": "RevocationRecord",
            "schema_version": "1.0.0",
            "tenant_id": tenant_id,
            "boundary_ref": original.boundary_ref,
            "stream_id": f"{tenant_id}:lifecycle:{attestation_id}",
            "sequence": sequence,
            "prev_digest": prev_digest,
            "source": {"service": "attestation-lifecycle", "version": "0.1.0"},
            "clocks": {"source_time": _timestamp(source_time)},
            "body": {
                "attestation_ref": attestation_id,
                "reason": reason,
                "issuer": original.body.issuer,
                "effective_at": _timestamp(effective_at),
                "superseding_ref": superseding_ref,
                "relying_party_notification_status": status.value,
            },
            "signature": {},
        }
    )
    if not isinstance(unsigned, RevocationRecord):  # pragma: no cover
        raise AttestationLifecycleError("record dispatcher did not create a revocation")
    record = sign_record(
        unsigned,
        key_id=signer.key_id,
        private_key=signer.private_key,
    )
    public_key = _registered_key(
        connection,
        tenant_id=tenant_id,
        key_id=signer.key_id,
        namespace="issuer",
    )
    try:
        verify_record_origin_signature(
            record,
            verification_keys={
                signer.key_id: RegisteredPublicKey(
                    namespace="issuer", public_key=public_key
                )
            },
        )
    except SignatureError as exc:
        raise AttestationLifecycleError(f"revocation signature refused: {exc}") from exc
    connection.execute(
        revocations.insert().values(
            revocation_id=uuid.UUID(record.record_id),
            tenant_id=tenant_id,
            attestation_id=uuid.UUID(attestation_id),
            superseding_attestation_id=(
                uuid.UUID(superseding_ref) if superseding_ref is not None else None
            ),
            stream_id=record.stream_id,
            sequence=record.sequence,
            prev_digest=(
                bytes.fromhex(record.prev_digest.removeprefix("sha256:"))
                if record.prev_digest is not None
                else None
            ),
            reason=reason,
            effective_at=parse_timestamp(record.body.effective_at),
            notified_at=notified_at,
            notification_status=status.value,
            issuer_key_id=signer.key_id,
            issuer_key_namespace="issuer",
            signature=record_signature_bytes(record),
            canonical_bytes=canonicalize(record),
            recorded_at=source_time,
        )
    )
    return LifecycleTransition(record=record, delivery_errors=delivery_errors)


def revoke_attestation(
    connection: Connection,
    *,
    tenant_id: str,
    attestation_id: str,
    ground: RevocationGround,
    effective_at: datetime,
    signer: IssuerSigner,
    notify: NotificationSink | None = None,
) -> LifecycleTransition:
    if not isinstance(ground, RevocationGround):
        raise AttestationLifecycleError("revocation ground is not permitted by AR-010")
    return _record_transition(
        connection,
        tenant_id=tenant_id,
        attestation_id=attestation_id,
        reason=ground.value,
        effective_at=effective_at,
        signer=signer,
        superseding_ref=None,
        notify=notify,
    )


def supersede_attestation(
    connection: Connection,
    *,
    tenant_id: str,
    original_attestation_id: str,
    superseding_attestation: AttestationWindowRecord,
    effective_at: datetime,
    signer: IssuerSigner,
    notify: NotificationSink | None = None,
) -> LifecycleTransition:
    original_row = _attestation_row(
        connection,
        tenant_id=tenant_id,
        attestation_id=original_attestation_id,
    )
    original = _attestation_record(original_row)
    replacement = superseding_attestation
    if replacement.tenant_id != tenant_id:
        raise AttestationLifecycleError("superseding attestation must belong to same tenant")
    if replacement.boundary_ref != original.boundary_ref:
        raise AttestationLifecycleError("superseding attestation must retain same boundary")
    if (
        replacement.body.window_start != original.body.window_start
        or replacement.body.window_end != original.body.window_end
    ):
        raise AttestationLifecycleError("superseding attestation must retain same window")
    if replacement.record_id == original.record_id:
        raise AttestationLifecycleError("an attestation cannot supersede itself")
    record_attestation(connection, replacement)
    return _record_transition(
        connection,
        tenant_id=tenant_id,
        attestation_id=original_attestation_id,
        reason=_TransitionReason.LATE_EVIDENCE.value,
        effective_at=effective_at,
        signer=signer,
        superseding_ref=replacement.record_id,
        notify=notify,
    )


def attestation_status(
    connection: Connection,
    *,
    tenant_id: str,
    attestation_id: str,
    as_of: datetime,
) -> LifecycleStatus:
    if as_of.tzinfo is None or as_of.utcoffset() is None:
        raise AttestationLifecycleError("status time must be timezone-aware")
    row = _attestation_row(
        connection, tenant_id=tenant_id, attestation_id=attestation_id
    )
    transition = connection.execute(
        select(revocations.c.superseding_attestation_id)
        .where(
            revocations.c.tenant_id == tenant_id,
            revocations.c.attestation_id == uuid.UUID(attestation_id),
            revocations.c.effective_at <= as_of,
        )
        .order_by(revocations.c.effective_at.desc(), revocations.c.sequence.desc())
        .limit(1)
    ).scalar_one_or_none()
    if transition is not None:
        return LifecycleStatus.SUPERSEDED
    revoked = connection.execute(
        select(revocations.c.revocation_id)
        .where(
            revocations.c.tenant_id == tenant_id,
            revocations.c.attestation_id == uuid.UUID(attestation_id),
            revocations.c.effective_at <= as_of,
        )
        .limit(1)
    ).first()
    if revoked is not None:
        return LifecycleStatus.REVOKED
    if as_of < row["validity_from"]:
        return LifecycleStatus.NOT_YET_VALID
    if as_of >= row["validity_until"]:
        return LifecycleStatus.EXPIRED
    return LifecycleStatus.VALID


__all__ = [
    "AttestationLifecycleError",
    "LifecycleStatus",
    "LifecycleTransition",
    "NotificationSink",
    "NotificationStatus",
    "RevocationGround",
    "attestation_status",
    "record_attestation",
    "revoke_attestation",
    "supersede_attestation",
]
