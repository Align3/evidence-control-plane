"""Issuer-signed hosted clock observations (ES-019, ES-030, DM-024)."""

from __future__ import annotations

import hmac
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import ValidationError

from sdk_python.evidence.canonical import canonicalize
from sdk_python.evidence.schema import IngestionReceipt, RecordEnvelope
from sdk_python.evidence.signing import signing_digest

_LEAP_SECOND = re.compile(r":60(?=\.\d+(?:Z|[+-]\d{2}:\d{2})$)")


class ReceiptError(ValueError):
    """A hosted observation cannot be represented as a conformant receipt."""


class ReceiptSignatureError(ReceiptError):
    """The issuer proof does not authenticate the exact receipt bytes."""


@dataclass(frozen=True, slots=True)
class SignedIngestionReceipt:
    """Authoritative receipt bytes and their detached issuer proof."""

    payload: IngestionReceipt
    canonical_bytes: bytes
    key_id: str
    signature: bytes


def _parse_timestamp(value: str) -> datetime:
    leap_second = _LEAP_SECOND.search(value) is not None
    normalized = _LEAP_SECOND.sub(":59", value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:  # pragma: no cover - schema normally catches this
        raise ReceiptError(f"invalid RFC 3339 timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        raise ReceiptError("receipt timestamps require an explicit UTC offset")
    if leap_second:
        parsed += timedelta(seconds=1)
    return parsed


def _format_ingest_time(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ReceiptError("ingest_time must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _whole_milliseconds(delta: timedelta) -> int:
    microseconds = (
        delta.days * 86_400_000_000 + delta.seconds * 1_000_000 + delta.microseconds
    )
    if microseconds < 0:
        return -((-microseconds) // 1_000)
    return microseconds // 1_000


def measure_clock_skew_ms(*, source_time: str, ingest_time: str) -> int:
    """Return ``ingest_time - source_time`` in whole milliseconds."""

    return _whole_milliseconds(_parse_timestamp(ingest_time) - _parse_timestamp(source_time))


def create_ingestion_receipt(
    record: RecordEnvelope,
    *,
    ingest_time: datetime,
    issuer_key_id: str,
    issuer_private_key: Ed25519PrivateKey,
) -> SignedIngestionReceipt:
    """Observe, canonicalize, and sign hosted receipt metadata without changing record."""

    if not issuer_key_id:
        raise ReceiptError("issuer_key_id must be a non-empty string")
    formatted_ingest_time = _format_ingest_time(ingest_time)
    payload = IngestionReceipt(
        record_digest=signing_digest(record),
        ingest_time=formatted_ingest_time,
        clock_skew_ms=measure_clock_skew_ms(
            source_time=record.clocks.source_time,
            ingest_time=formatted_ingest_time,
        ),
    )
    canonical_bytes = canonicalize(payload)
    return SignedIngestionReceipt(
        payload=payload,
        canonical_bytes=canonical_bytes,
        key_id=issuer_key_id,
        signature=issuer_private_key.sign(canonical_bytes),
    )


def verify_ingestion_receipt(
    receipt: SignedIngestionReceipt,
    *,
    record: RecordEnvelope,
    issuer_public_keys: Mapping[str, Ed25519PublicKey],
) -> IngestionReceipt:
    """Verify issuer proof and binding to the unchanged customer record."""

    public_key = issuer_public_keys.get(receipt.key_id)
    if public_key is None:
        raise ReceiptSignatureError(f"unknown receipt signing key: {receipt.key_id}")
    try:
        payload = IngestionReceipt.model_validate_json(receipt.canonical_bytes)
    except ValidationError as exc:
        raise ReceiptSignatureError("receipt payload is not conformant") from exc
    if canonicalize(payload) != receipt.canonical_bytes:
        raise ReceiptSignatureError("receipt payload is not RFC 8785 canonical")
    try:
        public_key.verify(receipt.signature, receipt.canonical_bytes)
    except InvalidSignature as exc:
        raise ReceiptSignatureError("ingestion receipt signature verification failed") from exc
    if not hmac.compare_digest(payload.record_digest, signing_digest(record)):
        raise ReceiptSignatureError("ingestion receipt names a different customer record")
    measured_skew_ms = measure_clock_skew_ms(
        source_time=record.clocks.source_time,
        ingest_time=payload.ingest_time,
    )
    if payload.clock_skew_ms != measured_skew_ms:
        raise ReceiptSignatureError(
            "ingestion receipt clock_skew_ms does not match ingest_time - source_time"
        )
    return payload
