"""Evidence-stream linking, fork detection, and key continuity (ES-006..008/024)."""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from sdk_python.evidence.canonical import canonical_digest, canonicalize
from sdk_python.evidence.origin import primary_signer_namespace
from sdk_python.evidence.schema import RecordEnvelope
from sdk_python.evidence.signing import (
    ALGORITHM,
    CONTINUITY_FIELDS,
    SignatureError,
    UnsupportedAlgorithmError,
    verify_record_signature,
)


class ChainVerificationError(ValueError):
    """A break with enough context for the attestation layer to stop safely."""

    def __init__(
        self,
        message: str,
        *,
        stream_id: str | None = None,
        break_sequence: int | None = None,
        valid_through_sequence: int | None = None,
        fatal: bool = False,
        coverage_gap_body: Mapping[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.stream_id = stream_id
        self.break_sequence = break_sequence
        self.valid_through_sequence = valid_through_sequence
        self.attestation_permitted = not fatal
        self.coverage_gap_body = dict(coverage_gap_body or {})


class StreamForkError(ChainVerificationError):
    """Two different records claim one stream position; no prefix is trusted."""


class SequenceGapError(ChainVerificationError):
    """A sequence number is missing from the submitted stream."""


class DigestLinkError(ChainVerificationError):
    """A record does not commit the canonical digest of its predecessor."""


class KeyContinuityError(ChainVerificationError):
    """A signing-key change lacks a valid proof from the predecessor key."""


class KeyNamespaceError(ChainVerificationError):
    """A cryptographically valid signer belongs to a forbidden key namespace."""


class RegisteredPublicKey(Protocol):
    """The key-registry facts required by namespace-aware verification."""

    namespace: str
    public_key: Ed25519PublicKey


@dataclass(frozen=True, slots=True)
class ChainVerificationResult:
    """The completely verified contiguous prefix for one stream."""

    stream_id: str
    start_sequence: int
    end_sequence: int
    last_digest: str
    last_key_id: str
    records: tuple[RecordEnvelope, ...]


def _encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_base64url(value: object, *, label: str, expected_length: int) -> bytes:
    if (
        not isinstance(value, str)
        or not value
        or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None
    ):
        raise KeyContinuityError(f"{label} must be unpadded base64url")
    try:
        raw = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, binascii.Error) as exc:
        raise KeyContinuityError(f"{label} must be unpadded base64url") from exc
    if len(raw) != expected_length:
        raise KeyContinuityError(f"{label} has the wrong Ed25519 length")
    return raw


def _public_key_bytes(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _continuity_payload(
    *,
    predecessor_key_id: str,
    new_key_id: str,
    new_public_key: Ed25519PublicKey,
    tenant_id: str,
    stream_id: str,
) -> dict[str, str]:
    if not all((predecessor_key_id, new_key_id, tenant_id, stream_id)):
        raise KeyContinuityError("continuity IDs must be non-empty strings")
    if predecessor_key_id == new_key_id:
        raise KeyContinuityError("key continuity must describe a real key rotation")
    return {
        "alg": ALGORITHM,
        "predecessor_key_id": predecessor_key_id,
        "new_key_id": new_key_id,
        "new_public_key": _encode_base64url(_public_key_bytes(new_public_key)),
        "tenant_id": tenant_id,
        "stream_id": stream_id,
    }


def create_key_continuity(
    *,
    predecessor_key_id: str,
    predecessor_private_key: Ed25519PrivateKey,
    new_key_id: str,
    new_public_key: Ed25519PublicKey,
    tenant_id: str,
    stream_id: str,
) -> dict[str, str]:
    """Sign a context-bound key rotation with the predecessor key (ES-024a)."""

    payload = _continuity_payload(
        predecessor_key_id=predecessor_key_id,
        new_key_id=new_key_id,
        new_public_key=new_public_key,
        tenant_id=tenant_id,
        stream_id=stream_id,
    )
    return {
        **payload,
        "sig": _encode_base64url(predecessor_private_key.sign(canonicalize(payload))),
    }


def verify_key_continuity(
    assertion: Mapping[str, object],
    *,
    expected_predecessor_key_id: str,
    predecessor_public_key: Ed25519PublicKey,
    expected_new_key_id: str,
    new_public_key: Ed25519PublicKey,
    expected_tenant_id: str,
    expected_stream_id: str,
) -> None:
    """Verify a closed, non-negotiable Ed25519 continuity assertion."""

    if set(assertion) != CONTINUITY_FIELDS:
        raise KeyContinuityError("key continuity assertion has unknown or missing fields")
    if assertion.get("alg") != ALGORITHM:
        raise UnsupportedAlgorithmError(
            "unsupported key-continuity algorithm; v0.1 accepts only ed25519"
        )
    if assertion.get("predecessor_key_id") != expected_predecessor_key_id:
        raise KeyContinuityError("key continuity names the wrong predecessor key")
    if assertion.get("new_key_id") != expected_new_key_id:
        raise KeyContinuityError("key continuity names the wrong new key")
    if assertion.get("tenant_id") != expected_tenant_id:
        raise KeyContinuityError("key continuity tenant_id does not match record tenant_id")
    if assertion.get("stream_id") != expected_stream_id:
        raise KeyContinuityError("key continuity stream_id does not match record stream_id")
    expected_public_key = _public_key_bytes(new_public_key)
    asserted_public_key = _decode_base64url(
        assertion.get("new_public_key"), label="new public key", expected_length=32
    )
    if asserted_public_key != expected_public_key:
        raise KeyContinuityError("key continuity contains the wrong new public key")

    payload = {
        "alg": assertion["alg"],
        "predecessor_key_id": assertion["predecessor_key_id"],
        "new_key_id": assertion["new_key_id"],
        "new_public_key": assertion["new_public_key"],
        "tenant_id": assertion["tenant_id"],
        "stream_id": assertion["stream_id"],
    }
    signature = _decode_base64url(
        assertion.get("sig"), label="continuity sig", expected_length=64
    )
    try:
        predecessor_public_key.verify(signature, canonicalize(payload))
    except InvalidSignature as exc:
        raise KeyContinuityError("new public key is not signed by the predecessor key") from exc


def _gap_body(
    previous: RecordEnvelope,
    current: RecordEnvelope,
    *,
    cause: str,
) -> dict[str, object]:
    return {
        "gap_start": previous.clocks.source_time,
        "gap_end": current.clocks.source_time,
        "affected_scope": {"stream_id": current.stream_id},
        "cause": cause,
        "detection_source": "chain_verifier",
        "exposure": "unknown",
        "actions_during_gap": None,
    }


def _signature_key_id(
    record: RecordEnvelope,
    public_keys: Mapping[str, Ed25519PublicKey],
    *,
    verification_keys: Mapping[str, RegisteredPublicKey],
    valid_through_sequence: int | None = None,
    coverage_gap_body: Mapping[str, object] | None = None,
) -> str:
    try:
        key_id = verify_record_signature(record, public_keys=public_keys)
    except SignatureError as exc:
        raise ChainVerificationError(
            f"signature verification failed at sequence {record.sequence}: {exc}",
            stream_id=record.stream_id,
            break_sequence=record.sequence,
            valid_through_sequence=valid_through_sequence,
            coverage_gap_body=coverage_gap_body,
        ) from exc
    expected = primary_signer_namespace(record.record_type)
    if verification_keys[key_id].namespace != expected:
        raise KeyNamespaceError(
            "key namespace mismatch: "
            f"{record.record_type} requires an {expected} primary signer",
            stream_id=record.stream_id,
            break_sequence=record.sequence,
            valid_through_sequence=valid_through_sequence,
            coverage_gap_body=coverage_gap_body,
        )
    return key_id


def _fork_checked_records(
    records: Iterable[RecordEnvelope],
    public_keys: Mapping[str, Ed25519PublicKey],
    *,
    verification_keys: Mapping[str, RegisteredPublicKey],
) -> list[RecordEnvelope]:
    positions: dict[tuple[str, int], RecordEnvelope] = {}
    for record in records:
        position = (record.stream_id, record.sequence)
        previous = positions.get(position)
        if previous is None:
            positions[position] = record
            continue
        if (
            previous.record_id != record.record_id
            or canonical_digest(previous) != canonical_digest(record)
        ):
            # A fatal fork is an authenticated equivocation.  Unsigned garbage
            # at an occupied position is only a bad submission; allowing it to
            # poison the stream would turn fork detection into a DoS primitive.
            _signature_key_id(
                previous, public_keys, verification_keys=verification_keys
            )
            _signature_key_id(record, public_keys, verification_keys=verification_keys)
            raise StreamForkError(
                f"stream fork at {record.stream_id} sequence {record.sequence}",
                stream_id=record.stream_id,
                break_sequence=record.sequence,
                fatal=True,
            )
    return list(positions.values())


def _verify_stream(
    records: Iterable[RecordEnvelope],
    *,
    public_keys: Mapping[str, Ed25519PublicKey],
    verification_keys: Mapping[str, RegisteredPublicKey],
) -> ChainVerificationResult:
    materialized = _fork_checked_records(
        records, public_keys, verification_keys=verification_keys
    )
    if not materialized:
        raise ChainVerificationError("cannot verify an empty stream")
    stream_ids = {record.stream_id for record in materialized}
    if len(stream_ids) != 1:
        raise ChainVerificationError(
            "verify_evidence_stream accepts exactly one stream_id"
        )
    ordered = sorted(materialized, key=lambda record: record.sequence)
    stream_id = ordered[0].stream_id
    stream_namespace = primary_signer_namespace(ordered[0].record_type)
    for record in ordered[1:]:
        record_namespace = primary_signer_namespace(record.record_type)
        if record_namespace != stream_namespace:
            raise KeyNamespaceError(
                "stream changes primary signer namespace; ES-033 requires a new "
                "stream rather than cross-role continuity",
                stream_id=stream_id,
                break_sequence=record.sequence,
            )

    first = ordered[0]
    if first.sequence != 1:
        raise SequenceGapError(
            f"stream begins at sequence {first.sequence} without a verified anchor",
            stream_id=stream_id,
            break_sequence=first.sequence,
            coverage_gap_body={
                "gap_start": first.clocks.source_time,
                "gap_end": first.clocks.source_time,
                "affected_scope": {"stream_id": stream_id},
                "cause": "sequence_break",
                "detection_source": "chain_verifier",
                "exposure": "unknown",
                "actions_during_gap": None,
            },
        )
    if first.sequence == 1 and first.prev_digest is not None:
        raise DigestLinkError(
            "first stream record must have null prev_digest",
            stream_id=stream_id,
            break_sequence=1,
        )
    last_key_id = _signature_key_id(
        first, public_keys, verification_keys=verification_keys
    )
    if "key_continuity" in first.signature:
        raise KeyContinuityError(
            "key continuity is forbidden on the first stream record",
            stream_id=stream_id,
            break_sequence=1,
        )
    last_digest = canonical_digest(first)
    previous = first

    for current in ordered[1:]:
        if current.sequence != previous.sequence + 1:
            raise SequenceGapError(
                f"sequence gap before {current.sequence}",
                stream_id=stream_id,
                break_sequence=current.sequence,
                valid_through_sequence=previous.sequence,
                coverage_gap_body=_gap_body(previous, current, cause="sequence_break"),
            )
        if current.prev_digest != last_digest:
            raise DigestLinkError(
                f"prev_digest mismatch at sequence {current.sequence}",
                stream_id=stream_id,
                break_sequence=current.sequence,
                valid_through_sequence=previous.sequence,
                coverage_gap_body=_gap_body(previous, current, cause="sequence_break"),
            )

        current_key_id = _signature_key_id(
            current,
            public_keys,
            verification_keys=verification_keys,
            valid_through_sequence=previous.sequence,
            coverage_gap_body=_gap_body(
                previous, current, cause="key_discontinuity"
            ),
        )
        continuity = current.signature.get("key_continuity")
        if current_key_id != last_key_id:
            if not isinstance(continuity, dict):
                raise KeyContinuityError(
                    f"key rotation without continuity at sequence {current.sequence}",
                    stream_id=stream_id,
                    break_sequence=current.sequence,
                    valid_through_sequence=previous.sequence,
                    coverage_gap_body=_gap_body(
                        previous, current, cause="key_discontinuity"
                    ),
                )
            predecessor_key = public_keys.get(last_key_id)
            new_key = public_keys.get(current_key_id)
            if predecessor_key is None or new_key is None:  # already checked, defensive
                raise KeyContinuityError("key continuity refers to an unknown key")
            try:
                verify_key_continuity(
                    continuity,
                    expected_predecessor_key_id=last_key_id,
                    predecessor_public_key=predecessor_key,
                    expected_new_key_id=current_key_id,
                    new_public_key=new_key,
                    expected_tenant_id=current.tenant_id,
                    expected_stream_id=current.stream_id,
                )
            except (KeyContinuityError, UnsupportedAlgorithmError) as exc:
                raise KeyContinuityError(
                    f"invalid key continuity at sequence {current.sequence}: {exc}",
                    stream_id=stream_id,
                    break_sequence=current.sequence,
                    valid_through_sequence=previous.sequence,
                    coverage_gap_body=_gap_body(
                        previous, current, cause="key_discontinuity"
                    ),
                ) from exc
            last_key_id = current_key_id
        elif continuity is not None:
            raise KeyContinuityError(
                f"key continuity without a key rotation at sequence {current.sequence}",
                stream_id=stream_id,
                break_sequence=current.sequence,
                valid_through_sequence=previous.sequence,
                coverage_gap_body=_gap_body(
                    previous, current, cause="key_discontinuity"
                ),
            )

        previous = current
        last_digest = canonical_digest(current)

    return ChainVerificationResult(
        stream_id=stream_id,
        start_sequence=ordered[0].sequence,
        end_sequence=ordered[-1].sequence,
        last_digest=last_digest,
        last_key_id=last_key_id,
        records=tuple(ordered),
    )


def verify_evidence_stream(
    records: Iterable[RecordEnvelope],
    *,
    verification_keys: Mapping[str, RegisteredPublicKey],
) -> ChainVerificationResult:
    """Verify one record stream and enforce ES-033 on every active signer.

    A fork is fatal for the complete stream.  Other breaks expose the last
    valid sequence so an attestation window can terminate there rather than
    incorporating unverifiable evidence.

    There is deliberately no namespace-free variant of this function. One
    existed and was exported as ``verify_stream``: it took bare Ed25519 keys,
    which carry no custody namespace, so it could not establish SE-003.  Any
    caller that reached for the primitive instead of the wrapper bypassed the
    check, and an issuer key authenticating a customer stream is exactly the
    confusion the two namespaces exist to make impossible. Issuer-observation
    streams use the same entry point and are dispatched from record_type. A
    weakening path that is merely unattractive is still a path. This mirrors the same rule
    in ``verifier-go/internal/evidence/chain.go``.
    """

    public_keys = {
        key_id: registered.public_key
        for key_id, registered in verification_keys.items()
    }
    return _verify_stream(
        records,
        public_keys=public_keys,
        verification_keys=verification_keys,
    )


def verify_evidence_streams(
    records: Iterable[RecordEnvelope],
    *,
    verification_keys: Mapping[str, RegisteredPublicKey],
) -> dict[str, ChainVerificationResult]:
    """Verify each stream independently, without inventing cross-stream order.

    The namespace-free ``verify_streams`` was removed for the reason given on
    :func:`verify_evidence_stream`.
    """

    grouped: dict[str, list[RecordEnvelope]] = {}
    for record in records:
        grouped.setdefault(record.stream_id, []).append(record)
    if not grouped:
        raise ChainVerificationError("cannot verify an empty stream collection")
    return {
        stream_id: verify_evidence_stream(
            stream_records, verification_keys=verification_keys
        )
        for stream_id, stream_records in grouped.items()
    }
