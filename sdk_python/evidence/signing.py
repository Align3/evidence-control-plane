"""Ed25519 record signatures and issuer counter-signatures (ES-021..023).

Record signatures sign the raw 32-byte SHA-256 value named by
``signed_digest``.  The digest is computed from RFC 8785 canonical bytes with
the complete top-level ``signature`` member removed.  Signing the digest keeps
the Python and future Go implementations independent of an in-memory record
representation while binding every canonical envelope and body member.

An AttestationWindow counter-signature is deliberately different: it commits
the already-present customer signature.  Its digest excludes only the nested
issuer proof, not the complete top-level signature object.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import re
from collections.abc import Mapping
from copy import deepcopy
from hashlib import sha256
from typing import Any, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from sdk_python.evidence.canonical import canonical_digest, canonicalize
from sdk_python.evidence.schema import AttestationWindowRecord, RecordEnvelope

ALGORITHM: Final = "ed25519"
ISSUER_SIGNATURE_MEMBER: Final = "issuer"
CUSTOMER_SIGNATURE_FIELDS: Final = frozenset(
    {"alg", "key_id", "sig", "signed_digest"}
)
CONTINUITY_FIELDS: Final = frozenset(
    {
        "alg",
        "predecessor_key_id",
        "new_key_id",
        "new_public_key",
        "tenant_id",
        "stream_id",
        "sig",
    }
)


class SignatureError(ValueError):
    """Base class for malformed or unverifiable evidence signatures."""


class UnsupportedAlgorithmError(SignatureError):
    """Raised rather than negotiating an algorithm other than Ed25519."""


class UnknownKeyError(SignatureError):
    """Raised when the declared signing key is not in the supplied keyring."""


class InvalidSignatureError(SignatureError):
    """Raised when a signature or its claimed digest does not verify."""


def _record_mapping(record: RecordEnvelope) -> dict[str, Any]:
    value = record.model_dump(mode="json", exclude_unset=True)
    if not isinstance(value, dict):  # pragma: no cover - Pydantic contract
        raise SignatureError("record must serialize as a JSON object")
    return value


def _unsigned_mapping(record: RecordEnvelope) -> dict[str, Any]:
    value = _record_mapping(record)
    value.pop("signature", None)
    return value


def _digest_bytes(digest: str) -> bytes:
    prefix = "sha256:"
    if not digest.startswith(prefix):
        raise SignatureError("signed_digest must use sha256:<lowercase hex>")
    encoded = digest.removeprefix(prefix)
    if len(encoded) != 64 or encoded.lower() != encoded:
        raise SignatureError("signed_digest must use sha256:<lowercase hex>")
    try:
        return bytes.fromhex(encoded)
    except ValueError as exc:
        raise SignatureError("signed_digest must use sha256:<lowercase hex>") from exc


def _encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_base64url(value: object, *, label: str, expected_length: int) -> bytes:
    if (
        not isinstance(value, str)
        or not value
        or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None
    ):
        raise SignatureError(f"{label} must be unpadded base64url")
    try:
        raw = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, binascii.Error) as exc:
        raise SignatureError(f"{label} must be unpadded base64url") from exc
    if len(raw) != expected_length:
        raise SignatureError(f"{label} has the wrong Ed25519 length")
    return raw


def _required_text(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise SignatureError(f"{label} must be a non-empty string")
    return value


def _signature_object(record: RecordEnvelope) -> dict[str, Any]:
    if not isinstance(record.signature, dict):
        raise SignatureError("signature must be a JSON object")
    return deepcopy(record.signature)


def _algorithm(signature: Mapping[str, object]) -> None:
    algorithm = signature.get("alg")
    if algorithm != ALGORITHM:
        raise UnsupportedAlgorithmError(
            f"unsupported signature algorithm {algorithm!r}; v0.1 accepts only ed25519"
        )


def _closed_members(
    value: Mapping[str, object],
    *,
    required: frozenset[str],
    allowed: frozenset[str],
    label: str,
    member_label: str = "",
) -> None:
    missing = required - value.keys()
    if missing:
        raise SignatureError(
            f"{label} has missing {member_label}member(s): "
            f"{', '.join(sorted(missing))}"
        )
    unknown = value.keys() - allowed
    if unknown:
        raise SignatureError(
            f"{label} has unknown {member_label}member(s): "
            f"{', '.join(sorted(unknown))}"
        )


def _validate_continuity_members(
    record: RecordEnvelope,
    signature: Mapping[str, object],
    continuity: object,
) -> None:
    if not isinstance(continuity, dict):
        raise SignatureError("key_continuity must be a JSON object")
    _closed_members(
        continuity,
        required=CONTINUITY_FIELDS,
        allowed=CONTINUITY_FIELDS,
        label="key continuity assertion",
    )
    _algorithm(continuity)
    if continuity.get("new_key_id") != signature.get("key_id"):
        raise SignatureError("key continuity new_key_id does not match signature key_id")
    if continuity.get("tenant_id") != record.tenant_id:
        raise SignatureError("key continuity tenant_id does not match record tenant_id")
    if continuity.get("stream_id") != record.stream_id:
        raise SignatureError("key continuity stream_id does not match record stream_id")
    _required_text(
        continuity.get("predecessor_key_id"), label="continuity predecessor_key_id"
    )
    _required_text(continuity.get("new_key_id"), label="continuity new_key_id")
    _required_text(continuity.get("tenant_id"), label="continuity tenant_id")
    _required_text(continuity.get("stream_id"), label="continuity stream_id")
    _decode_base64url(
        continuity.get("new_public_key"),
        label="continuity new_public_key",
        expected_length=32,
    )
    _decode_base64url(
        continuity.get("sig"), label="continuity sig", expected_length=64
    )


def _validate_signature_members(
    record: RecordEnvelope, signature: Mapping[str, object]
) -> None:
    allowed = set(CUSTOMER_SIGNATURE_FIELDS)
    allowed.add("key_continuity")
    if isinstance(record, AttestationWindowRecord):
        allowed.add(ISSUER_SIGNATURE_MEMBER)
    _closed_members(
        signature,
        required=CUSTOMER_SIGNATURE_FIELDS,
        allowed=frozenset(allowed),
        label="signature",
        member_label="signature ",
    )

    if "key_continuity" in signature:
        _validate_continuity_members(
            record, signature, signature.get("key_continuity")
        )

    if ISSUER_SIGNATURE_MEMBER in signature:
        issuer = signature.get(ISSUER_SIGNATURE_MEMBER)
        if not isinstance(issuer, dict):
            raise SignatureError("issuer signature must be a JSON object")
        _closed_members(
            issuer,
            required=CUSTOMER_SIGNATURE_FIELDS,
            allowed=CUSTOMER_SIGNATURE_FIELDS,
            label="issuer signature",
            member_label="issuer signature ",
        )


def signing_digest(record: RecordEnvelope) -> str:
    """Return the ES-021 digest of a record with ``signature`` excluded."""

    return canonical_digest(_unsigned_mapping(record))


def record_signing_bytes(record: RecordEnvelope) -> bytes:
    """Return the exact primary-signer bytes covered by ``signed_digest``."""

    return canonicalize(_unsigned_mapping(record))


def record_signature_bytes(record: RecordEnvelope) -> bytes:
    """Return the raw Ed25519 proof embedded in ``record.signature``.

    The same strict decoder used by verification is intentional: storage
    callers must not acquire a second, weaker interpretation of the proof.
    """

    signature = _signature_object(record)
    _validate_signature_members(record, signature)
    return _decode_base64url(signature.get("sig"), label="sig", expected_length=64)


def sign_record[RecordT: RecordEnvelope](
    record: RecordT,
    *,
    key_id: str,
    private_key: Ed25519PrivateKey,
    key_continuity: Mapping[str, object] | None = None,
) -> RecordT:
    """Return a copy carrying its primary Ed25519 signature.

    This primitive proves bytes, not custody role. ES-033 namespace dispatch is
    enforced by the complete record verifiers; callers producing issuer
    observations pass an issuer key and callers producing customer records pass
    an evidence key.

    ``key_continuity`` is attached only on the first record using a new key.
    It is a separately authenticated assertion created by ``chain`` and is
    carried in the existing signature object because v0.1 defines no separate
    KeyContinuity record type.
    """

    if record.signature:
        raise SignatureError("record already carries a signature; refusing to overwrite it")
    key_id = _required_text(key_id, label="key_id")
    digest = signing_digest(record)
    signature: dict[str, object] = {
        "alg": ALGORITHM,
        "key_id": key_id,
        "sig": _encode_base64url(private_key.sign(_digest_bytes(digest))),
        "signed_digest": digest,
    }
    if key_continuity is not None:
        signature["key_continuity"] = deepcopy(dict(key_continuity))
    _validate_signature_members(record, signature)
    return record.model_copy(update={"signature": signature}, deep=True)


def verify_record_signature(
    record: RecordEnvelope,
    *,
    public_keys: Mapping[str, Ed25519PublicKey],
) -> str:
    """Verify the primary signature's cryptography and return its key ID.

    This is deliberately *not* an ES-033 entry point and cannot become one:
    ``public_keys`` holds bare Ed25519 keys, which carry no custody namespace,
    so origin dispatch is unrepresentable here rather than merely omitted. It
    answers "was this signed by the key claimed" and nothing about whether that
    key was allowed to sign this record type.

    ``chain.py`` removed its namespace-free ``verify_stream`` export on the
    grounds that a weakening path which is merely unattractive is still a path.
    The reason this primitive stays is that it is not such a path: it is
    unexported from ``sdk_python.evidence``, and both in-tree callers
    (``chain._signature_key_id`` and
    ``services.ingestion.receipts.verify_record_origin_signature``) apply
    ``primary_signer_namespace`` to the key ID it returns. Reach for
    ``verify_record_origin_signature`` unless you are building that check.
    """

    return verify_record_signature_bytes(
        record,
        signing_bytes=record_signing_bytes(record),
        public_keys=public_keys,
    )


def verify_record_signature_bytes(
    record: RecordEnvelope,
    *,
    signing_bytes: bytes,
    public_keys: Mapping[str, Ed25519PublicKey],
) -> str:
    """Verify against the exact primary-signing bytes retained by storage.

    Callers that possess the received canonical representation pass those
    bytes here.  The ordinary model-only verifier remains available for
    offline callers that necessarily have to render the model first.
    """

    expected_signing_bytes = record_signing_bytes(record)
    if not hmac.compare_digest(signing_bytes, expected_signing_bytes):
        raise InvalidSignatureError(
            "canonical signing bytes do not match the supplied record"
        )

    signature = _signature_object(record)
    _validate_signature_members(record, signature)
    _algorithm(signature)
    key_id = _required_text(signature.get("key_id"), label="key_id")
    public_key = public_keys.get(key_id)
    if public_key is None:
        raise UnknownKeyError(f"unknown evidence signing key: {key_id}")

    claimed_digest = _required_text(signature.get("signed_digest"), label="signed_digest")
    actual_digest = f"sha256:{sha256(signing_bytes).hexdigest()}"
    if not hmac.compare_digest(claimed_digest, actual_digest):
        raise InvalidSignatureError("signed_digest does not match the canonical record")

    encoded_signature = _decode_base64url(
        signature.get("sig"), label="sig", expected_length=64
    )
    try:
        public_key.verify(encoded_signature, _digest_bytes(actual_digest))
    except InvalidSignature as exc:
        raise InvalidSignatureError("Ed25519 record signature verification failed") from exc
    return key_id


def _counter_signing_mapping(record: AttestationWindowRecord) -> dict[str, Any]:
    value = _record_mapping(record)
    signature = value.get("signature")
    if not isinstance(signature, dict):
        raise SignatureError("signature must be a JSON object")
    signature.pop(ISSUER_SIGNATURE_MEMBER, None)
    return value


def counter_signing_digest(record: AttestationWindowRecord) -> str:
    """Digest an attestation including its customer signature."""

    return canonical_digest(_counter_signing_mapping(record))


def counter_sign_attestation(
    record: AttestationWindowRecord,
    *,
    issuer_key_id: str,
    issuer_private_key: Ed25519PrivateKey,
) -> AttestationWindowRecord:
    """Add the issuer's ES-023 counter-signature without replacing customer proof."""

    signature = _signature_object(record)
    if not CUSTOMER_SIGNATURE_FIELDS.issubset(signature):
        raise SignatureError("customer signature must exist before issuer counter-signing")
    _validate_signature_members(record, signature)
    if ISSUER_SIGNATURE_MEMBER in signature:
        raise SignatureError("attestation already carries an issuer counter-signature")
    issuer_key_id = _required_text(issuer_key_id, label="issuer key_id")
    digest = counter_signing_digest(record)
    signature[ISSUER_SIGNATURE_MEMBER] = {
        "alg": ALGORITHM,
        "key_id": issuer_key_id,
        "sig": _encode_base64url(issuer_private_key.sign(_digest_bytes(digest))),
        "signed_digest": digest,
    }
    _validate_signature_members(record, signature)
    return record.model_copy(update={"signature": signature}, deep=True)


def verify_attestation_counter_signature(
    record: AttestationWindowRecord,
    *,
    issuer_public_keys: Mapping[str, Ed25519PublicKey],
) -> str:
    """Verify the issuer proof and return its key ID."""

    signature = _signature_object(record)
    _validate_signature_members(record, signature)
    issuer = signature.get(ISSUER_SIGNATURE_MEMBER)
    if not isinstance(issuer, dict):
        raise InvalidSignatureError("attestation has no issuer counter-signature")
    _algorithm(issuer)
    key_id = _required_text(issuer.get("key_id"), label="issuer key_id")
    public_key = issuer_public_keys.get(key_id)
    if public_key is None:
        raise UnknownKeyError(f"unknown issuer signing key: {key_id}")

    claimed_digest = _required_text(issuer.get("signed_digest"), label="signed_digest")
    actual_digest = counter_signing_digest(record)
    if not hmac.compare_digest(claimed_digest, actual_digest):
        raise InvalidSignatureError(
            "counter-signature signed_digest does not match the customer-signed attestation"
        )
    encoded_signature = _decode_base64url(
        issuer.get("sig"), label="issuer sig", expected_length=64
    )
    try:
        public_key.verify(encoded_signature, _digest_bytes(actual_digest))
    except InvalidSignature as exc:
        raise InvalidSignatureError("Ed25519 counter-signature verification failed") from exc
    return key_id


def verify_attestation_signatures(
    record: AttestationWindowRecord,
    *,
    evidence_public_keys: Mapping[str, Ed25519PublicKey],
    issuer_public_keys: Mapping[str, Ed25519PublicKey],
) -> tuple[str, str]:
    """Require and verify both sides of the ES-023 two-signature model."""

    evidence_key_id = verify_record_signature(record, public_keys=evidence_public_keys)
    issuer_key_id = verify_attestation_counter_signature(
        record, issuer_public_keys=issuer_public_keys
    )
    return evidence_key_id, issuer_key_id
