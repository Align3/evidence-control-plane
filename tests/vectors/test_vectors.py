"""Execute every normative ES-029 vector through the Python implementation."""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from sdk_python.evidence.canonical import (
    CanonicalizationError,
    canonical_digest,
    canonicalize,
)
from sdk_python.evidence.chain import (
    ChainVerificationError,
    DigestLinkError,
    KeyContinuityError,
    SequenceGapError,
    StreamForkError,
    verify_stream,
)
from sdk_python.evidence.schema import AttestationWindowRecord, RecordEnvelope, validate_record
from sdk_python.evidence.signing import (
    SignatureError,
    counter_sign_attestation,
    sign_record,
    verify_attestation_signatures,
    verify_record_signature,
)
from tests.vectors.generate import VECTOR_PATH, render_vectors

DOCUMENT: dict[str, Any] = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
VECTORS: list[dict[str, Any]] = DOCUMENT["vectors"]

REQUIRED_ATTACK_VECTORS = {
    "canonical-utf16-order",
    "chain-valid-signature-inclusive-prev-digest",
    "reject-validly-resigned-predecessor",
    "reject-signature-excluded-prev-digest",
    "reject-unknown-customer-signature-member",
    "reject-unknown-issuer-signature-member",
    "reject-unknown-continuity-member",
    "rotation-valid-context-bound",
    "reject-continuity-tenant-replay",
    "reject-continuity-stream-replay",
    "reject-forged-continuity-tenant-binding",
    "reject-forged-continuity-stream-binding",
    "new-stream-starts-from-trusted-keyring-anchor",
    "reject-continuity-on-first-stream-record",
    "reject-missing-customer-signature-member",
    "reject-missing-issuer-signature-member",
    "reject-missing-continuity-member",
}
JCS_REFERENCE = Path(__file__).parents[1] / "property" / "jcs_reference.js"


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _public_keys(encoded: dict[str, str]) -> dict[str, Ed25519PublicKey]:
    return {
        key_id: Ed25519PublicKey.from_public_bytes(_decode(public_key))
        for key_id, public_key in encoded.items()
    }


def _record(value: dict[str, Any]) -> RecordEnvelope:
    return validate_record(value)


def _error_code(error: Exception) -> str:
    message = str(error)
    if isinstance(error, CanonicalizationError):
        if "lone surrogates" in message:
            return "canonicalization.lone_surrogate"
        if "outside the interoperable JCS range" in message:
            return "canonicalization.integer_out_of_range"
        if "IEEE-754 floats" in message:
            return "canonicalization.float_forbidden"
    if isinstance(error, StreamForkError):
        return "chain.fork"
    if isinstance(error, SequenceGapError):
        return "chain.sequence_gap"
    if isinstance(error, DigestLinkError):
        return "chain.prev_digest_mismatch"
    if isinstance(error, KeyContinuityError):
        if "rotation without continuity" in message:
            return "continuity.missing"
        if "signed by the predecessor" in message:
            return "continuity.signature_invalid"
        if "forbidden on the first stream record" in message:
            return "continuity.first_record_forbidden"
        if "without a key rotation" in message:
            return "continuity.no_key_change"
    if isinstance(error, ChainVerificationError):
        if "continuity tenant_id does not match" in message:
            return "continuity.tenant_mismatch"
        if "continuity stream_id does not match" in message:
            return "continuity.stream_mismatch"
        if "key continuity assertion has unknown member" in message:
            return "continuity.unknown_member"
        if "key continuity assertion has missing member" in message:
            return "continuity.missing_member"
    if isinstance(error, SignatureError):
        if "unsupported signature algorithm" in message:
            return "signature.algorithm_unsupported"
        if "must be unpadded base64url" in message:
            return "signature.encoding_invalid"
        if "unknown issuer signature member" in message:
            return "signature.unknown_issuer_member"
        if "missing issuer signature member" in message:
            return "signature.missing_issuer_member"
        if "unknown signature member" in message:
            return "signature.unknown_customer_member"
        if "missing signature member" in message:
            return "signature.missing_customer_member"
    raise AssertionError(f"unmapped Python refusal: {type(error).__name__}: {error}")


def _assert_expected_error(expected: dict[str, Any], error: Exception) -> None:
    assert _error_code(error) == expected["error_code"]
    for attribute in (
        "break_sequence",
        "valid_through_sequence",
        "attestation_permitted",
    ):
        if attribute in expected:
            assert getattr(error, attribute) == expected[attribute]


def _run_canonicalization(vector: dict[str, Any]) -> None:
    value = json.loads(vector["input_json"])
    expected = vector["expected"]
    if not expected["accepted"]:
        with pytest.raises(CanonicalizationError) as caught:
            canonicalize(value)
        _assert_expected_error(expected, caught.value)
        return

    canonical = canonicalize(value)
    assert canonical.decode("utf-8") == expected["canonical_json"]
    assert canonical.hex() == expected["canonical_utf8_hex"]
    assert canonical_digest(value) == expected["digest"]


def _run_sign_record(vector: dict[str, Any]) -> None:
    expected = vector["expected"]
    private_key = Ed25519PrivateKey.from_private_bytes(
        _decode(vector["private_key_seed"])
    )
    public_key = Ed25519PublicKey.from_public_bytes(_decode(vector["public_key"]))
    signed = sign_record(
        _record(vector["unsigned_record"]),
        key_id=vector["key_id"],
        private_key=private_key,
    )

    assert signed.signature == expected["signature"]
    assert signed.signature["signed_digest"] == expected["signed_digest"]
    assert signed.model_dump(mode="json", exclude_unset=True) == expected["signed_record"]
    assert canonical_digest(signed) == expected["signed_record_digest"]
    assert verify_record_signature(
        signed, public_keys={vector["key_id"]: public_key}
    ) == vector["key_id"]


def _run_verify_signature(vector: dict[str, Any]) -> None:
    record = _record(vector["record"])
    expected = vector["expected"]
    try:
        key_id = verify_record_signature(
            record, public_keys=_public_keys(vector["public_keys"])
        )
    except SignatureError as error:
        assert not expected["accepted"]
        _assert_expected_error(expected, error)
        return
    assert expected["accepted"]
    assert key_id == expected["key_id"]


def _run_verify_attestation(vector: dict[str, Any]) -> None:
    record = _record(vector["record"])
    assert isinstance(record, AttestationWindowRecord)
    expected = vector["expected"]
    if "private_key_seeds" in vector:
        unsigned_raw = json.loads(json.dumps(vector["record"]))
        unsigned_raw["signature"] = {}
        unsigned = _record(unsigned_raw)
        assert isinstance(unsigned, AttestationWindowRecord)
        customer_signed = sign_record(
            unsigned,
            key_id=expected["evidence_key_id"],
            private_key=Ed25519PrivateKey.from_private_bytes(
                _decode(vector["private_key_seeds"][expected["evidence_key_id"]])
            ),
        )
        reproduced = counter_sign_attestation(
            customer_signed,
            issuer_key_id=expected["issuer_key_id"],
            issuer_private_key=Ed25519PrivateKey.from_private_bytes(
                _decode(vector["private_key_seeds"][expected["issuer_key_id"]])
            ),
        )
        assert reproduced.model_dump(
            mode="json", exclude_unset=True
        ) == record.model_dump(mode="json", exclude_unset=True)
    try:
        key_ids = verify_attestation_signatures(
            record,
            evidence_public_keys=_public_keys(vector["evidence_public_keys"]),
            issuer_public_keys=_public_keys(vector["issuer_public_keys"]),
        )
    except SignatureError as error:
        assert not expected["accepted"]
        _assert_expected_error(expected, error)
        return
    assert expected["accepted"]
    assert key_ids == (expected["evidence_key_id"], expected["issuer_key_id"])
    assert canonical_digest(record) == expected["record_digest"]


def _run_verify_stream(vector: dict[str, Any]) -> None:
    records = [_record(value) for value in vector["records"]]
    expected = vector["expected"]
    try:
        result = verify_stream(records, public_keys=_public_keys(vector["public_keys"]))
    except ChainVerificationError as error:
        assert not expected["accepted"]
        _assert_expected_error(expected, error)
        return

    assert expected["accepted"]
    assert result.start_sequence == expected["start_sequence"]
    assert result.end_sequence == expected["end_sequence"]
    assert result.last_key_id == expected["last_key_id"]
    assert result.last_digest == expected["last_digest"]
    if "sequence_2_prev_digest" in expected:
        assert records[1].prev_digest == expected["sequence_2_prev_digest"]
        assert records[1].prev_digest != expected["signature_excluded_digest_must_differ"]


RUNNERS = {
    "canonicalize": _run_canonicalization,
    "sign_record": _run_sign_record,
    "verify_signature": _run_verify_signature,
    "verify_attestation_signatures": _run_verify_attestation,
    "verify_stream": _run_verify_stream,
}


def test_es_029_vector_manifest_is_closed_and_attack_complete() -> None:
    assert DOCUMENT["format"] == "evidence-control-plane-conformance-vectors"
    assert DOCUMENT["format_version"] == "1.0.0"
    assert DOCUMENT["spec_version"] == "0.1"
    ids = [vector["id"] for vector in VECTORS]
    assert len(ids) == len(set(ids))
    assert {vector["operation"] for vector in VECTORS} == set(RUNNERS)
    assert REQUIRED_ATTACK_VECTORS <= set(ids)
    assert sum(not vector["expected"]["accepted"] for vector in VECTORS) > sum(
        vector["expected"]["accepted"] for vector in VECTORS
    )


def test_es_029_stored_vectors_match_deterministic_generation() -> None:
    assert Path(VECTOR_PATH).read_bytes() == render_vectors()


def _oracle_disagreements(vectors: list[dict[str, Any]]) -> list[str]:
    node = shutil.which("node")
    assert node is not None, "Node is required for the independent RFC 8785 vector gate"
    completed = subprocess.run(  # noqa: S603 - resolved executable, fixed script
        [node, str(JCS_REFERENCE)],
        input=json.dumps([json.loads(vector["input_json"]) for vector in vectors]).encode(),
        capture_output=True,
        check=True,
    )
    oracle_outputs: list[str] = json.loads(completed.stdout)
    disagreements: list[str] = []
    for vector, oracle in zip(vectors, oracle_outputs, strict=True):
        expected = vector["expected"]
        oracle_bytes = oracle.encode("utf-8")
        oracle_digest = f"sha256:{sha256(oracle_bytes).hexdigest()}"
        if (
            oracle != expected["canonical_json"]
            or oracle_bytes.hex() != expected["canonical_utf8_hex"]
            or oracle_digest != expected["digest"]
        ):
            disagreements.append(
                f"ORACLE DISAGREES: {vector['id']}\n"
                f"  corpus: {expected['canonical_json']!r}\n"
                f"  oracle: {oracle!r}"
            )
    return disagreements


def test_es_029_canonicalization_matches_independent_ecmascript_oracle() -> None:
    vectors = [
        vector
        for vector in VECTORS
        if vector["operation"] == "canonicalize" and vector["expected"]["accepted"]
    ]
    disagreements = _oracle_disagreements(vectors)
    assert not disagreements, "\n\n".join(disagreements)


def test_es_029_oracle_rejects_coherently_regenerated_non_rfc_bytes() -> None:
    vector = deepcopy(
        next(vector for vector in VECTORS if vector["id"] == "canonical-utf16-order")
    )
    wrong = '{"\ue000":1,"😀":2}'  # Unicode code-point order, not RFC 8785 UTF-16 order.
    wrong_bytes = wrong.encode("utf-8")
    vector["expected"].update(
        {
            "canonical_json": wrong,
            "canonical_utf8_hex": wrong_bytes.hex(),
            "digest": f"sha256:{sha256(wrong_bytes).hexdigest()}",
        }
    )

    disagreements = _oracle_disagreements([vector])

    assert disagreements
    assert "ORACLE DISAGREES: canonical-utf16-order" in disagreements[0]


@pytest.mark.parametrize("vector", VECTORS, ids=lambda vector: vector["id"])
def test_es_029_python_implementation_passes_vector(vector: dict[str, Any]) -> None:
    RUNNERS[vector["operation"]](vector)
