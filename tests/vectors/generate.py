"""Deterministically render the normative ES-029 v0.1 vector corpus."""

from __future__ import annotations

import argparse
import base64
import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sdk_python.evidence.canonical import canonical_digest, canonicalize
from sdk_python.evidence.chain import create_key_continuity
from sdk_python.evidence.schema import AttestationWindowRecord, RecordEnvelope, validate_record
from sdk_python.evidence.signing import (
    counter_sign_attestation,
    sign_record,
    signing_digest,
)

VECTOR_PATH = Path(__file__).with_name("vectors-v0.1.json")
TS = "2026-08-01T12:00:00.000+01:00"
SEEDS = {
    "K1": bytes(range(0x00, 0x20)),
    "K2": bytes(range(0x20, 0x40)),
    "KX": bytes(range(0x40, 0x60)),
    "ISSUER1": bytes(range(0x60, 0x80)),
}


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _key(key_id: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(SEEDS[key_id])


def _public_key(key_id: str) -> str:
    raw = _key(key_id).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _b64(raw)


def _keyring(*key_ids: str) -> dict[str, str]:
    return {key_id: _public_key(key_id) for key_id in key_ids}


def _dump(record: RecordEnvelope) -> dict[str, Any]:
    return record.model_dump(mode="json", exclude_unset=True)


def _record_id(index: int) -> str:
    return f"01890f47-2f58-7cc0-98c4-{index:012x}"


def _agent_record(
    sequence: int,
    *,
    record_index: int | None = None,
    tenant_id: str = "tenant-1",
    stream_id: str = "stream-1",
    prev_digest: str | None = None,
) -> RecordEnvelope:
    return validate_record(
        {
            "record_id": _record_id(record_index or sequence),
            "record_type": "AgentIdentity",
            "schema_version": "1.0.0",
            "tenant_id": tenant_id,
            "boundary_ref": "boundary-1",
            "stream_id": stream_id,
            "sequence": sequence,
            "prev_digest": prev_digest,
            "source": {"collector": "vector-generator", "version": "0.1.0"},
            "clocks": {
                "source_time": TS,
                "ingest_time": TS,
                "clock_skew_ms": 0,
            },
            "body": {
                "agent_id": "agent-1",
                "deployment": "prod",
                "runtime": "python-3.12",
                "tenant_scope": tenant_id,
                "service_identity": "collector@example.invalid",
                "model_versions": ["model-1"],
                "tool_versions": ["tool-1"],
                "credential_ref": "service_identity",
            },
            "signature": {},
        }
    )


def _attestation_record() -> AttestationWindowRecord:
    record = validate_record(
        {
            "record_id": _record_id(100),
            "record_type": "AttestationWindow",
            "schema_version": "1.0.0",
            "tenant_id": "tenant-1",
            "boundary_ref": "boundary-1",
            "stream_id": "attestation-1",
            "sequence": 1,
            "prev_digest": None,
            "source": {"collector": "vector-generator", "version": "0.1.0"},
            "clocks": {
                "source_time": TS,
                "ingest_time": TS,
                "clock_skew_ms": 0,
            },
            "body": {
                "boundary_ref": "boundary-1",
                "window_start": TS,
                "window_end": TS,
                "methodology_version": "1.0.0",
                "denominator_class": "C1",
                "population_record_refs": [],
                "coverage_level": "observed",
                "verification_status": "self_computed",
                "coverage_ratio": "1.0",
                "counts": {},
                "gaps": [],
                "assertions": [],
                "exclusions": [],
                "relying_parties": [],
                "validity_from": TS,
                "validity_until": TS,
                "liability_ref": "terms-1",
                "issued_at": TS,
                "issuer": "issuer-1",
                "verifier_version": "0.1.0",
            },
            "signature": {},
        }
    )
    if not isinstance(record, AttestationWindowRecord):  # pragma: no cover
        raise TypeError("vector attestation did not select AttestationWindowRecord")
    return record


def _canonicalization_vectors() -> list[dict[str, Any]]:
    valid_inputs = {
        "canonical-object-order": '{"z":0,"a":[3,2,1],"nested":{"b":true,"a":null}}',
        "canonical-utf16-order": '{"\\ue000":1,"\\ud83d\\ude00":2}',
        "canonical-string-escaping": '{"text":"\\b\\t\\n\\f\\r\\u0000\\u001f\\\\\\\"/€"}',
        "canonical-safe-integers": (
            '{"max":9007199254740991,"min":-9007199254740991,"zero":0}'
        ),
        "canonical-preserves-unicode-normalization": '{"á":1,"á":2}',
    }
    vectors: list[dict[str, Any]] = []
    for vector_id, input_json in valid_inputs.items():
        value = json.loads(input_json)
        canonical = canonicalize(value)
        vectors.append(
            {
                "id": vector_id,
                "operation": "canonicalize",
                "input_json": input_json,
                "expected": {
                    "accepted": True,
                    "canonical_json": canonical.decode("utf-8"),
                    "canonical_utf8_hex": canonical.hex(),
                    "digest": canonical_digest(value),
                },
            }
        )

    invalid_inputs = {
        "reject-fraction": ('{"value":1.5}', "canonicalization.float_forbidden"),
        "reject-exponent": ('{"value":1e0}', "canonicalization.float_forbidden"),
        "reject-too-large-integer": (
            '{"value":9007199254740992}',
            "canonicalization.integer_out_of_range",
        ),
        "reject-too-small-integer": (
            '{"value":-9007199254740992}',
            "canonicalization.integer_out_of_range",
        ),
        "reject-nan": ('{"value":NaN}', "canonicalization.float_forbidden"),
        "reject-positive-infinity": (
            '{"value":Infinity}',
            "canonicalization.float_forbidden",
        ),
        "reject-negative-infinity": (
            '{"value":-Infinity}',
            "canonicalization.float_forbidden",
        ),
        "reject-lone-surrogate": (
            '{"value":"\\ud800"}',
            "canonicalization.lone_surrogate",
        ),
    }
    for vector_id, (input_json, error_code) in invalid_inputs.items():
        vectors.append(
            {
                "id": vector_id,
                "operation": "canonicalize",
                "input_json": input_json,
                "expected": {
                    "accepted": False,
                    "error_code": error_code,
                },
            }
        )
    return vectors


def _signature_vectors() -> list[dict[str, Any]]:
    unsigned = _agent_record(1)
    signed = sign_record(unsigned, key_id="K1", private_key=_key("K1"))
    sign_vector = {
        "id": "sign-customer-record",
        "operation": "sign_record",
        "key_id": "K1",
        "private_key_seed": _b64(SEEDS["K1"]),
        "public_key": _public_key("K1"),
        "unsigned_record": _dump(unsigned),
        "expected": {
            "accepted": True,
            "signed_digest": signing_digest(unsigned),
            "signature": deepcopy(signed.signature),
            "signed_record": _dump(signed),
            "signed_record_digest": canonical_digest(signed),
        },
    }

    extended_raw = _dump(unsigned)
    extended_raw["body"]["future_extension"] = {
        "included_in_signature": True,
        "version": 2,
    }
    extended_unsigned = validate_record(extended_raw)
    extended_signed = sign_record(
        extended_unsigned, key_id="K1", private_key=_key("K1")
    )
    unknown_body_vector = {
        "id": "sign-record-preserves-unknown-body-member",
        "operation": "sign_record",
        "key_id": "K1",
        "private_key_seed": _b64(SEEDS["K1"]),
        "public_key": _public_key("K1"),
        "unsigned_record": _dump(extended_unsigned),
        "expected": {
            "accepted": True,
            "signed_digest": signing_digest(extended_unsigned),
            "signature": deepcopy(extended_signed.signature),
            "signed_record": _dump(extended_signed),
            "signed_record_digest": canonical_digest(extended_signed),
        },
    }

    unknown_customer = _dump(signed)
    unknown_customer["signature"]["junk"] = "not-authenticated"
    unknown_vector = {
        "id": "reject-unknown-customer-signature-member",
        "operation": "verify_signature",
        "record": unknown_customer,
        "public_keys": _keyring("K1"),
        "expected": {
            "accepted": False,
            "error_code": "signature.unknown_customer_member",
        },
    }
    missing_customer = _dump(signed)
    missing_customer["signature"].pop("signed_digest")
    missing_customer_vector = {
        "id": "reject-missing-customer-signature-member",
        "operation": "verify_signature",
        "record": missing_customer,
        "public_keys": _keyring("K1"),
        "expected": {
            "accepted": False,
            "error_code": "signature.missing_customer_member",
        },
    }
    unsupported_algorithm = _dump(signed)
    unsupported_algorithm["signature"]["alg"] = "ed448"
    unsupported_algorithm_vector = {
        "id": "reject-unsupported-signature-algorithm",
        "operation": "verify_signature",
        "record": unsupported_algorithm,
        "public_keys": _keyring("K1"),
        "expected": {
            "accepted": False,
            "error_code": "signature.algorithm_unsupported",
        },
    }
    padded_signature = _dump(signed)
    padded_signature["signature"]["sig"] += "="
    padded_signature_vector = {
        "id": "reject-padded-signature-encoding",
        "operation": "verify_signature",
        "record": padded_signature,
        "public_keys": _keyring("K1"),
        "expected": {
            "accepted": False,
            "error_code": "signature.encoding_invalid",
        },
    }

    attestation = sign_record(
        _attestation_record(), key_id="K1", private_key=_key("K1")
    )
    counter_signed = counter_sign_attestation(
        attestation,
        issuer_key_id="ISSUER1",
        issuer_private_key=_key("ISSUER1"),
    )
    attestation_vector = {
        "id": "verify-customer-and-issuer-signatures",
        "operation": "verify_attestation_signatures",
        "record": _dump(counter_signed),
        "evidence_public_keys": _keyring("K1"),
        "issuer_public_keys": _keyring("ISSUER1"),
        "private_key_seeds": {
            "K1": _b64(SEEDS["K1"]),
            "ISSUER1": _b64(SEEDS["ISSUER1"]),
        },
        "expected": {
            "accepted": True,
            "evidence_key_id": "K1",
            "issuer_key_id": "ISSUER1",
            "record_digest": canonical_digest(counter_signed),
        },
    }
    unknown_issuer = _dump(counter_signed)
    unknown_issuer["signature"]["issuer"]["junk"] = "not-permitted"
    issuer_closure_vector = {
        "id": "reject-unknown-issuer-signature-member",
        "operation": "verify_attestation_signatures",
        "record": unknown_issuer,
        "evidence_public_keys": _keyring("K1"),
        "issuer_public_keys": _keyring("ISSUER1"),
        "expected": {
            "accepted": False,
            "error_code": "signature.unknown_issuer_member",
        },
    }
    missing_issuer = _dump(counter_signed)
    missing_issuer["signature"]["issuer"].pop("signed_digest")
    missing_issuer_vector = {
        "id": "reject-missing-issuer-signature-member",
        "operation": "verify_attestation_signatures",
        "record": missing_issuer,
        "evidence_public_keys": _keyring("K1"),
        "issuer_public_keys": _keyring("ISSUER1"),
        "expected": {
            "accepted": False,
            "error_code": "signature.missing_issuer_member",
        },
    }
    return [
        sign_vector,
        unknown_body_vector,
        unknown_vector,
        missing_customer_vector,
        unsupported_algorithm_vector,
        padded_signature_vector,
        attestation_vector,
        issuer_closure_vector,
        missing_issuer_vector,
    ]


def _chain_vector(
    vector_id: str,
    records: list[RecordEnvelope],
    key_ids: tuple[str, ...],
    expected: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": vector_id,
        "operation": "verify_stream",
        "records": [_dump(record) for record in records],
        "public_keys": _keyring(*key_ids),
        "expected": expected,
    }


def _chain_vectors() -> list[dict[str, Any]]:
    k1 = _key("K1")
    k2 = _key("K2")
    kx = _key("KX")
    first = sign_record(_agent_record(1), key_id="K1", private_key=k1)
    second = sign_record(
        _agent_record(2, prev_digest=canonical_digest(first)),
        key_id="K1",
        private_key=k1,
    )
    valid_chain = _chain_vector(
        "chain-valid-signature-inclusive-prev-digest",
        [first, second],
        ("K1",),
        {
            "accepted": True,
            "start_sequence": 1,
            "end_sequence": 2,
            "last_key_id": "K1",
            "last_digest": canonical_digest(second),
            "sequence_2_prev_digest": canonical_digest(first),
            "signature_excluded_digest_must_differ": signing_digest(first),
        },
    )

    unsigned_first = first.model_copy(update={"signature": {}}, deep=True)
    resigned_first = sign_record(unsigned_first, key_id="KX", private_key=kx)
    resigned = _chain_vector(
        "reject-validly-resigned-predecessor",
        [resigned_first, second],
        ("K1", "KX"),
        {
            "accepted": False,
            "error_code": "chain.prev_digest_mismatch",
            "break_sequence": 2,
            "valid_through_sequence": 1,
        },
    )

    signature_excluded_link = sign_record(
        _agent_record(2, record_index=20, prev_digest=signing_digest(first)),
        key_id="K1",
        private_key=k1,
    )
    wrong_digest_source = _chain_vector(
        "reject-signature-excluded-prev-digest",
        [first, signature_excluded_link],
        ("K1",),
        {
            "accepted": False,
            "error_code": "chain.prev_digest_mismatch",
            "break_sequence": 2,
            "valid_through_sequence": 1,
        },
    )

    continuity = create_key_continuity(
        predecessor_key_id="K1",
        predecessor_private_key=k1,
        new_key_id="K2",
        new_public_key=k2.public_key(),
        tenant_id="tenant-1",
        stream_id="stream-1",
    )
    rotated = sign_record(
        _agent_record(2, record_index=21, prev_digest=canonical_digest(first)),
        key_id="K2",
        private_key=k2,
        key_continuity=continuity,
    )
    valid_rotation = _chain_vector(
        "rotation-valid-context-bound",
        [first, rotated],
        ("K1", "K2"),
        {
            "accepted": True,
            "start_sequence": 1,
            "end_sequence": 2,
            "last_key_id": "K2",
            "last_digest": canonical_digest(rotated),
        },
    )

    rotation_without_proof = sign_record(
        _agent_record(2, record_index=22, prev_digest=canonical_digest(first)),
        key_id="K2",
        private_key=k2,
    )
    missing_continuity = _chain_vector(
        "reject-rotation-without-continuity",
        [first, rotation_without_proof],
        ("K1", "K2"),
        {
            "accepted": False,
            "error_code": "continuity.missing",
            "break_sequence": 2,
            "valid_through_sequence": 1,
        },
    )

    foreign_first = sign_record(
        _agent_record(1, record_index=30, tenant_id="tenant-2"),
        key_id="K1",
        private_key=k1,
    )
    foreign_second = sign_record(
        _agent_record(
            2,
            record_index=31,
            tenant_id="tenant-2",
            prev_digest=canonical_digest(foreign_first),
        ),
        key_id="K2",
        private_key=k2,
    )
    replayed_signature = deepcopy(foreign_second.signature)
    replayed_signature["key_continuity"] = deepcopy(continuity)
    replayed = foreign_second.model_copy(
        update={"signature": replayed_signature}, deep=True
    )
    context_replay = _chain_vector(
        "reject-continuity-tenant-replay",
        [foreign_first, replayed],
        ("K1", "K2"),
        {
            "accepted": False,
            "error_code": "continuity.tenant_mismatch",
            "break_sequence": 2,
        },
    )

    foreign_stream_first = sign_record(
        _agent_record(1, record_index=33, stream_id="stream-2"),
        key_id="K1",
        private_key=k1,
    )
    foreign_stream_second = sign_record(
        _agent_record(
            2,
            record_index=34,
            stream_id="stream-2",
            prev_digest=canonical_digest(foreign_stream_first),
        ),
        key_id="K2",
        private_key=k2,
    )
    stream_replayed_signature = deepcopy(foreign_stream_second.signature)
    stream_replayed_signature["key_continuity"] = deepcopy(continuity)
    stream_replayed = foreign_stream_second.model_copy(
        update={"signature": stream_replayed_signature}, deep=True
    )
    stream_replay = _chain_vector(
        "reject-continuity-stream-replay",
        [foreign_stream_first, stream_replayed],
        ("K1", "K2"),
        {
            "accepted": False,
            "error_code": "continuity.stream_mismatch",
            "break_sequence": 2,
        },
    )

    forged_continuity = deepcopy(continuity)
    forged_continuity["tenant_id"] = "tenant-2"
    forged_second = sign_record(
        _agent_record(
            2,
            record_index=32,
            tenant_id="tenant-2",
            prev_digest=canonical_digest(foreign_first),
        ),
        key_id="K2",
        private_key=k2,
        key_continuity=forged_continuity,
    )
    cryptographic_binding = _chain_vector(
        "reject-forged-continuity-tenant-binding",
        [foreign_first, forged_second],
        ("K1", "K2"),
        {
            "accepted": False,
            "error_code": "continuity.signature_invalid",
            "break_sequence": 2,
            "valid_through_sequence": 1,
        },
    )

    forged_stream_continuity = deepcopy(continuity)
    forged_stream_continuity["stream_id"] = "stream-2"
    forged_stream_second = sign_record(
        _agent_record(
            2,
            record_index=35,
            stream_id="stream-2",
            prev_digest=canonical_digest(foreign_stream_first),
        ),
        key_id="K2",
        private_key=k2,
        key_continuity=forged_stream_continuity,
    )
    cryptographic_stream_binding = _chain_vector(
        "reject-forged-continuity-stream-binding",
        [foreign_stream_first, forged_stream_second],
        ("K1", "K2"),
        {
            "accepted": False,
            "error_code": "continuity.signature_invalid",
            "break_sequence": 2,
            "valid_through_sequence": 1,
        },
    )

    unknown_continuity = deepcopy(continuity)
    unknown_continuity["junk"] = "not-authenticated"
    unknown_signature = deepcopy(rotation_without_proof.signature)
    unknown_signature["key_continuity"] = unknown_continuity
    unknown_record = rotation_without_proof.model_copy(
        update={"signature": unknown_signature}, deep=True
    )
    continuity_closure = _chain_vector(
        "reject-unknown-continuity-member",
        [first, unknown_record],
        ("K1", "K2"),
        {
            "accepted": False,
            "error_code": "continuity.unknown_member",
            "break_sequence": 2,
        },
    )

    continuity_without_stream = deepcopy(continuity)
    continuity_without_stream.pop("stream_id")
    missing_signature = deepcopy(rotation_without_proof.signature)
    missing_signature["key_continuity"] = continuity_without_stream
    missing_record = rotation_without_proof.model_copy(
        update={"signature": missing_signature}, deep=True
    )
    continuity_missing_member = _chain_vector(
        "reject-missing-continuity-member",
        [first, missing_record],
        ("K1", "K2"),
        {
            "accepted": False,
            "error_code": "continuity.missing_member",
            "break_sequence": 2,
        },
    )

    new_stream_anchor = sign_record(
        _agent_record(1, record_index=40, stream_id="stream-after-rotation"),
        key_id="K2",
        private_key=k2,
    )
    trusted_anchor = _chain_vector(
        "new-stream-starts-from-trusted-keyring-anchor",
        [new_stream_anchor],
        ("K2",),
        {
            "accepted": True,
            "start_sequence": 1,
            "end_sequence": 1,
            "last_key_id": "K2",
            "last_digest": canonical_digest(new_stream_anchor),
        },
    )

    first_continuity = create_key_continuity(
        predecessor_key_id="K1",
        predecessor_private_key=k1,
        new_key_id="K2",
        new_public_key=k2.public_key(),
        tenant_id="tenant-1",
        stream_id="stream-after-rotation",
    )
    forbidden_anchor = sign_record(
        _agent_record(1, record_index=41, stream_id="stream-after-rotation"),
        key_id="K2",
        private_key=k2,
        key_continuity=first_continuity,
    )
    first_record_proof = _chain_vector(
        "reject-continuity-on-first-stream-record",
        [forbidden_anchor],
        ("K1", "K2"),
        {
            "accepted": False,
            "error_code": "continuity.first_record_forbidden",
            "break_sequence": 1,
        },
    )

    same_key_first = sign_record(
        _agent_record(1, record_index=50), key_id="K2", private_key=k2
    )
    same_key_second = sign_record(
        _agent_record(
            2,
            record_index=51,
            prev_digest=canonical_digest(same_key_first),
        ),
        key_id="K2",
        private_key=k2,
        key_continuity=continuity,
    )
    proof_without_rotation = _chain_vector(
        "reject-continuity-without-key-change",
        [same_key_first, same_key_second],
        ("K1", "K2"),
        {
            "accepted": False,
            "error_code": "continuity.no_key_change",
            "break_sequence": 2,
            "valid_through_sequence": 1,
        },
    )

    fork_a = sign_record(
        _agent_record(1, record_index=60), key_id="K1", private_key=k1
    )
    fork_b = sign_record(
        _agent_record(1, record_index=61), key_id="K1", private_key=k1
    )
    fork = _chain_vector(
        "reject-authenticated-stream-fork",
        [fork_a, fork_b],
        ("K1",),
        {
            "accepted": False,
            "error_code": "chain.fork",
            "break_sequence": 1,
            "attestation_permitted": False,
        },
    )

    third = sign_record(
        _agent_record(3, record_index=70, prev_digest=canonical_digest(first)),
        key_id="K1",
        private_key=k1,
    )
    gap = _chain_vector(
        "reject-sequence-gap",
        [first, third],
        ("K1",),
        {
            "accepted": False,
            "error_code": "chain.sequence_gap",
            "break_sequence": 3,
            "valid_through_sequence": 1,
        },
    )

    return [
        valid_chain,
        resigned,
        wrong_digest_source,
        valid_rotation,
        missing_continuity,
        context_replay,
        stream_replay,
        cryptographic_binding,
        cryptographic_stream_binding,
        continuity_closure,
        continuity_missing_member,
        trusted_anchor,
        first_record_proof,
        proof_without_rotation,
        fork,
        gap,
    ]


def vector_document() -> dict[str, Any]:
    vectors = [
        *_canonicalization_vectors(),
        *_signature_vectors(),
        *_chain_vectors(),
    ]
    return {
        "format": "evidence-control-plane-conformance-vectors",
        "format_version": "1.0.0",
        "spec_version": "0.1",
        "encoding": {
            "json": "UTF-8",
            "binary": "base64url-unpadded",
            "digest": "sha256:<lowercase-hex>",
        },
        "vectors": vectors,
    }


def render_vectors() -> bytes:
    return (
        json.dumps(
            vector_document(),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if the stored normative corpus differs from deterministic output",
    )
    args = parser.parse_args()
    rendered = render_vectors()
    if args.check:
        if not VECTOR_PATH.exists() or VECTOR_PATH.read_bytes() != rendered:
            parser.error("vectors-v0.1.json is stale; regenerate and review its byte diff")
        return 0
    VECTOR_PATH.write_bytes(rendered)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
