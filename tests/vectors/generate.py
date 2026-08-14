"""Deterministically render the normative ES-029 v0.1 vector corpus."""

from __future__ import annotations

import argparse
import base64
import json
import re
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
from services.verification.bundle import RevocationResponse
from tests.ev41_bundle_support import (
    build_bundle,
    coverage_gap_record,
    revocation_record,
)

VECTOR_PATH = Path(__file__).with_name("vectors-v0.1.json")
TS = "2026-08-01T12:00:00.000+01:00"
SEEDS = {
    "K1": bytes(range(0x00, 0x20)),
    "K2": bytes(range(0x20, 0x40)),
    "KX": bytes(range(0x40, 0x60)),
    "ISSUER1": bytes(range(0x60, 0x80)),
}

REQUIREMENT_DEFINITION = re.compile(
    r"\*\*(?P<rid>(?:AC|AP|AR|CM|DE|DM|DP|ES|IN|QA|RC|SE|TM)-\d{3}[a-z]?)"
    r"(?:\*\*|\s+[—-]\s)"
)
DOCS_ROOT = Path(__file__).parents[2] / "docs"
EXCLUDED_COVERAGE_DOCS = {
    "agent-working-agreement.md",
    "decision-log.md",
    "prd.md",
}
LEGACY_OPERATION_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "canonicalize": ("ES-001", "ES-002", "ES-002a", "ES-003"),
    "sign_record": ("ES-003", "ES-005", "ES-021"),
    "verify_signature": ("ES-021",),
    "verify_attestation_signatures": ("ES-021", "ES-023"),
    "verify_stream": ("ES-006", "ES-006a", "ES-007", "ES-008", "ES-024", "ES-033"),
    "validate_record": ("ES-002", "ES-005", "ES-019"),
    "verify_ingestion_receipt": ("ES-019", "ES-020", "ES-030", "DM-023", "SE-003"),
    "verify_evidence_record_signature": ("ES-021", "ES-033", "SE-003"),
    "verify_record_origin_signature": ("ES-021", "ES-033", "SE-003"),
    "verify_canonical_evidence_record": (
        "DM-023",
        "ES-001",
        "ES-021",
        "ES-023",
        "ES-033",
        "SE-003",
    ),
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


def _registered_keyring(**namespaces: str) -> dict[str, dict[str, str]]:
    return {
        key_id: {"namespace": namespace, "public_key": _public_key(key_id)}
        for key_id, namespace in namespaces.items()
    }


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
    source_time: str = TS,
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
            # ES-019 (EV-27): `ingest_time` and `clock_skew_ms` are hosted
            # observations and MUST NOT appear in a customer-signed record.
            # They live in the issuer-signed ingestion receipt (ES-030).
            "clocks": {"source_time": source_time},
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
            # ES-019 (EV-27): `ingest_time` and `clock_skew_ms` are hosted
            # observations and MUST NOT appear in a customer-signed record.
            # They live in the issuer-signed ingestion receipt (ES-030).
            "clocks": {"source_time": TS},
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


# `len(record_type)` was the original discriminator and collides: PopulationRecord
# and RevocationRecord are both sixteen characters, so they would share a
# record_id at the same sequence. The first two values are the lengths they
# already had, so existing vector bytes are unchanged.
_ISSUER_PRIMARY_OFFSETS: dict[str, int] = {
    "PopulationRecord": 16,
    "ExternalConfirmation": 20,
    "RevocationRecord": 32,
}


def _issuer_primary_record(record_type: str, *, sequence: int = 1) -> RecordEnvelope:
    """Build an unsigned record that ES-033 requires an issuer key to sign.

    Covers both issuer categories: the connector observations and the
    `RevocationRecord` conclusion, which has no customer-authored conclusion to
    preserve and so carries an issuer primary signature rather than the
    `AttestationWindow` counter-signature form.
    """

    bodies: dict[str, dict[str, Any]] = {
        "PopulationRecord": {
            "action_family": "ticket.resolve",
            "destination_system": "destination-1",
            "window_start": "2026-08-01T10:00:00.000Z",
            "window_end": "2026-08-01T11:00:00.000Z",
            "enumeration_query": {"scope": {"actor": "agent-1"}},
            "record_identifiers": ["ticket-1"],
            "count": 1,
            "pagination_complete": True,
            "result_cap_hit": False,
            "retrieved_at": "2026-08-01T11:00:01.000Z",
            "authoritative_timestamps": {
                "min": "2026-08-01T10:30:00.000Z",
                "max": "2026-08-01T10:30:00.000Z",
            },
        },
        "ExternalConfirmation": {
            "action_id": "action-1",
            "destination_system": "destination-1",
            "destination_record_id": "ticket-1",
            "destination_record_digest": "sha256:" + "11" * 32,
            "authoritative_timestamp": "2026-08-01T10:30:00.000Z",
            "reconciliation_status": "matched",
            "retrieved_at": "2026-08-01T11:00:01.000Z",
        },
        "RevocationRecord": {
            "attestation_ref": "attestation-1",
            "reason": "denominator withdrawn by the destination system",
            "issuer": "issuer-1",
            "effective_at": "2026-08-01T11:00:01.000Z",
            "superseding_ref": None,
            "relying_party_notification_status": "pending",
        },
    }
    return validate_record(
        {
            "record_id": _record_id(
                0x200 + sequence + _ISSUER_PRIMARY_OFFSETS[record_type]
            ),
            "record_type": record_type,
            "schema_version": "1.0.0",
            "tenant_id": "tenant-1",
            "boundary_ref": "boundary-1",
            "stream_id": f"issuer:{record_type}",
            "sequence": sequence,
            "prev_digest": None,
            "source": {"service": "hosted-connector", "version": "0.1.0"},
            "clocks": {"source_time": "2026-08-01T11:00:01.000Z"},
            "body": bodies[record_type],
            "signature": {},
        }
    )


def _record_origin_vectors() -> list[dict[str, Any]]:
    vectors: list[dict[str, Any]] = []
    for record_type in ("PopulationRecord", "ExternalConfirmation", "RevocationRecord"):
        unsigned = _issuer_primary_record(record_type)
        for key_id, namespace, accepted in (("ISSUER1", "issuer", True),):
            signed = sign_record(unsigned, key_id=key_id, private_key=_key(key_id))
            vectors.append(
                {
                    "id": (
                        f"accept-{record_type.lower()}-signed-by-issuer-key"
                        if accepted
                        else f"reject-{record_type.lower()}-signed-by-evidence-key"
                    ),
                    "operation": "verify_record_origin_signature",
                    "record": _dump(signed),
                    "verification_keys": _registered_keyring(
                        **{key_id: namespace}
                    ),
                    "expected": {
                        "accepted": accepted,
                        **(
                            {"key_id": key_id, "namespace": namespace}
                            if accepted
                            else {"error_code": "key.namespace_mismatch"}
                        ),
                    },
                }
            )
    population = sign_record(
        _issuer_primary_record("PopulationRecord"),
        key_id="ISSUER1",
        private_key=_key("ISSUER1"),
    )
    vectors.append(
        {
            "id": "issuer-observation-stream-uses-issuer-namespace",
            "operation": "verify_stream",
            "records": [_dump(population)],
            "verification_keys": _registered_keyring(ISSUER1="issuer"),
            "expected": {
                "accepted": True,
                "start_sequence": 1,
                "end_sequence": 1,
                "last_key_id": "ISSUER1",
                "last_digest": canonical_digest(population),
            },
        }
    )
    successor = _issuer_primary_record("PopulationRecord", sequence=2).model_copy(
        update={"prev_digest": canonical_digest(population)}, deep=True
    )
    continuity = create_key_continuity(
        predecessor_key_id="ISSUER1",
        predecessor_private_key=_key("ISSUER1"),
        new_key_id="K2",
        new_public_key=_key("K2").public_key(),
        tenant_id=successor.tenant_id,
        stream_id=successor.stream_id,
    )
    evidence_successor = sign_record(
        successor,
        key_id="K2",
        private_key=_key("K2"),
        key_continuity=continuity,
    )
    vectors.append(
        {
            "id": "reject-issuer-stream-rotation-to-evidence-key",
            "operation": "verify_stream",
            "records": [_dump(population), _dump(evidence_successor)],
            "verification_keys": _registered_keyring(
                ISSUER1="issuer", K2="evidence"
            ),
            "expected": {
                "accepted": False,
                "error_code": "key.namespace_mismatch",
                "break_sequence": 2,
                "valid_through_sequence": 1,
            },
        }
    )
    return vectors


def _record_origin_adversarial_vectors() -> list[dict[str, Any]]:
    vectors: list[dict[str, Any]] = []
    for record_type in ("PopulationRecord", "ExternalConfirmation", "RevocationRecord"):
        signed = sign_record(
            _issuer_primary_record(record_type), key_id="K1", private_key=_key("K1")
        )
        vectors.append(
            {
                "id": f"reject-{record_type.lower()}-signed-by-evidence-key",
                "operation": "verify_canonical_evidence_record",
                "received_wire_utf8_hex": canonicalize(_dump(signed)).hex(),
                "verification_keys": _registered_keyring(K1="evidence"),
                "pre_fix": {
                    "revision": "4fbba6c",
                    "implementations": {
                        "python": {
                            "entry_point": (
                                "services.ingestion.receipts."
                                "verify_canonical_evidence_record"
                            ),
                            "accepted": True,
                            "result": f"accepted {record_type} signed by evidence key K1",
                        },
                        "go": {
                            "entry_point": "evidence.VerifyCanonicalEvidenceRecord",
                            "accepted": True,
                            "result": f"accepted {record_type} signed by evidence key K1",
                        },
                    },
                },
                "expected": {
                    "accepted": False,
                    "error_code": "key.namespace_mismatch",
                },
            }
        )
    return vectors


def _canonicalization_vectors() -> list[dict[str, Any]]:
    valid_inputs = {
        "canonical-object-order": '{"z":0,"a":[3,2,1],"nested":{"b":true,"a":null}}',
        "canonical-prototype-key": '{"__proto__":"x","a":1}',
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
        "verification_keys": _registered_keyring(K1="evidence", ISSUER1="issuer"),
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
        "verification_keys": _registered_keyring(
            **{key_id: "evidence" for key_id in key_ids}
        ),
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



def _receipt_vectors() -> list[dict[str, Any]]:
    """ES-030 / ES-S-013 -- the hosted receipt as a separate signed object.

    The receipt is what carries our clock observation now that ES-019 forbids
    it inside the customer record. Its bytes are published here so an
    independent verifier reproduces the payload shape, the canonicalization,
    and the issuer signature without reading our code.
    """
    from datetime import datetime

    from services.ingestion.receipts import (
        create_ingestion_receipt,
        measure_clock_skew_ms,
    )

    record = sign_record(_agent_record(1), key_id="K1", private_key=_key("K1"))
    # 1500 ms after source_time, so a non-zero measured skew is on the wire and
    # a suppressed one is visibly different (ES-S-013, TM-006).
    ingest_time = datetime.fromisoformat("2026-08-01T12:00:01.500+01:00")
    receipt = create_ingestion_receipt(
        record,
        ingest_time=ingest_time,
        issuer_key_id="ISSUER1",
        issuer_private_key=_key("ISSUER1"),
    )
    payload = json.loads(receipt.canonical_bytes.decode("utf-8"))
    assert payload["clock_skew_ms"] == 1500, payload

    accepted = {
        "id": "receipt-issuer-signed-hosted-clocks",
        "operation": "verify_ingestion_receipt",
        "record": _dump(record),
        "receipt": {
            "canonical_utf8_hex": receipt.canonical_bytes.hex(),
            "key_id": receipt.key_id,
            "signature": _b64(receipt.signature),
        },
        "verification_keys": _registered_keyring(ISSUER1="issuer"),
        "expected": {
            "accepted": True,
            "payload": payload,
            "canonical_json": receipt.canonical_bytes.decode("utf-8"),
            "digest": canonical_digest(payload),
            "record_digest": canonical_digest(record),
            "measured_clock_skew_ms": measure_clock_skew_ms(
                source_time=record.clocks.source_time,
                ingest_time=payload["ingest_time"],
            ),
        },
    }

    # ES-S-013: a collector cannot suppress measured skew. Rewriting the field
    # coherently -- valid JCS, valid shape -- must still fail, because the
    # issuer signature covers it and the customer bytes are untouched.
    suppressed = deepcopy(payload)
    suppressed["clock_skew_ms"] = 0
    suppressed_bytes = canonicalize(suppressed)
    forged_skew = {
        "id": "reject-receipt-suppressed-clock-skew",
        "operation": "verify_ingestion_receipt",
        "record": accepted["record"],
        "receipt": {
            "canonical_utf8_hex": suppressed_bytes.hex(),
            "key_id": receipt.key_id,
            "signature": _b64(receipt.signature),
        },
        "verification_keys": _registered_keyring(ISSUER1="issuer"),
        "expected": {
            "accepted": False,
            "error_code": "receipt.signature_invalid",
            "customer_record_bytes_unchanged": True,
        },
    }

    # A receipt that verifies cryptographically but names a different record
    # must not be accepted as covering this one.
    other = sign_record(
        _agent_record(1, record_index=42, stream_id="stream-2"),
        key_id="K1",
        private_key=_key("K1"),
    )
    foreign = create_ingestion_receipt(
        other,
        ingest_time=ingest_time,
        issuer_key_id="ISSUER1",
        issuer_private_key=_key("ISSUER1"),
    )
    wrong_record = {
        "id": "reject-receipt-bound-to-another-record",
        "operation": "verify_ingestion_receipt",
        "record": accepted["record"],
        "receipt": {
            "canonical_utf8_hex": foreign.canonical_bytes.hex(),
            "key_id": foreign.key_id,
            "signature": _b64(foreign.signature),
        },
        "verification_keys": _registered_keyring(ISSUER1="issuer"),
        "expected": {
            "accepted": False,
            "error_code": "receipt.record_mismatch",
        },
    }

    # The receipt identifies the complete artifact observed on the wire, not
    # merely the signature-excluded bytes the customer signed. Substituting a
    # different valid customer signature over the same payload must break the
    # receipt binding even though `signed_digest` remains unchanged.
    signature_substitution = sign_record(
        _agent_record(1), key_id="K2", private_key=_key("K2")
    )
    assert signing_digest(signature_substitution) == signing_digest(record)
    assert canonical_digest(signature_substitution) != canonical_digest(record)
    wrong_signature = {
        "id": "reject-receipt-after-customer-signature-substitution",
        "operation": "verify_ingestion_receipt",
        "record": _dump(signature_substitution),
        "receipt": accepted["receipt"],
        "verification_keys": _registered_keyring(ISSUER1="issuer"),
        "expected": {
            "accepted": False,
            "error_code": "receipt.record_mismatch",
        },
    }

    # ES-019: the customer record may not carry the hosted fields at all.
    def _hosted_field_refusal(field: str, value: Any) -> dict[str, Any]:
        record_json = deepcopy(accepted["record"])
        record_json["signature"] = {}
        record_json["clocks"][field] = value
        return {
            "id": f"reject-hosted-{field}-in-customer-record",
            "operation": "validate_record",
            "record": record_json,
            "expected": {
                "accepted": False,
                "error_code": "schema.hosted_clock_field_forbidden",
            },
        }

    # DM-008 / SE-003: an evidence-namespace key may never counter-sign a
    # hosted receipt. The key is present and its proof is valid: only the
    # explicit evidence namespace makes this vector fail.
    evidence_signed = create_ingestion_receipt(
        record,
        ingest_time=ingest_time,
        issuer_key_id="K1",
        issuer_private_key=_key("K1"),
    )
    wrong_namespace = {
        "id": "reject-receipt-signed-by-evidence-namespace-key",
        "operation": "verify_ingestion_receipt",
        "record": accepted["record"],
        "receipt": {
            "canonical_utf8_hex": evidence_signed.canonical_bytes.hex(),
            "key_id": evidence_signed.key_id,
            "signature": _b64(evidence_signed.signature),
        },
        "verification_keys": _registered_keyring(K1="evidence"),
        "expected": {
            "accepted": False,
            "error_code": "key.namespace_mismatch",
        },
    }

    # The reverse half of SE-003: an issuer key may not authenticate a
    # customer evidence record even when its signature is cryptographically
    # valid and the key is present in the registry.
    issuer_signed_record = sign_record(
        _agent_record(1), key_id="ISSUER1", private_key=_key("ISSUER1")
    )
    issuer_as_evidence = {
        "id": "reject-record-signed-by-issuer-namespace-key",
        "operation": "verify_evidence_record_signature",
        "record": _dump(issuer_signed_record),
        "verification_keys": _registered_keyring(ISSUER1="issuer"),
        "expected": {
            "accepted": False,
            "error_code": "key.namespace_mismatch",
        },
    }

    # DM-023 / ES-002a: a signature that is valid for the canonical model
    # does not make a differently encoded wire artifact conformant. The
    # canonical control and the non-canonical subject carry identical values
    # and proof; only the received encoding differs.
    canonical_wire = canonicalize(record)
    noncanonical_wire = json.dumps(
        _dump(record), ensure_ascii=False, indent=2
    ).encode("utf-8")
    assert noncanonical_wire != canonical_wire
    noncanonical_record_wire = {
        "id": "reject-non-canonical-customer-record-wire",
        "operation": "verify_canonical_evidence_record",
        "canonical_control_utf8_hex": canonical_wire.hex(),
        "received_wire_utf8_hex": noncanonical_wire.hex(),
        "verification_keys": _registered_keyring(K1="evidence"),
        "expected": {
            "accepted": False,
            "error_code": "wire.non_canonical",
        },
    }

    # ES-030 truncation. `clock_skew_ms` truncates the sub-millisecond
    # remainder *toward zero*, which is not what a floor does: floored, a
    # -0.5 ms skew becomes -1. Python's `//` floors and Go's `/` truncates, so
    # an implementation ported without care diverges on every early-clock
    # record and on nothing else. These pin the boundary in both directions.
    def _skew_vector(
        name: str, ingest: str, expected_skew: int, *, source_time: str = TS
    ) -> dict[str, Any]:
        # `_format_ingest_time` quantises ingest_time to whole milliseconds
        # before the measurement, so a sub-millisecond remainder can only ever
        # come from `source_time`, which the customer supplies.
        subject = sign_record(
            _agent_record(1, source_time=source_time), key_id="K1", private_key=_key("K1")
        )
        signed = create_ingestion_receipt(
            subject,
            ingest_time=datetime.fromisoformat(ingest),
            issuer_key_id="ISSUER1",
            issuer_private_key=_key("ISSUER1"),
        )
        body = json.loads(signed.canonical_bytes.decode("utf-8"))
        assert body["clock_skew_ms"] == expected_skew, (name, body)
        return {
            "id": name,
            "operation": "verify_ingestion_receipt",
            "record": _dump(subject),
            "receipt": {
                "canonical_utf8_hex": signed.canonical_bytes.hex(),
                "key_id": signed.key_id,
                "signature": _b64(signed.signature),
            },
            "verification_keys": _registered_keyring(ISSUER1="issuer"),
            "expected": {
                "accepted": True,
                "payload": body,
                "canonical_json": signed.canonical_bytes.decode("utf-8"),
                "digest": canonical_digest(body),
                "record_digest": canonical_digest(subject),
                "measured_clock_skew_ms": expected_skew,
            },
        }

    return [
        accepted,
        forged_skew,
        wrong_record,
        wrong_signature,
        wrong_namespace,
        issuer_as_evidence,
        noncanonical_record_wire,
        _hosted_field_refusal("ingest_time", TS),
        _hosted_field_refusal("clock_skew_ms", 0),
        # Ingest before source: the collector clock ran fast.
        _skew_vector("receipt-negative-clock-skew", "2026-08-01T11:59:58.500+01:00", -1500),
        # The vector that separates truncation from flooring. Source carries a
        # half-millisecond; ingest lands on the whole millisecond below it, so
        # the exact skew is -0.5 ms. Truncated toward zero that is 0. Floored
        # -- which is what Python's `//` and any naive port would give -- it is
        # -1. Nothing else in the corpus distinguishes the two.
        _skew_vector(
            "receipt-negative-sub-millisecond-skew-truncates-to-zero",
            "2026-08-01T12:00:00.000+01:00",
            0,
            source_time="2026-08-01T12:00:00.0005+01:00",
        ),
        # Same boundary at a magnitude where flooring gives -1001, not -1000.
        _skew_vector(
            "receipt-negative-skew-truncates-toward-zero-not-downward",
            "2026-08-01T11:59:59.000+01:00",
            -1000,
            source_time="2026-08-01T12:00:00.0005+01:00",
        ),
        # Positive control: truncation and flooring agree above zero.
        _skew_vector(
            "receipt-positive-sub-millisecond-skew-truncates-down",
            "2026-08-01T12:00:01.000+01:00",
            999,
            source_time="2026-08-01T12:00:00.0005+01:00",
        ),
    ]


def _stream_shape_vectors() -> list[dict[str, Any]]:
    """Vectors for stream shape, added after EV-05 review.

    These exist because the corpus exercised library functions while the Go
    binary routed around them: a verifier could pass every published vector and
    still accept a stream assembled from two different chains, or one that
    simply begins partway through. A third party reading "51/51" would inherit
    exactly those holes, so the shape rules get vectors of their own.
    """
    k1 = _key("K1")
    first = sign_record(_agent_record(1), key_id="K1", private_key=k1)

    # ES-006: a stream is the records sharing one stream_id. Verifying a mixture
    # computes links across chains that were never one chain.
    foreign = sign_record(
        _agent_record(2, record_index=0x70, stream_id="stream-2",
                      prev_digest=canonical_digest(first)),
        key_id="K1",
        private_key=k1,
    )
    mixed = _chain_vector(
        "reject-mixed-stream-ids",
        [first, foreign],
        ("K1",),
        {"accepted": False, "error_code": "chain.stream_id_mismatch"},
    )

    # ES-003: sequence starts at 1. A stream handed to a verifier beginning at 5
    # leaves four records unaccounted for, and reporting it as verified is the
    # silent omission the methodology exists to prevent.
    unanchored = sign_record(
        _agent_record(5, record_index=0x71), key_id="K1", private_key=k1
    )
    not_anchored = _chain_vector(
        "reject-stream-not-anchored-at-sequence-one",
        [unanchored],
        ("K1",),
        {"accepted": False, "error_code": "chain.sequence_gap", "break_sequence": 5},
    )
    return [mixed, not_anchored]


def _adversarial_vectors() -> list[dict[str, Any]]:
    """Refusal probes for composition paths that primitives alone do not cover."""

    # SE-003: the signature is valid and the key is registered; only its
    # issuer custody role makes it ineligible to authenticate evidence. No
    # namespace-free public_keys control is published, because there is no
    # longer a namespace-free stream entry point in either implementation to
    # run it against.
    issuer_signed = sign_record(
        _agent_record(1), key_id="ISSUER1", private_key=_key("ISSUER1")
    )
    issuer_stream = {
        "id": "adversarial-reject-issuer-key-on-evidence-stream",
        "operation": "verify_stream",
        "records": [_dump(issuer_signed)],
        "verification_keys": _registered_keyring(ISSUER1="issuer"),
        "pre_fix": {
            "revision": "9e5904b",
            "implementations": {
                "python": {
                    "entry_point": "sdk_python.evidence.chain.verify_stream",
                    "accepted": True,
                    "result": "accepted sequences 1..1, key ISSUER1",
                },
                "go": {
                    "entry_point": "evidence.VerifyEvidenceStream",
                    "accepted": False,
                    "result": (
                        "refused: key \"ISSUER1\" is in the \"issuer\" "
                        "namespace; evidence streams require evidence keys "
                        "(SE-003)"
                    ),
                },
            },
            "harness_observations": {
                "go": {
                    "accepted": True,
                    "result": (
                        "VALID stream sequences 1..1, last key ISSUER1"
                    ),
                    "unstated_input": (
                        "evidenceKeyring() stamped the evidence namespace onto "
                        "every namespace-free key"
                    ),
                }
            },
        },
        "expected": {
            "accepted": False,
            "error_code": "key.namespace_mismatch",
        },
    }

    # ES-023: the customer proof remains valid when signature.issuer is
    # deleted because it signs the signature-excluded record. This therefore
    # probes the complete record entry point's record_type dispatch, not the
    # already-correct issuer-signature primitive.
    customer_signed = sign_record(
        _attestation_record(), key_id="K1", private_key=_key("K1")
    )
    complete = counter_sign_attestation(
        customer_signed,
        issuer_key_id="ISSUER1",
        issuer_private_key=_key("ISSUER1"),
    )
    stripped = _dump(complete)
    stripped["signature"].pop("issuer")
    missing_counter_signature = {
        "id": "adversarial-reject-attestation-without-issuer-signature",
        "operation": "verify_canonical_evidence_record",
        "canonical_control_utf8_hex": canonicalize(complete).hex(),
        "received_wire_utf8_hex": canonicalize(stripped).hex(),
        "verification_keys": _registered_keyring(
            K1="evidence", ISSUER1="issuer"
        ),
        "pre_fix": {
            "revision": "9e5904b",
            "implementations": {
                "python": {
                    "entry_point": (
                        "services.ingestion.receipts."
                        "verify_canonical_evidence_record"
                    ),
                    "accepted": True,
                    "result": (
                        "accepted AttestationWindow with signature.issuer absent"
                    ),
                },
                "go": {
                    "entry_point": "evidence.VerifyCanonicalEvidenceRecord",
                    "accepted": False,
                    "result": (
                        "refused: attestation is missing the issuer "
                        "counter-signature (ES-023)"
                    ),
                },
            },
        },
        "expected": {
            "accepted": False,
            "error_code": "signature.missing_issuer_member",
        },
    }
    return [issuer_stream, missing_counter_signature]


def _bundle_expected(
    *,
    accepted: bool = True,
    verdict: str = "unchecked_revocation",
    revocation_status: str = "unchecked",
    coverage_ratio: str | None = "0.3333",
    unchecked: list[str] | None = None,
    error_code: str | None = None,
    pending_effective_at: str | None = None,
    superseding_ref: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "accepted": accepted,
        "verdict": verdict,
        "evaluated_at": "2026-10-01T00:00:00.000Z",
        "revocation_status": revocation_status,
        "coverage_ratio": coverage_ratio,
        "unchecked": unchecked or [],
    }
    if accepted or error_code != "bundle.container_invalid":
        result["attestation_id"] = _record_id(404)
    if error_code is not None:
        result["error_codes"] = [error_code]
        if error_code.startswith("bundle.") or error_code == "schema.version_unsupported":
            result.pop("attestation_id", None)
    if pending_effective_at is not None:
        result["pending_revocation_effective_at"] = pending_effective_at
    if superseding_ref is not None:
        result["superseding_ref"] = superseding_ref
    return result


def _bundle_vector(
    vector_id: str,
    fixture: Any,
    *,
    requirements: tuple[str, ...],
    expected: dict[str, Any],
    revocation_response: RevocationResponse | None = None,
) -> dict[str, Any]:
    vector: dict[str, Any] = {
        "id": vector_id,
        "operation": "verify_bundle",
        "requirements": list(requirements),
        "bundle_utf8_hex": fixture.wire.hex(),
        "verification_keys": _registered_keyring(K1="evidence", ISSUER1="issuer"),
        "evaluated_at": "2026-10-01T00:00:00.000Z",
        "expected": expected,
    }
    if revocation_response is not None:
        vector["revocation_response"] = {
            "status_code": revocation_response.status_code,
            "body_utf8_hex": (
                revocation_response.body.hex()
                if revocation_response.body is not None
                else None
            ),
        }
    return vector


def _bundle_vectors() -> list[dict[str, Any]]:
    gap = coverage_gap_record()
    gap_body = gap.body.model_dump(mode="json", exclude_unset=True)
    return [
        _bundle_vector(
            "bundle-valid-offline",
            build_bundle(),
            requirements=("ES-034", "CM-013", "TM-014"),
            expected=_bundle_expected(),
        ),
        _bundle_vector(
            "coverage-ratio-excludes-out-of-scope-fixed-scale",
            build_bundle(population_count=4, matched=1, out_of_scope=1, ratio="0.3333"),
            requirements=("ES-017", "CM-011"),
            expected=_bundle_expected(),
        ),
        _bundle_vector(
            "coverage-ratio-truncates-two-thirds",
            build_bundle(population_count=3, matched=2, out_of_scope=0, ratio="0.6666"),
            requirements=("ES-017", "CM-011"),
            expected=_bundle_expected(coverage_ratio="0.6666"),
        ),
        _bundle_vector(
            "coverage-ratio-null-on-result-cap",
            build_bundle(result_cap_hit=True, ratio=None),
            requirements=("ES-011",),
            expected=_bundle_expected(coverage_ratio=None),
        ),
        _bundle_vector(
            "coverage-ratio-null-on-incomplete-pagination",
            build_bundle(pagination_complete=False, ratio=None),
            requirements=("ES-012",),
            expected=_bundle_expected(coverage_ratio=None),
        ),
        _bundle_vector(
            "coverage-class-caps-level-and-withholds-ratio",
            build_bundle(
                denominator_class="C4",
                coverage_level="observed",
                ratio=None,
                capped_by_class=True,
            ),
            requirements=("CM-008", "CM-009"),
            expected=_bundle_expected(
                coverage_ratio=None,
                unchecked=[
                    "coverage.capped_by_class",
                    "coverage.count_conservation",
                ],
            ),
        ),
        _bundle_vector(
            "coverage-gap-is-an-explicit-interval",
            build_bundle(gap_record=gap, announced_gaps=[gap_body]),
            requirements=("CM-014",),
            expected=_bundle_expected(),
        ),
        _bundle_vector(
            "reject-assertion-outside-catalogue",
            build_bundle(assertions=[{"assertion_id": "A-11"}]),
            requirements=("AR-003", "ES-036"),
            expected=_bundle_expected(
                accepted=False,
                verdict="invalid",
                coverage_ratio=None,
                error_code="assertion.outside_catalogue",
            ),
        ),
        _bundle_vector(
            "reject-qualification-at-window-boundary",
            build_bundle(qualified_at="2026-08-01T00:00:00.000Z"),
            requirements=("TM-013",),
            expected=_bundle_expected(
                accepted=False,
                verdict="invalid",
                coverage_ratio=None,
                error_code="qualification.postdates_window",
            ),
        ),
        _bundle_vector(
            "attestation-expired-at-evaluation-instant",
            build_bundle(validity_until="2026-09-30T00:00:00.000Z"),
            requirements=("AR-009",),
            expected=_bundle_expected(verdict="expired"),
        ),
        _bundle_vector(
            "reject-unpublished-schema-version",
            build_bundle(schema_version="9.9.9"),
            requirements=("ES-035",),
            expected=_bundle_expected(
                accepted=False,
                verdict="invalid",
                coverage_ratio=None,
                error_code="schema.version_unsupported",
            ),
        ),
        _bundle_vector(
            "reject-unpublished-methodology-version",
            build_bundle(methodology_version="9.9.9"),
            requirements=("CM-025",),
            expected=_bundle_expected(
                accepted=False,
                verdict="invalid",
                coverage_ratio=None,
                error_code="methodology.version_unsupported",
            ),
        ),
        _bundle_vector(
            "revocation-unauthenticated-answer-is-unchecked",
            build_bundle(),
            requirements=("AR-029",),
            revocation_response=RevocationResponse(200, b"<html>captive portal</html>"),
            expected=_bundle_expected(),
        ),
        _bundle_vector(
            "revocation-superseding-reference-is-distinct",
            build_bundle(),
            requirements=("AR-030",),
            revocation_response=RevocationResponse(
                200,
                revocation_record(
                    effective_at="2026-09-01T00:00:00.000Z",
                    superseding_ref="attestation-2",
                ),
            ),
            expected=_bundle_expected(
                verdict="superseded",
                revocation_status="superseded",
                superseding_ref="attestation-2",
            ),
        ),
        _bundle_vector(
            "revocation-pending-by-one-millisecond",
            build_bundle(),
            requirements=("AR-031",),
            revocation_response=RevocationResponse(
                200,
                revocation_record(
                    effective_at="2026-10-01T00:00:00.001Z",
                    superseding_ref=None,
                ),
            ),
            expected=_bundle_expected(
                verdict="valid",
                revocation_status="valid",
                pending_effective_at="2026-10-01T00:00:00.001Z",
            ),
        ),
    ]


def _new_rule_adversarial_vectors() -> list[dict[str, Any]]:
    vector = _bundle_vector(
        "reject-bundle-object-container",
        type("Fixture", (), {"wire": canonicalize({"records": []})})(),
        requirements=("ES-034",),
        expected=_bundle_expected(
            accepted=False,
            verdict="invalid",
            coverage_ratio=None,
            error_code="bundle.container_invalid",
        ),
    )
    vector["new_rule"] = {
        "requirement": "ES-034",
        "introduced_by": "2b4b6a7260de04d4c2cfb13c743d1f12a7396815",
    }
    return [vector]


def _defined_requirements() -> set[str]:
    requirements: set[str] = set()
    for path in sorted(DOCS_ROOT.glob("*.md")):
        if path.name in EXCLUDED_COVERAGE_DOCS:
            continue
        requirements.update(
            match.group("rid")
            for match in REQUIREMENT_DEFINITION.finditer(path.read_text(encoding="utf-8"))
        )
    return requirements


def _requirement_coverage(vectors: list[dict[str, Any]]) -> dict[str, Any]:
    covered: dict[str, list[str]] = {}
    for vector in vectors:
        requirements = vector.get(
            "requirements", LEGACY_OPERATION_REQUIREMENTS.get(vector["operation"], ())
        )
        for requirement in requirements:
            covered.setdefault(requirement, []).append(vector["id"])
    covered = {
        requirement: sorted(vector_ids)
        for requirement, vector_ids in sorted(covered.items())
    }
    absent = sorted(_defined_requirements() - covered.keys())
    return {
        "covered": covered,
        "declared_absent": absent,
        "declared_absent_count": len(absent),
    }


def vector_document() -> dict[str, Any]:
    vectors = [
        *_canonicalization_vectors(),
        *_signature_vectors(),
        *_chain_vectors(),
        *_stream_shape_vectors(),
        *_receipt_vectors(),
        *_record_origin_vectors(),
        *_bundle_vectors(),
    ]
    adversarial_vectors = [
        *_adversarial_vectors(),
        *_record_origin_adversarial_vectors(),
        *_new_rule_adversarial_vectors(),
    ]
    return {
        "format": "evidence-control-plane-conformance-vectors",
        "format_version": "1.3.0",
        "spec_version": "0.1",
        "encoding": {
            "json": "UTF-8",
            "binary": "base64url-unpadded",
            "digest": "sha256:<lowercase-hex>",
        },
        "vectors": vectors,
        "adversarial_vectors": adversarial_vectors,
        "requirement_coverage": _requirement_coverage([*vectors, *adversarial_vectors]),
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
