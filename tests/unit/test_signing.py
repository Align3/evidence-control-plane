"""Focused refusal and integrity tests for EV-03 signatures."""

from __future__ import annotations

from copy import deepcopy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sdk_python.evidence.schema import AttestationWindowRecord, validate_record
from sdk_python.evidence.signing import (
    InvalidSignatureError,
    SignatureError,
    UnsupportedAlgorithmError,
    counter_sign_attestation,
    sign_record,
    signing_digest,
    verify_attestation_counter_signature,
    verify_attestation_signatures,
    verify_record_signature,
)

TS = "2026-07-31T12:00:00.000+01:00"


def _agent_record():
    return validate_record(
        {
            "record_id": "01890f47-2f58-7cc0-98c4-dc0c0c07398f",
            "record_type": "AgentIdentity",
            "schema_version": "1.0.0",
            "tenant_id": "tenant-1",
            "boundary_ref": "boundary-1",
            "stream_id": "collector-1",
            "sequence": 1,
            "prev_digest": None,
            "source": {"collector": "sdk-python"},
            "clocks": {"source_time": TS, "ingest_time": TS, "clock_skew_ms": 0},
            "body": {
                "agent_id": "agent-1",
                "deployment": "prod",
                "runtime": "python-3.12",
                "tenant_scope": "tenant-1",
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
            "record_id": "01890f47-2f58-7cc0-98c4-dc0c0c07398f",
            "record_type": "AttestationWindow",
            "schema_version": "1.0.0",
            "tenant_id": "tenant-1",
            "boundary_ref": "boundary-1",
            "stream_id": "collector-1",
            "sequence": 1,
            "prev_digest": None,
            "source": {"collector": "sdk-python"},
            "clocks": {"source_time": TS, "ingest_time": TS, "clock_skew_ms": 0},
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
    assert isinstance(record, AttestationWindowRecord)
    return record


def test_record_signature_round_trip_and_shape() -> None:
    private_key = Ed25519PrivateKey.generate()
    record = _agent_record()

    signed = sign_record(record, key_id="customer-key", private_key=private_key)

    assert set(signed.signature) == {"alg", "key_id", "sig", "signed_digest"}
    assert signed.signature["alg"] == "ed25519"
    assert "=" not in str(signed.signature["sig"])
    assert signed.signature["signed_digest"] == signing_digest(record)
    assert verify_record_signature(
        signed, public_keys={"customer-key": private_key.public_key()}
    ) == "customer-key"


def test_signing_refuses_to_overwrite_existing_customer_proof() -> None:
    private_key = Ed25519PrivateKey.generate()
    signed = sign_record(_agent_record(), key_id="customer-key", private_key=private_key)

    with pytest.raises(SignatureError, match="refusing to overwrite"):
        sign_record(signed, key_id="replacement", private_key=Ed25519PrivateKey.generate())


def test_unknown_body_extension_is_digest_covered_by_signature() -> None:
    private_key = Ed25519PrivateKey.generate()
    raw = _agent_record().model_dump(mode="json", exclude_unset=True)
    raw["body"]["future_extension"] = {"included": True}
    signed = sign_record(
        validate_record(raw), key_id="customer-key", private_key=private_key
    )
    tampered = signed.model_copy(deep=True)
    tampered.body.__pydantic_extra__["future_extension"] = {"included": False}

    with pytest.raises(InvalidSignatureError, match="signed_digest"):
        verify_record_signature(
            tampered, public_keys={"customer-key": private_key.public_key()}
        )


def test_verifier_refuses_algorithm_negotiation() -> None:
    private_key = Ed25519PrivateKey.generate()
    signed = sign_record(_agent_record(), key_id="customer-key", private_key=private_key)
    bad_signature = deepcopy(signed.signature)
    bad_signature["alg"] = "ed448"
    tampered = signed.model_copy(update={"signature": bad_signature}, deep=True)

    with pytest.raises(UnsupportedAlgorithmError, match="ed25519"):
        verify_record_signature(
            tampered, public_keys={"customer-key": private_key.public_key()}
        )


def test_verifier_refuses_standard_base64_alphabet() -> None:
    private_key = Ed25519PrivateKey.generate()
    signed = sign_record(_agent_record(), key_id="customer-key", private_key=private_key)
    bad_signature = deepcopy(signed.signature)
    bad_signature["sig"] = "+" + str(bad_signature["sig"])[1:]
    tampered = signed.model_copy(update={"signature": bad_signature}, deep=True)

    with pytest.raises(SignatureError, match="unpadded base64url"):
        verify_record_signature(
            tampered, public_keys={"customer-key": private_key.public_key()}
        )


def test_attestation_counter_signature_commits_customer_signature() -> None:
    customer = Ed25519PrivateKey.generate()
    issuer = Ed25519PrivateKey.generate()
    signed = sign_record(_attestation_record(), key_id="customer-key", private_key=customer)
    counter_signed = counter_sign_attestation(
        signed, issuer_key_id="issuer-key", issuer_private_key=issuer
    )

    assert verify_record_signature(
        counter_signed, public_keys={"customer-key": customer.public_key()}
    ) == "customer-key"
    assert verify_attestation_counter_signature(
        counter_signed, issuer_public_keys={"issuer-key": issuer.public_key()}
    ) == "issuer-key"
    assert verify_attestation_signatures(
        counter_signed,
        evidence_public_keys={"customer-key": customer.public_key()},
        issuer_public_keys={"issuer-key": issuer.public_key()},
    ) == ("customer-key", "issuer-key")

    changed = deepcopy(counter_signed.signature)
    changed["sig"] = "A" * 86
    tampered = counter_signed.model_copy(update={"signature": changed}, deep=True)
    with pytest.raises(InvalidSignatureError, match="counter-signature"):
        verify_attestation_counter_signature(
            tampered, issuer_public_keys={"issuer-key": issuer.public_key()}
        )


def test_two_signature_verifier_refuses_customer_only_attestation() -> None:
    customer = Ed25519PrivateKey.generate()
    customer_only = sign_record(
        _attestation_record(), key_id="customer-key", private_key=customer
    )

    with pytest.raises(InvalidSignatureError, match="no issuer counter-signature"):
        verify_attestation_signatures(
            customer_only,
            evidence_public_keys={"customer-key": customer.public_key()},
            issuer_public_keys={},
        )
