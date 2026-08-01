"""Acceptance steps for EV-03 signing and chain integrity."""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pytest_bdd import given, scenario, then, when

from sdk_python.evidence.canonical import canonical_digest
from sdk_python.evidence.chain import KeyContinuityError, StreamForkError, verify_stream
from sdk_python.evidence.schema import validate_record
from sdk_python.evidence.signing import sign_record


@scenario("evidence.feature", "ES-S-001 Fork detection")
def test_es_s_001_fork_detection() -> None:
    """Two identities at one stream position make the whole stream unsafe."""


@scenario("evidence.feature", "ES-S-005 Rotation without continuity breaks the chain")
def test_es_s_005_rotation_without_continuity_breaks_the_chain() -> None:
    """An unexplained signing-key change terminates the verifiable prefix."""


def _record(*, record_id: str, sequence: int, prev_digest: str | None = None) -> Any:
    return validate_record(
        {
            "record_id": record_id,
            "record_type": "AgentIdentity",
            "schema_version": "1.0.0",
            "tenant_id": "tenant-1",
            "boundary_ref": "boundary-1",
            "stream_id": "collector-1",
            "sequence": sequence,
            "prev_digest": prev_digest,
            "source": {"collector": "sdk-python", "version": "0.1.0"},
            "clocks": {
                "source_time": "2026-07-31T12:00:00.000+01:00",
                "ingest_time": "2026-07-31T12:00:00.001+01:00",
                "clock_skew_ms": 1,
            },
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


@given("a stream containing a record at sequence 42", target_fixture="context")
def stream_at_sequence_42() -> dict[str, Any]:
    key = Ed25519PrivateKey.generate()
    first = sign_record(
        _record(record_id="01890f47-2f58-7cc0-98c4-dc0c0c07398f", sequence=42),
        key_id="K1",
        private_key=key,
    )
    return {"key": key, "records": [first]}


@when("a second record with the same stream_id and sequence 42 is submitted")
def submit_fork(context: dict[str, Any]) -> None:
    second = sign_record(
        _record(record_id="01890f47-2f58-7cc0-98c4-dc0c0c073990", sequence=42),
        key_id="K1",
        private_key=context["key"],
    )
    try:
        verify_stream(
            [*context["records"], second],
            public_keys={"K1": context["key"].public_key()},
        )
    except StreamForkError as exc:
        context["error"] = exc


@then('verification fails with "stream fork"')
def fork_is_reported(context: dict[str, Any]) -> None:
    assert "stream fork" in str(context["error"])


@then("no attestation may be issued covering that stream")
def fork_prevents_attestation(context: dict[str, Any]) -> None:
    assert context["error"].attestation_permitted is False


@given("records signed with key K1", target_fixture="context")
def records_signed_with_k1() -> dict[str, Any]:
    k1 = Ed25519PrivateKey.generate()
    first = sign_record(
        _record(record_id="01890f47-2f58-7cc0-98c4-dc0c0c07398f", sequence=1),
        key_id="K1",
        private_key=k1,
    )
    return {"k1": k1, "records": [first]}


@when("subsequent records are signed with K2 and no KeyContinuity assertion exists")
def rotate_without_continuity(context: dict[str, Any]) -> None:
    k2 = Ed25519PrivateKey.generate()
    previous = context["records"][-1]
    second = sign_record(
        _record(
            record_id="01890f47-2f58-7cc0-98c4-dc0c0c073990",
            sequence=2,
            prev_digest=canonical_digest(previous),
        ),
        key_id="K2",
        private_key=k2,
    )
    try:
        verify_stream(
            [previous, second],
            public_keys={"K1": context["k1"].public_key(), "K2": k2.public_key()},
        )
    except KeyContinuityError as exc:
        context["error"] = exc


@then("verification reports a chain break at the rotation point")
def rotation_break_is_reported(context: dict[str, Any]) -> None:
    assert "key rotation without continuity" in str(context["error"])
    assert context["error"].break_sequence == 2


@then("the attestation window terminates there")
def attestation_stops_before_rotation(context: dict[str, Any]) -> None:
    assert context["error"].valid_through_sequence == 1
