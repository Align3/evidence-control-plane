"""Acceptance steps for EV-03 signing and chain integrity."""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pytest_bdd import given, scenario, then, when

from sdk_python.evidence.canonical import canonical_digest
from sdk_python.evidence.chain import (
    ChainVerificationError,
    DigestLinkError,
    KeyContinuityError,
    StreamForkError,
    create_key_continuity,
    verify_stream,
)
from sdk_python.evidence.schema import validate_record
from sdk_python.evidence.signing import SignatureError, sign_record, verify_record_signature


@scenario("evidence.feature", "ES-S-001 Fork detection")
def test_es_s_001_fork_detection() -> None:
    """Two identities at one stream position make the whole stream unsafe."""


@scenario("evidence.feature", "ES-S-005 Rotation without continuity breaks the chain")
def test_es_s_005_rotation_without_continuity_breaks_the_chain() -> None:
    """An unexplained signing-key change terminates the verifiable prefix."""


@scenario("evidence.feature", "ES-S-010 Previous authentication is chain-linked")
def test_es_s_010_previous_authentication_is_chain_linked() -> None:
    """A later link commits the complete signed predecessor record."""


@scenario("evidence.feature", "ES-S-011 Unknown signature member rejected")
def test_es_s_011_unknown_signature_member_rejected() -> None:
    """The closed signature object refuses unauthenticated extensions."""


@scenario(
    "evidence.feature", "ES-S-012 Continuity proof is bound to its tenant and stream"
)
def test_es_s_012_continuity_proof_is_context_bound() -> None:
    """A valid continuity proof cannot be replayed into another tenant."""


def _record(
    *,
    record_id: str,
    sequence: int,
    prev_digest: str | None = None,
    tenant_id: str = "tenant-1",
    stream_id: str = "collector-1",
) -> Any:
    return validate_record(
        {
            "record_id": record_id,
            "record_type": "AgentIdentity",
            "schema_version": "1.0.0",
            "tenant_id": tenant_id,
            "boundary_ref": "boundary-1",
            "stream_id": stream_id,
            "sequence": sequence,
            "prev_digest": prev_digest,
            "source": {"collector": "sdk-python", "version": "0.1.0"},
            "clocks": {
                "source_time": "2026-07-31T12:00:00.000+01:00",
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


@given("two records linked after the first record is signed", target_fixture="context")
def linked_signed_records() -> dict[str, Any]:
    key = Ed25519PrivateKey.generate()
    first = sign_record(
        _record(record_id="01890f47-2f58-7cc0-98c4-dc0c0c07398f", sequence=1),
        key_id="K1",
        private_key=key,
    )
    second = sign_record(
        _record(
            record_id="01890f47-2f58-7cc0-98c4-dc0c0c073990",
            sequence=2,
            prev_digest=canonical_digest(first),
        ),
        key_id="K1",
        private_key=key,
    )
    return {"key": key, "records": [first, second]}


@when("the first record is replaced by an independently valid re-signature")
def replace_predecessor_signature(context: dict[str, Any]) -> None:
    replacement_key = Ed25519PrivateKey.generate()
    unsigned = context["records"][0].model_copy(update={"signature": {}}, deep=True)
    replacement = sign_record(unsigned, key_id="KX", private_key=replacement_key)
    try:
        verify_stream(
            [replacement, context["records"][1]],
            public_keys={
                "K1": context["key"].public_key(),
                "KX": replacement_key.public_key(),
            },
        )
    except DigestLinkError as exc:
        context["error"] = exc


@then('verification fails with "prev_digest mismatch" at sequence 2')
def replacement_breaks_link(context: dict[str, Any]) -> None:
    assert "prev_digest mismatch" in str(context["error"])
    assert context["error"].break_sequence == 2


@given("a valid signed terminal record", target_fixture="context")
def valid_signed_terminal_record() -> dict[str, Any]:
    key = Ed25519PrivateKey.generate()
    record = sign_record(
        _record(record_id="01890f47-2f58-7cc0-98c4-dc0c0c07398f", sequence=1),
        key_id="K1",
        private_key=key,
    )
    return {"key": key, "record": record}


@when("an unknown member is added to its signature object")
def add_unknown_signature_member(context: dict[str, Any]) -> None:
    signature = dict(context["record"].signature)
    signature["junk"] = "not authenticated"
    changed = context["record"].model_copy(
        update={"signature": signature}, deep=True
    )
    try:
        verify_record_signature(changed, public_keys={"K1": context["key"].public_key()})
    except SignatureError as exc:
        context["error"] = exc


@then('verification fails with "unknown signature member"')
def unknown_signature_member_is_refused(context: dict[str, Any]) -> None:
    assert "unknown signature member" in str(context["error"])


@given(
    "a valid key-continuity assertion bound to tenant A and stream X",
    target_fixture="context",
)
def context_bound_continuity() -> dict[str, Any]:
    predecessor = Ed25519PrivateKey.generate()
    current = Ed25519PrivateKey.generate()
    continuity = create_key_continuity(
        predecessor_key_id="K1",
        predecessor_private_key=predecessor,
        new_key_id="K2",
        new_public_key=current.public_key(),
        tenant_id="tenant-A",
        stream_id="stream-X",
    )
    return {"k1": predecessor, "k2": current, "continuity": continuity}


@when("it is replayed into tenant B on stream X")
def replay_continuity_into_another_tenant(context: dict[str, Any]) -> None:
    first = sign_record(
        _record(
            record_id="01890f47-2f58-7cc0-98c4-dc0c0c07398f",
            sequence=1,
            tenant_id="tenant-B",
            stream_id="stream-X",
        ),
        key_id="K1",
        private_key=context["k1"],
    )
    second = sign_record(
        _record(
            record_id="01890f47-2f58-7cc0-98c4-dc0c0c073990",
            sequence=2,
            prev_digest=canonical_digest(first),
            tenant_id="tenant-B",
            stream_id="stream-X",
        ),
        key_id="K2",
        private_key=context["k2"],
    )
    signature = dict(second.signature)
    signature["key_continuity"] = context["continuity"]
    replayed = second.model_copy(update={"signature": signature}, deep=True)
    try:
        verify_stream(
            [first, replayed],
            public_keys={
                "K1": context["k1"].public_key(),
                "K2": context["k2"].public_key(),
            },
        )
    except ChainVerificationError as exc:
        context["error"] = exc
        context["accepted"] = False


@then('verification fails with "continuity tenant_id does not match"')
def replayed_continuity_is_refused(context: dict[str, Any]) -> None:
    assert "continuity tenant_id does not match" in str(context["error"])


@then("the rotated record is not accepted")
def replayed_record_is_not_accepted(context: dict[str, Any]) -> None:
    assert context["accepted"] is False
