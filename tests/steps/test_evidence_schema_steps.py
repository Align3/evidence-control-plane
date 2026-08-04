"""Acceptance steps for EV-02 envelope validation (ES-S-008/009)."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from pytest_bdd import given, scenario, then, when


@scenario("evidence.feature", "ES-S-008 Unknown envelope field rejected")
def test_es_s_008_unknown_envelope_field_rejected() -> None:
    """An extension at the trust-boundary envelope must be refused."""


@scenario("evidence.feature", "ES-S-009 Unknown body field preserved")
def test_es_s_009_unknown_body_field_preserved() -> None:
    """Payload extensions remain verifiable and digest-covered."""


def _valid_record() -> dict[str, Any]:
    return {
        "record_id": "01890f47-2f58-7cc0-98c4-dc0c0c07398f",
        "record_type": "AgentIdentity",
        "schema_version": "1.0.0",
        "tenant_id": "tenant-1",
        "boundary_ref": "boundary-1",
        "stream_id": "collector-1",
        "sequence": 1,
        "prev_digest": None,
        "source": {"collector": "sdk-python", "version": "0.1.0"},
        "clocks": {
            "source_time": "2026-07-31T12:00:00.000+01:00",
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


@given("a record carrying an unrecognised field in its envelope", target_fixture="context")
def record_with_unknown_envelope_field() -> dict[str, Any]:
    record = _valid_record()
    record["future_envelope_field"] = "must be rejected"
    return {"record": record}


@given("a record carrying an unrecognised field inside body", target_fixture="context")
def record_with_unknown_body_field() -> dict[str, Any]:
    record = _valid_record()
    without_extension = deepcopy(record)
    record["body"]["future_body_field"] = {"retained": True}
    return {"record": record, "without_extension": without_extension}


@when("the verifier validates it")
def validate_with_python_verifier(context: dict[str, Any]) -> None:
    from sdk_python.evidence.canonical import canonical_digest
    from sdk_python.evidence.schema import validate_record

    try:
        context["validated"] = validate_record(context["record"])
    except ValueError as exc:
        context["error"] = str(exc)
    else:
        context["digest"] = canonical_digest(context["validated"])
        if "without_extension" in context:
            baseline = validate_record(context["without_extension"])
            context["baseline_digest"] = canonical_digest(baseline)


@then('verification fails with "unknown envelope field"')
def unknown_envelope_field_is_reported(context: dict[str, Any]) -> None:
    assert "unknown envelope field" in context["error"]


@then("verification succeeds")
def verification_succeeds(context: dict[str, Any]) -> None:
    assert "error" not in context
    assert context["validated"] is not None


@then("the unknown field is included in the digest computation")
def unknown_body_field_changes_digest(context: dict[str, Any]) -> None:
    # QA-003: assert through the verifier's canonical output and digest, not
    # through the model's internal extras.
    from sdk_python.evidence.canonical import canonicalize

    assert b'"future_body_field":{"retained":true}' in canonicalize(context["validated"])
    assert context["digest"] != context["baseline_digest"]
