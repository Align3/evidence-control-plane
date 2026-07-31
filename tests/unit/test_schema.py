"""Envelope and typed-body validation tests for EV-02."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest
from pydantic import ValidationError

from sdk_python.evidence.schema import (
    AgentIdentityRecord,
    EnvelopeValidationError,
    parse_record,
    validate_record,
)


def agent_identity_record() -> dict[str, Any]:
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


def test_unknown_envelope_field_is_refused_before_body_validation() -> None:
    raw = agent_identity_record()
    raw["future"] = "unsafe"
    raw["body"] = {}

    with pytest.raises(EnvelopeValidationError, match="unknown envelope field: future"):
        validate_record(raw)


def test_unknown_body_fields_are_preserved_recursively() -> None:
    raw = agent_identity_record()
    raw["body"]["future"] = {"nested": [True, None, "value"]}

    record = validate_record(raw)

    assert isinstance(record, AgentIdentityRecord)
    assert record.body.model_extra == {"future": {"nested": [True, None, "value"]}}


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("record_id", "01890F47-2F58-7CC0-98C4-DC0C0C07398F"),
        ("record_id", "550e8400-e29b-41d4-a716-446655440000"),
        ("schema_version", "v1"),
        ("sequence", 0),
    ],
)
def test_invalid_envelope_scalar_is_refused(field: str, value: object) -> None:
    raw = agent_identity_record()
    raw[field] = value
    with pytest.raises(ValidationError):
        validate_record(raw)


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-07-31T12:00:00Z",  # no milliseconds
        "2026-07-31T12:00:00.000",  # no offset
        "2026-02-30T12:00:00.000Z",  # not a real date
    ],
)
def test_invalid_body_timestamp_is_refused(timestamp: str) -> None:
    raw = agent_identity_record()
    raw["record_type"] = "ActionProposal"
    raw["body"] = {
        "action_family": "payment",
        "action_id": "action-1",
        "tool": "payments-api",
        "parameters_digest": "sha256:" + "0" * 64,
        "purpose": "invoice",
        "target_ref": "invoice-1",
        "risk_class": "high",
        "proposed_at": timestamp,
    }
    with pytest.raises(ValidationError):
        validate_record(raw)


def test_float_in_unknown_body_extension_is_refused() -> None:
    raw = agent_identity_record()
    raw["body"]["future"] = {"quantity": 1.5}
    with pytest.raises(ValidationError, match="IEEE-754 floats"):
        validate_record(raw)


def test_duplicate_json_member_is_refused() -> None:
    raw = b'{"record_type":"AgentIdentity","record_type":"ActionProposal"}'
    with pytest.raises(EnvelopeValidationError, match="duplicate JSON field: record_type"):
        parse_record(raw)


def test_input_is_not_mutated_during_validation() -> None:
    raw = agent_identity_record()
    before = deepcopy(raw)
    validate_record(raw)
    assert raw == before
