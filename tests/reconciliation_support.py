"""Small typed record builders shared by EV-15 acceptance and unit tests."""

from __future__ import annotations

from collections.abc import Sequence

from sdk_python.evidence.schema import (
    ActionProposalRecord,
    ExecutionReceiptRecord,
    ExternalConfirmationRecord,
    PopulationRecord,
)

_TIMESTAMP = "2026-08-11T12:00:00.000Z"
_DIGEST_A = "sha256:" + "a" * 64
_DIGEST_B = "sha256:" + "b" * 64


def _envelope(record_type: str, body: dict[str, object], *, serial: int) -> dict[str, object]:
    return {
        "record_id": f"01890f47-2f58-7cc0-98c4-{serial:012x}",
        "record_type": record_type,
        "schema_version": "0.1.0",
        "tenant_id": "acme",
        "boundary_ref": "acme:boundary:1",
        "stream_id": f"acme:{record_type}:1",
        "sequence": serial,
        "prev_digest": None,
        "source": {"implementation": "ev-15-test"},
        "clocks": {"source_time": _TIMESTAMP},
        "body": body,
        "signature": {},
    }


def population(
    identifiers: Sequence[str] | None,
    *,
    count: int | None = None,
    serial: int = 1,
    action_family: str = "refund.issue",
    destination_system: str = "payments",
    result_cap_hit: bool = False,
    pagination_complete: bool = True,
) -> PopulationRecord:
    body: dict[str, object] = {
        "action_family": action_family,
        "destination_system": destination_system,
        "window_start": "2026-08-11T11:00:00.000Z",
        "window_end": "2026-08-11T12:00:00.000Z",
        "enumeration_query": {},
        "count": len(identifiers) if count is None and identifiers is not None else count,
        "pagination_complete": pagination_complete,
        "result_cap_hit": result_cap_hit,
        "retrieved_at": _TIMESTAMP,
        "authoritative_timestamps": {"min": None, "max": None},
    }
    if identifiers is None:
        body["identifier_digest"] = _DIGEST_A
    else:
        body["record_identifiers"] = list(identifiers)
    return PopulationRecord.model_validate(_envelope("PopulationRecord", body, serial=serial))


def proposal(
    action_id: str,
    *,
    family: str = "refund.issue",
    serial: int = 10,
) -> ActionProposalRecord:
    body = {
        "action_family": family,
        "action_id": action_id,
        "tool": "payments.refund",
        "parameters_digest": _DIGEST_A,
        "purpose": "customer refund",
        "target_ref": "account:1",
        "risk_class": "medium",
        "proposed_at": _TIMESTAMP,
    }
    return ActionProposalRecord.model_validate(
        _envelope("ActionProposal", body, serial=serial)
    )


def receipt(
    action_id: str,
    destination_record_id: str,
    *,
    serial: int = 20,
) -> ExecutionReceiptRecord:
    body = {
        "action_id": action_id,
        "dispatch_attempt": 1,
        "connector_identity": "payments-connector",
        "connector_version": "0.1.0",
        "destination_response_digest": _DIGEST_A,
        "destination_record_ref": destination_record_id,
        "status": "accepted",
        "dispatched_at": _TIMESTAMP,
        "responded_at": _TIMESTAMP,
    }
    return ExecutionReceiptRecord.model_validate(
        _envelope("ExecutionReceipt", body, serial=serial)
    )


def confirmation(
    action_id: str,
    destination_record_id: str,
    *,
    digest: str = _DIGEST_B,
    destination_system: str = "payments",
    serial: int = 30,
) -> ExternalConfirmationRecord:
    body = {
        "action_id": action_id,
        "destination_system": destination_system,
        "destination_record_id": destination_record_id,
        "destination_record_digest": digest,
        "authoritative_timestamp": _TIMESTAMP,
        "reconciliation_status": "matched",
        "retrieved_at": _TIMESTAMP,
    }
    return ExternalConfirmationRecord.model_validate(
        _envelope("ExternalConfirmation", body, serial=serial)
    )


def digest(character: str) -> str:
    return "sha256:" + character * 64
