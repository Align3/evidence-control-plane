"""The fixture generator's evidence-selection rules (EV-42).

These are offline and deterministic: no Salesforce, no ledger, no keys beyond a
fixed local seed. They exist because the two defects they cover are both silent
-- each produces a well-formed fixture set that states something the evidence
does not support, which is precisely the failure this product exists to make
impossible.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sdk_python.evidence.canonical import canonicalize
from sdk_python.evidence.schema import (
    ActionProposalRecord,
    ExecutionReceiptRecord,
    ExternalConfirmationRecord,
    PopulationRecord,
)
from sdk_python.evidence.signing import sign_record
from services.computation.reconciliation import ReconciliationStatus, reconcile
from tools.generate_salesforce_live_fixtures import (
    TENANT_ID,
    LedgerEvidence,
    _envelope,
    _timestamp,
    _uuid7,
    select_confirmation_targets,
)

KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
KEY_ID = "test-evidence-1"
NOW = datetime(2026, 8, 18, 8, 55, tzinfo=UTC)
CASE_A = "500ak000036cT2QAAU"
CASE_B = "500ak000036cT2RAAU"
ACTION_FAMILY = "record.create"
DESTINATION = "salesforce"

# The identity an EV-08 action carries: minted when the action was *proposed*,
# which is before the destination record exists and therefore cannot be
# derived from its id.
LEDGER_ACTION_ID = "ev08-action-before-case-exists"


def _held(*records: Any) -> tuple[LedgerEvidence, ...]:
    """Wrap records as the ledger hands them back.

    The selector reads what the ledger holds, not bare models, so the tests
    exercise the same shape the generator does.
    """
    return tuple(
        LedgerEvidence(
            record=record,
            wire=canonicalize(record),
            receipt_key_id="test-issuer-1",
            receipt_signature=b"\x00" * 64,
            receipt_canonical_bytes=b"{}",
        )
        for record in records
    )


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _sign(model: Any, record: Any) -> Any:
    return sign_record(model.model_validate(record), key_id=KEY_ID, private_key=KEY)


def _population(identifiers: list[str]) -> PopulationRecord:
    return _sign(
        PopulationRecord,
        _envelope(
            record_type="PopulationRecord",
            record_id=_uuid7(NOW),
            stream_id=f"{TENANT_ID}:issuer:test:population",
            clocks={"source_time": _timestamp(NOW)},
            source={"implementation": "test", "version": "1.0.0"},
            body={
                "action_family": ACTION_FAMILY,
                "destination_system": DESTINATION,
                "window_start": _timestamp(NOW),
                "window_end": _timestamp(NOW + timedelta(minutes=1)),
                "enumeration_query": {"scope": "test"},
                "count": len(identifiers),
                "record_identifiers": identifiers,
                "pagination_complete": True,
                "result_cap_hit": False,
                "retrieved_at": _timestamp(NOW),
                "authoritative_timestamps": {},
            },
        ),
    )


def _receipt(destination_id: str, action_id: str) -> ExecutionReceiptRecord:
    return _sign(
        ExecutionReceiptRecord,
        _envelope(
            record_type="ExecutionReceipt",
            record_id=_uuid7(NOW),
            stream_id=f"{TENANT_ID}:evidence:test:action",
            clocks={"source_time": _timestamp(NOW)},
            source={"implementation": "test", "version": "1.0.0"},
            body={
                "action_id": action_id,
                "dispatch_attempt": 1,
                "connector_identity": DESTINATION,
                "connector_version": "1.0.0",
                "destination_response_digest": _digest(b"response"),
                "destination_record_ref": destination_id,
                "status": "succeeded",
                "dispatched_at": _timestamp(NOW),
                "responded_at": _timestamp(NOW),
            },
        ),
    )


def _proposal(action_id: str) -> ActionProposalRecord:
    return _sign(
        ActionProposalRecord,
        _envelope(
            record_type="ActionProposal",
            record_id=_uuid7(NOW),
            stream_id=f"{TENANT_ID}:evidence:test:action",
            clocks={"source_time": _timestamp(NOW)},
            source={"implementation": "test", "version": "1.0.0"},
            body={
                "action_family": ACTION_FAMILY,
                "action_id": action_id,
                "tool": "salesforce.case.create",
                "parameters_digest": _digest(b"parameters"),
                "purpose": "test",
                "target_ref": DESTINATION,
                "risk_class": "low",
                "proposed_at": _timestamp(NOW),
            },
        ),
    )


def _confirmation(destination_id: str, action_id: str) -> ExternalConfirmationRecord:
    return _sign(
        ExternalConfirmationRecord,
        _envelope(
            record_type="ExternalConfirmation",
            record_id=_uuid7(NOW),
            stream_id=f"{TENANT_ID}:issuer:test:confirmation",
            clocks={"source_time": _timestamp(NOW)},
            source={"implementation": "test", "version": "1.0.0"},
            body={
                "action_id": action_id,
                "destination_system": DESTINATION,
                "destination_record_id": destination_id,
                "destination_record_digest": _digest(b"record"),
                "authoritative_timestamp": _timestamp(NOW),
                "reconciliation_status": "matched",
                "retrieved_at": _timestamp(NOW),
            },
        ),
    )


def test_confirmation_action_id_is_read_from_the_ledger_receipt() -> None:
    """The identity must come from the receipt, never be composed here.

    EV-15 matches a receipt to a confirmation by action identity. An id built
    as `"<prefix>:<CaseId>"` cannot equal one minted before the Case existed,
    so a generator that composes one can never produce a matched fixture --
    the failure is silent, because every record is individually well-formed.
    """
    ledger = _held(_receipt(CASE_B, LEDGER_ACTION_ID))

    targets = select_confirmation_targets(ledger, [CASE_A, CASE_B])

    assert len(targets) == 1
    assert targets[0].destination_record_id == CASE_B
    assert targets[0].action_id == LEDGER_ACTION_ID
    assert targets[0].derived_from_ledger is True
    # The Case the ledger points at, not merely the first one enumerated.
    assert targets[0].destination_record_id != CASE_A
    assert not targets[0].action_id.startswith("salesforce-live-case:")


def test_an_unevidenced_population_still_confirms_one_case_transparently() -> None:
    """With nothing in the ledger, no confirmation can match anything. One is
    still issued to exercise the capability, under an identity that does not
    pretend to be an action id."""
    targets = select_confirmation_targets((), [CASE_A, CASE_B])

    assert len(targets) == 1
    assert targets[0].destination_record_id == CASE_A
    assert targets[0].action_id.startswith("unmatched-probe:")
    assert targets[0].derived_from_ledger is False


def test_ledger_derived_action_id_reconciles_as_matched() -> None:
    """The end the selector exists for: a real EV-08 action reaches `matched`."""
    population = _population([CASE_A])
    ledger = _held(_proposal(LEDGER_ACTION_ID), _receipt(CASE_A, LEDGER_ACTION_ID))

    target = select_confirmation_targets(ledger, [CASE_A])[0]
    assert target.derived_from_ledger is True
    results = reconcile(
        population,
        tuple(item.record for item in ledger),
        (_confirmation(target.destination_record_id, target.action_id),),
    )

    assert [result.status for result in results] == [ReconciliationStatus.MATCHED]
    assert results[0].action_id == LEDGER_ACTION_ID


def test_a_composed_action_id_would_not_have_matched() -> None:
    """The regression this pins: the previous generator's identity scheme.

    Reproduced rather than described, so the defect cannot return quietly by
    someone reintroducing a composed id that looks reasonable.
    """
    population = _population([CASE_A])
    ledger = _held(_proposal(LEDGER_ACTION_ID), _receipt(CASE_A, LEDGER_ACTION_ID))
    composed = _confirmation(CASE_A, f"salesforce-live-case:{CASE_A}")

    results = reconcile(
        population, tuple(item.record for item in ledger), (composed,)
    )

    assert results[0].status is ReconciliationStatus.UNMATCHED_WITH_EVIDENCE
    assert results[0].status is not ReconciliationStatus.MATCHED


def test_a_non_empty_ledger_does_not_imply_a_ledger_derived_identity() -> None:
    """Provenance is about what was *selected*, not what the ledger held.

    Both cases below leave a non-empty ledger while selecting nothing from it,
    so a flag derived from `bool(ledger_records)` would report a ledger-derived
    identity for a confirmation that carries a probe id. A manifest asserting a
    provenance it never established is the same defect as a fabricated count,
    arriving one field over.
    """
    # A proposal with no receipt: nothing names a destination record at all.
    proposal_only = _held(_proposal(LEDGER_ACTION_ID))
    targets = select_confirmation_targets(proposal_only, [CASE_A])
    assert proposal_only  # the ledger is not empty
    assert targets[0].derived_from_ledger is False
    assert targets[0].action_id.startswith("unmatched-probe:")

    # A receipt naming a Case outside the enumerated window.
    outside = _held(_receipt("500ZZZnotinpopulation", LEDGER_ACTION_ID))
    targets = select_confirmation_targets(outside, [CASE_A])
    assert outside
    assert targets[0].derived_from_ledger is False
    assert targets[0].destination_record_id == CASE_A

    # And the positive control, so the assertion above is not vacuous.
    inside = _held(_receipt(CASE_A, LEDGER_ACTION_ID))
    assert select_confirmation_targets(inside, [CASE_A])[0].derived_from_ledger


def test_the_two_published_sets_demonstrate_opposite_outcomes() -> None:
    """The pair is the argument; either set alone is not.

    An honest zero is only evidence if a matched result was reachable by the
    same route. These two sets come from one code path over one ledger: the
    zero is a zero the reconciler looked for and did not find, and the match
    proves looking can succeed. A zero produced by a path that cannot match is
    indistinguishable from a fabricated one, which is the defect this pair
    exists to rule out.
    """
    import json
    from pathlib import Path

    root = Path(__file__).resolve().parents[1] / "fixtures"
    zero = json.loads((root / "salesforce-live" / "09-manifest.json").read_text())
    match = json.loads(
        (root / "salesforce-live-matched" / "09-manifest.json").read_text()
    )

    # Both consulted a real ledger that held real evidence.
    for manifest in (zero, match):
        assert manifest["evidence_ledger"]["queried"] is True
        assert manifest["evidence_ledger"]["rows_returned"] > 0

    # The zero is not an artefact of an empty evidence side.
    assert zero["computation"]["matched_count"] == 0
    assert zero["computation"]["coverage_ratio"] == "0.0000"

    # And the same code path reaches a match.
    assert match["computation"]["matched_count"] >= 1
    assert match["computation"]["coverage_ratio"] == "1.0000"
    assert match["computation"]["confirmations_with_ledger_derived_action_id"] >= 1
    # The zero set read a non-empty ledger and still selected no receipt-
    # derived identity, which is exactly the distinction the flag must keep.
    assert zero["computation"]["confirmations_with_ledger_derived_action_id"] == 0
