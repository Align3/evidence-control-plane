"""Adversarial EV-11 oversight-effectiveness tests."""

from __future__ import annotations

import pytest

from sdk_python.evidence.schema import HumanReviewRecord, validate_record
from services.computation.oversight import (
    OversightReason,
    evaluate_oversight,
    evaluate_review,
)
from tests.coverage_support import at


def human_review(
    *,
    record_id: str = "01890f47-2f58-7cc0-98c4-000000000311",
    action_id: str = "action-1",
    state: str = "proposed",
    tenant_id: str = "acme",
    boundary_ref: str = "acme:boundary:1",
    provenance: str | None = "client_rendered",
) -> HumanReviewRecord:
    body: dict[str, object] = {
        "action_id": action_id,
        "reviewer_identity": "reviewer-1",
        "reviewer_authority": {"role": "approver", "authorised": True},
        "surface": {"ui": "review", "version": "1"},
        "evidence_shown": "sha256:" + "11" * 32,
        "evidence_shown_refs": ["proposal-1"],
        "options_offered": ["approve", "deny"],
        "time_available_ms": 30_000,
        "time_taken_ms": 1_000,
        "decision": "approve",
        "modifications": None,
        "action_state_at_review": state,
        "decided_at": at(9, 30).isoformat(timespec="milliseconds"),
    }
    if provenance is not None:
        body["evidence_shown_provenance"] = provenance
    record = validate_record(
        {
            "record_id": record_id,
            "record_type": "HumanReview",
            "schema_version": "1.0.0",
            "tenant_id": tenant_id,
            "boundary_ref": boundary_ref,
            "stream_id": "review-stream",
            "sequence": 1,
            "prev_digest": None,
            "source": {"sdk": "typescript"},
            "clocks": {"source_time": at(9, 30).isoformat(timespec="milliseconds")},
            "body": body,
            "signature": {},
        }
    )
    assert isinstance(record, HumanReviewRecord)
    return record


@pytest.mark.parametrize("state", ["committed", "irreversible"])
def test_approval_after_commitment_never_counts_as_effective(state: str) -> None:
    result = evaluate_review(human_review(state=state))

    assert result.effective is False
    assert result.reason is (
        OversightReason.REVIEW_AFTER_COMMITMENT
        if state == "committed"
        else OversightReason.REVIEW_AFTER_IRREVERSIBILITY
    )


def test_state_mutation_is_the_effectiveness_boundary() -> None:
    late = evaluate_review(human_review(state="committed"))
    timely = evaluate_review(human_review(state="reversible"))

    assert late.effective is False
    assert timely.effective is True


def test_server_reconstruction_cannot_be_upgraded_to_effective_oversight() -> None:
    result = evaluate_review(human_review(provenance="server_reconstructed"))

    assert result.effective is False
    assert result.reason is OversightReason.SERVER_RECONSTRUCTED_EVIDENCE


def test_unknown_provenance_cannot_fall_through_as_client_rendered() -> None:
    result = evaluate_review(human_review(provenance="rendered_on_server"))

    assert result.effective is False
    assert result.reason is OversightReason.UNVERIFIED_EVIDENCE_PROVENANCE


def test_unlabelled_original_schema_record_retains_rendered_evidence_claim() -> None:
    """ES-013 requires the label for reconstruction, not for rendered evidence."""

    assert evaluate_review(human_review(provenance=None)).effective is True


def test_wrong_tenant_boundary_and_action_cannot_inflate_counts() -> None:
    report = evaluate_oversight(
        (
            human_review(),
            human_review(record_id="01890f47-2f58-7cc0-98c4-000000000312", tenant_id="other"),
            human_review(
                record_id="01890f47-2f58-7cc0-98c4-000000000313",
                boundary_ref="acme:other:1",
            ),
            human_review(
                record_id="01890f47-2f58-7cc0-98c4-000000000314",
                action_id="not-required",
            ),
        ),
        required_action_ids=("action-1",),
        tenant_id="acme",
        boundary_ref="acme:boundary:1",
        window_start=at(9),
        window_end=at(10),
    )

    assert report.reviewed_action_ids == ("action-1",)
    assert report.effective_action_ids == ("action-1",)
    assert len(report.evaluations) == 1


def test_out_of_window_review_is_recorded_but_not_counted_for_scoped_claim() -> None:
    review = human_review()
    late_body = review.body.model_copy(
        update={"decided_at": at(11).isoformat(timespec="milliseconds")}
    )
    late = review.model_copy(update={"body": late_body})
    report = evaluate_oversight(
        (late,),
        required_action_ids=("action-1",),
        tenant_id="acme",
        boundary_ref="acme:boundary:1",
        window_start=at(9),
        window_end=at(10),
    )

    assert report.reviewed_action_ids == ()
    assert report.effective_action_ids == ()
    assert report.evaluations[0].reason is OversightReason.OUTSIDE_ATTESTATION_WINDOW


def test_duplicate_reviews_count_actions_once_without_hiding_late_review() -> None:
    timely = human_review()
    late = human_review(
        record_id="01890f47-2f58-7cc0-98c4-000000000315", state="committed"
    )
    report = evaluate_oversight(
        (timely, late),
        required_action_ids=("action-1",),
        tenant_id="acme",
        boundary_ref="acme:boundary:1",
        window_start=at(9),
        window_end=at(10),
    )

    assert report.reviewed_action_ids == ("action-1",)
    assert report.effective_action_ids == ("action-1",)
    assert [item.reason for item in report.evaluations] == [
        OversightReason.EFFECTIVE,
        OversightReason.REVIEW_AFTER_COMMITMENT,
    ]


def test_required_action_ids_are_nonempty_unique_values() -> None:
    with pytest.raises(ValueError, match="duplicates"):
        evaluate_oversight(
            (),
            required_action_ids=("action-1", "action-1"),
            tenant_id="acme",
            boundary_ref="acme:boundary:1",
            window_start=at(9),
            window_end=at(10),
        )


def test_duplicate_record_id_cannot_inflate_record_count() -> None:
    review = human_review()
    with pytest.raises(ValueError, match="duplicate HumanReview record_id"):
        evaluate_oversight(
            (review, review),
            required_action_ids=("action-1",),
            tenant_id="acme",
            boundary_ref="acme:boundary:1",
            window_start=at(9),
            window_end=at(10),
        )
