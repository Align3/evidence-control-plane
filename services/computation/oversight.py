"""Pure human-oversight effectiveness evaluation for EV-11.

The evaluator deliberately separates "a review record exists" (A-07) from
"the review happened while intervention was still possible" (A-08).  A late
approval remains evidence, but it can never be promoted into effective
oversight.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum

from sdk_python.evidence.schema import HumanReviewRecord


class OversightReason(StrEnum):
    """Closed, attestation-safe explanation for one review evaluation."""

    EFFECTIVE = "effective oversight"
    REVIEW_AFTER_COMMITMENT = "review after commitment"
    REVIEW_AFTER_IRREVERSIBILITY = "review after irreversibility"
    SERVER_RECONSTRUCTED_EVIDENCE = "server-reconstructed evidence"
    UNVERIFIED_EVIDENCE_PROVENANCE = "unverified evidence provenance"
    OUTSIDE_ATTESTATION_WINDOW = "review outside attestation window"


@dataclass(frozen=True, slots=True)
class ReviewEvaluation:
    record_id: str
    action_id: str
    effective: bool
    reason: OversightReason


@dataclass(frozen=True, slots=True)
class OversightReport:
    """Deterministic action counts plus every in-scope review disposition."""

    required_action_ids: tuple[str, ...]
    reviewed_action_ids: tuple[str, ...]
    effective_action_ids: tuple[str, ...]
    missing_action_ids: tuple[str, ...]
    evaluations: tuple[ReviewEvaluation, ...]


def evaluate_review(review: HumanReviewRecord) -> ReviewEvaluation:
    """Evaluate the two explicit ES-013/014 refusal conditions.

    The original HumanReview schema predates ``evidence_shown_provenance``.
    ES-013 makes the marker mandatory only for server reconstruction, so an
    absent marker retains the body's conformant client-rendered claim.  An
    explicit weaker marker is never silently upgraded.
    """

    state = review.body.action_state_at_review
    provenance = (review.body.model_extra or {}).get("evidence_shown_provenance")
    if state == "committed":
        reason = OversightReason.REVIEW_AFTER_COMMITMENT
    elif state == "irreversible":
        reason = OversightReason.REVIEW_AFTER_IRREVERSIBILITY
    elif provenance == "server_reconstructed":
        reason = OversightReason.SERVER_RECONSTRUCTED_EVIDENCE
    elif provenance not in (None, "client_rendered"):
        reason = OversightReason.UNVERIFIED_EVIDENCE_PROVENANCE
    else:
        reason = OversightReason.EFFECTIVE
    return ReviewEvaluation(
        record_id=review.record_id,
        action_id=review.body.action_id,
        effective=reason is OversightReason.EFFECTIVE,
        reason=reason,
    )


def evaluate_oversight(
    reviews: Sequence[HumanReviewRecord],
    *,
    required_action_ids: tuple[str, ...],
    tenant_id: str,
    boundary_ref: str,
    window_start: datetime,
    window_end: datetime,
) -> OversightReport:
    """Evaluate reviews within one attestation's exact scope.

    Counts are by action, not by record: repeated reviews cannot inflate P or
    Q.  Individual late/weaker records remain visible in ``evaluations`` even
    when another review for the same action was effective.

    ``required_action_ids`` is the caller's assertion about which actions
    required human review, and nothing here can check it: this function sees
    the reviews that happened, never the actions that should have had one.
    Passing an action's id is what makes a missing review reportable, so an
    id left out is an action whose absent review is silently not missing.
    The caller must derive the list from the action population in scope, not
    from the reviews it happens to hold -- deriving it from the reviews would
    make ``missing_action_ids`` unconditionally empty and the A-07/A-08
    claims self-confirming.
    """

    if not required_action_ids or any(not action_id for action_id in required_action_ids):
        raise ValueError("required_action_ids must contain non-empty values")
    if len(set(required_action_ids)) != len(required_action_ids):
        raise ValueError("required_action_ids must not contain duplicates")
    if window_end <= window_start:
        raise ValueError("window_end must be after window_start")

    required = frozenset(required_action_ids)
    reviewed: set[str] = set()
    effective: set[str] = set()
    evaluations: list[ReviewEvaluation] = []
    seen_record_ids: set[str] = set()
    for review in reviews:
        action_id = review.body.action_id
        if (
            review.tenant_id != tenant_id
            or review.boundary_ref != boundary_ref
            or action_id not in required
        ):
            continue
        if review.record_id in seen_record_ids:
            raise ValueError(f"duplicate HumanReview record_id: {review.record_id}")
        seen_record_ids.add(review.record_id)
        result = evaluate_review(review)
        decided_at = datetime.fromisoformat(review.body.decided_at)
        if not window_start <= decided_at < window_end:
            evaluations.append(
                replace(
                    result,
                    effective=False,
                    reason=OversightReason.OUTSIDE_ATTESTATION_WINDOW,
                )
            )
            continue
        reviewed.add(action_id)
        evaluations.append(result)
        if result.effective:
            effective.add(action_id)

    ordered_required = tuple(sorted(required))
    return OversightReport(
        required_action_ids=ordered_required,
        reviewed_action_ids=tuple(sorted(reviewed)),
        effective_action_ids=tuple(sorted(effective)),
        missing_action_ids=tuple(sorted(required - reviewed)),
        evaluations=tuple(evaluations),
    )


__all__ = [
    "OversightReason",
    "OversightReport",
    "ReviewEvaluation",
    "evaluate_oversight",
    "evaluate_review",
]
