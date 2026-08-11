"""Focused EV-16 coverage-engine invariants."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from decimal import Decimal

import pytest

from services.admin.qualification import CoverageLevel, DenominatorClass
from services.computation.coverage import (
    ActionEvidence,
    CoverageInputError,
    RatioState,
    compute_coverage,
)
from services.computation.reconciliation import ReconciliationResult, ReconciliationStatus
from tests.coverage_support import (
    action_evidence,
    at,
    boundary,
    coverage_population,
    gap,
    qualification,
    receipted_action_evidence,
    reconciliation_results,
    signed_ingestion_receipt,
)
from tests.reconciliation_support import population


def _compute(
    denominator_class: DenominatorClass,
    statuses: list[ReconciliationStatus],
    *,
    evidence: tuple[ActionEvidence, ...] | None = None,
    gaps=(),
    result_cap_hit: bool = False,
    pagination_complete: bool = True,
):
    size = len(statuses)
    return compute_coverage(
        reconciliation_results=reconciliation_results(statuses),
        population=coverage_population(
            size,
            result_cap_hit=result_cap_hit,
            pagination_complete=pagination_complete,
        ),
        boundary=boundary(),
        qualification_history=(qualification(denominator_class),),
        action_evidence=(action_evidence(statuses) if evidence is None else evidence),
        gaps=gaps,
    )


@pytest.mark.parametrize("denominator_class", [DenominatorClass.C4, DenominatorClass.C5])
def test_ratio_null_is_present_not_zero_or_omitted(
    denominator_class: DenominatorClass,
) -> None:
    report = _compute(denominator_class, [ReconciliationStatus.MATCHED])
    payload = report.to_payload()

    assert "coverage_ratio" in payload
    assert payload["coverage_ratio"] is None
    assert report.coverage_ratio is None
    assert report.coverage_ratio != Decimal("0")
    assert report.ratio_state is RatioState.DENOMINATOR_CLASS_WITHHOLDS_RATIO


def test_zero_ratio_remains_distinct_from_null() -> None:
    report = _compute(
        DenominatorClass.C1,
        [ReconciliationStatus.UNMATCHED_WITHOUT_EVIDENCE],
        evidence=(
            ActionEvidence(
                destination_record_id="destination-0",
            ),
        ),
    )

    assert report.coverage_ratio == Decimal("0")
    assert report.to_payload()["coverage_ratio"] == "0"
    assert report.ratio_state is RatioState.AVAILABLE


@pytest.mark.parametrize(
    ("result_cap_hit", "pagination_complete"),
    [(True, True), (False, False), (True, False)],
)
def test_truncation_withholds_ratio(
    result_cap_hit: bool, pagination_complete: bool
) -> None:
    report = _compute(
        DenominatorClass.C1,
        [ReconciliationStatus.MATCHED],
        result_cap_hit=result_cap_hit,
        pagination_complete=pagination_complete,
    )

    assert report.coverage_ratio is None
    assert report.to_payload()["coverage_ratio"] is None
    assert report.ratio_state is RatioState.TRUNCATED_POPULATION


def test_digest_only_population_withholds_aggregate_ratio() -> None:
    """EV-15 cannot supply per-record labels for a digest-only denominator.

    EV-16 therefore does not invent an aggregate confirmation path: the class
    may ordinarily emit ratios, but this population representation cannot.
    """
    report = compute_coverage(
        reconciliation_results=(),
        population=population(
            None,
            count=2,
            window_start="2026-08-11T09:00:00.000Z",
            window_end="2026-08-11T11:00:00.000Z",
        ),
        boundary=boundary(),
        qualification_history=(qualification(DenominatorClass.C1),),
        action_evidence=(),
    )

    assert report.coverage_ratio is None
    assert report.ratio_state is RatioState.DIGEST_ONLY_POPULATION
    assert report.numerator_count == 0


def test_class_cap_uses_ev12_table_and_records_when_it_binds() -> None:
    report = _compute(DenominatorClass.C3, [ReconciliationStatus.MATCHED])

    assert report.class_admissible_level is DenominatorClass.C3.admissible_level
    assert report.claimed_level is CoverageLevel.ENFORCED
    assert report.capped_by_class is True


def test_cap_flag_is_false_when_derived_evidence_is_already_weaker() -> None:
    report = _compute(
        DenominatorClass.C3,
        [ReconciliationStatus.UNMATCHED_WITH_EVIDENCE],
        evidence=(receipted_action_evidence(0, occurred_at=at(10)),),
    )

    assert report.evidence_supported_level is CoverageLevel.OBSERVED
    assert report.claimed_level is CoverageLevel.OBSERVED
    assert report.capped_by_class is False


def test_classification_counts_are_conserved_without_imputation() -> None:
    statuses = list(ReconciliationStatus)
    report = _compute(
        DenominatorClass.C1,
        statuses,
        evidence=action_evidence(statuses),
    )

    assert report.counts.as_dict() == {status.value: 1 for status in statuses}
    assert report.numerator_count == 1


def test_fail_open_actions_are_only_unknown_or_reconciled() -> None:
    statuses = [ReconciliationStatus.MATCHED] * 2 + [
        ReconciliationStatus.UNMATCHED_WITH_EVIDENCE
    ] * 10
    evidence = action_evidence(statuses, occurred_at=at(10, 3))[:2] + tuple(
        receipted_action_evidence(index, occurred_at=at(10, 3))
        for index in range(2, 12)
    )
    report = _compute(
        DenominatorClass.C1,
        statuses,
        evidence=evidence,
        gaps=(gap(at(10), at(10, 7), cause="fail_open", actions_during_gap=12),),
    )

    assert {item.classification.value for item in report.gap_actions} == {
        "unknown",
        "reconciled",
    }
    assert sum(item.classification.value == "unknown" for item in report.gap_actions) == 10
    assert sum(item.classification.value == "reconciled" for item in report.gap_actions) == 2


def test_unknown_interval_is_adjacent_metadata_not_ratio_only() -> None:
    report = _compute(
        DenominatorClass.C1,
        [ReconciliationStatus.MATCHED],
        gaps=(gap(at(9, 15), at(10, 45), actions_during_gap=None),),
    )

    assert report.gaps[0].interval.start == at(9, 15)
    assert report.gaps[0].interval.end == at(10, 45)
    assert report.gaps[0].cause == "denominator_unavailable"
    assert report.gaps[0].affected_scope == ("refund.issue",)
    assert report.gap_intervals


def test_measured_skew_excludes_numerator_and_marks_interval_unknown() -> None:
    receipt, receipt_record, receipt_keys = signed_ingestion_receipt(
        skew_ms=5_001, action_id="action-0", source_time=at(10)
    )
    evidence = (
        ActionEvidence(
            destination_record_id="destination-0",
            ingestion_receipt=receipt,
            receipt_record=receipt_record,
            receipt_verification_keys=receipt_keys,
            affected_interval=gap(at(9, 59), at(10, 1), cause="clock_skew").interval,
        ),
    )
    report = _compute(
        DenominatorClass.C1,
        [ReconciliationStatus.UNMATCHED_WITH_EVIDENCE],
        evidence=evidence,
    )

    assert report.numerator_count == 0
    assert report.coverage_ratio == Decimal("0")
    assert any(item.cause == "clock_skew" for item in report.gaps)
    assert report.gap_actions[0].classification.value == "unknown"


def test_bound_destination_authoritative_time_needs_no_receipt() -> None:
    report = _compute(
        DenominatorClass.C1,
        [ReconciliationStatus.MATCHED],
    )
    assert report.numerator_count == 1


def test_receipt_for_another_action_cannot_supply_occurrence_or_numerator() -> None:
    receipt, record, keys = signed_ingestion_receipt(
        skew_ms=0,
        action_id="another-action",
        destination_record_id="destination-0",
        source_time=at(10),
    )
    with pytest.raises(CoverageInputError, match="not bound"):
        _compute(
            DenominatorClass.C1,
            [ReconciliationStatus.UNMATCHED_WITH_EVIDENCE],
            evidence=(
                ActionEvidence(
                    destination_record_id="destination-0",
                    ingestion_receipt=receipt,
                    receipt_record=record,
                    receipt_verification_keys=keys,
                ),
            ),
        )


def test_evidence_strength_and_authoritative_time_have_no_scalar_input() -> None:
    assert "supported_level" not in ActionEvidence.__dataclass_fields__
    assert "authoritative_time" not in ActionEvidence.__dataclass_fields__


@pytest.mark.parametrize(
    ("status", "evidence"),
    [
        (
            ReconciliationStatus.MATCHED,
            action_evidence([ReconciliationStatus.MATCHED], occurred_at=at(12)),
        ),
        (
            ReconciliationStatus.UNMATCHED_WITH_EVIDENCE,
            (receipted_action_evidence(0, occurred_at=at(12)),),
        ),
    ],
)
def test_evidence_occurring_outside_the_window_cannot_enter_numerator(
    status: ReconciliationStatus,
    evidence: tuple[ActionEvidence, ...],
) -> None:
    report = _compute(DenominatorClass.C1, [status], evidence=evidence)

    assert report.numerator_count == 0
    assert report.coverage_ratio == Decimal("0")


def test_replay_is_deterministic_and_inputs_are_not_mutated() -> None:
    kwargs = {
        "reconciliation_results": reconciliation_results([ReconciliationStatus.MATCHED]),
        "population": coverage_population(1),
        "boundary": boundary(),
        "qualification_history": (qualification(DenominatorClass.C1),),
        "action_evidence": action_evidence([ReconciliationStatus.MATCHED]),
        "gaps": (gap(at(9, 30), at(9, 45)),),
    }
    before = deepcopy(kwargs)

    assert compute_coverage(**kwargs) == compute_coverage(**kwargs)
    assert kwargs == before


def test_result_identity_set_must_equal_inline_population() -> None:
    with pytest.raises(CoverageInputError, match="identities"):
        compute_coverage(
            reconciliation_results=reconciliation_results([ReconciliationStatus.MATCHED]),
            population=coverage_population(2),
            boundary=boundary(),
            qualification_history=(qualification(DenominatorClass.C1),),
            action_evidence=action_evidence([ReconciliationStatus.MATCHED]),
        )


@pytest.mark.parametrize(
    "status",
    [
        ReconciliationStatus.UNMATCHED_WITH_EVIDENCE,
        ReconciliationStatus.DUPLICATE,
        ReconciliationStatus.AMBIGUOUS,
    ],
)
def test_only_matched_status_can_support_reconciled_numerator(
    status: ReconciliationStatus,
) -> None:
    matched_evidence = action_evidence([ReconciliationStatus.MATCHED])
    with pytest.raises(CoverageInputError, match="not bound"):
        _compute(
            DenominatorClass.C1,
            [status],
            evidence=matched_evidence,
        )


def test_unknown_reconciliation_status_is_refused_not_dropped_from_counts() -> None:
    malformed = ReconciliationResult(
        population_ref="01890f47-2f58-7cc0-98c4-000000000001",
        destination_record_id="destination-0",
        status="not_a_classification",  # type: ignore[arg-type]
        action_id="action-0",
        confirmation_record_id=None,
    )
    with pytest.raises(CoverageInputError, match="set is closed"):
        compute_coverage(
            reconciliation_results=(malformed,),
            population=coverage_population(1),
            boundary=boundary(),
            qualification_history=(qualification(DenominatorClass.C1),),
            action_evidence=(),
        )


def test_reconciled_gap_action_is_not_converted_to_enforced_by_c3_cap() -> None:
    report = _compute(
        DenominatorClass.C3,
        [ReconciliationStatus.MATCHED],
        evidence=action_evidence(
            [ReconciliationStatus.MATCHED], occurred_at=at(10, 3)
        ),
        gaps=(gap(at(10), at(10, 7), cause="fail_open", actions_during_gap=1),),
    )

    assert report.claimed_level is CoverageLevel.ENFORCED
    assert report.numerator_count == 0
    assert report.gap_actions[0].classification.value == "reconciled"


def test_known_gap_action_count_requires_exact_temporal_attribution() -> None:
    with pytest.raises(CoverageInputError, match="actions_during_gap"):
        _compute(
            DenominatorClass.C1,
            [ReconciliationStatus.UNMATCHED_WITH_EVIDENCE],
            evidence=(
                ActionEvidence(
                    destination_record_id="destination-0",
                ),
            ),
            gaps=(gap(at(10), at(10, 7), cause="fail_open", actions_during_gap=1),),
        )


def test_serialized_report_preserves_adjacent_gap_claim() -> None:
    report = _compute(
        DenominatorClass.C1,
        [ReconciliationStatus.MATCHED],
        gaps=(gap(at(9, 15), at(10, 45)),),
    )
    payload = report.to_payload()

    assert payload["gaps"]
    assert payload["gap_intervals"]
    assert payload["covered_intervals"]


def test_midwindow_downgrade_is_resolved_by_ev12_before_lattice_cap() -> None:
    baseline = qualification(DenominatorClass.C1)
    downgrade = replace(
        qualification(DenominatorClass.C4),
        qualification_ref="q-downgrade",
        qualified_at=at(10),
        recorded_at=at(10),
    )
    report = compute_coverage(
        reconciliation_results=reconciliation_results([ReconciliationStatus.MATCHED]),
        population=coverage_population(1),
        boundary=boundary(),
        qualification_history=(baseline, downgrade),
        action_evidence=action_evidence([ReconciliationStatus.MATCHED]),
    )

    assert report.denominator_class is DenominatorClass.C4
    assert report.claimed_level is CoverageLevel.OBSERVED
    assert report.coverage_ratio is None


def test_ratio_class_without_enumeration_is_refused_as_invalid_input() -> None:
    malformed = replace(
        qualification(DenominatorClass.C1), enumeration_capable=False
    )
    with pytest.raises(CoverageInputError, match="requires enumeration"):
        compute_coverage(
            reconciliation_results=reconciliation_results([ReconciliationStatus.MATCHED]),
            population=coverage_population(1),
            boundary=boundary(),
            qualification_history=(malformed,),
            action_evidence=action_evidence([ReconciliationStatus.MATCHED]),
        )
