"""Executable acceptance bindings for EV-16's pure coverage engine."""

from __future__ import annotations

from dataclasses import replace
from decimal import Decimal

from pytest_bdd import given, parsers, scenario, then, when

from services.admin.qualification import CoverageLevel, DenominatorClass
from services.computation.coverage import (
    ActionEvidence,
    GapActionClassification,
    TimeInterval,
    compute_coverage,
)
from services.computation.reconciliation import ReconciliationStatus
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


@scenario(
    "coverage.feature",
    "CM-S-001 Coverage ratio withheld at insufficient denominator class",
)
def test_cm_s_001_ratio_withheld_at_c4() -> None:
    """C4 produces an explicit non-numeric result and an observed cap."""


@scenario(
    "coverage.feature",
    "CM-S-003 Fail-open interval cannot claim enforced coverage",
)
def test_cm_s_003_fail_open_interval() -> None:
    """Actions in a fail-open interval are unknown or exactly reconciled."""


@scenario(
    "coverage.feature",
    "CM-S-004 Admissibility caps evidence-supported level",
)
def test_cm_s_004_class_cap() -> None:
    """EV-12's C3 cap binds a reconciled evidence-supported level."""


@scenario("coverage.feature", "CM-S-010 Unknown is not absorbed")
def test_cm_s_010_unknown_interval_is_adjacent() -> None:
    """An unavailable denominator remains explicit interval metadata."""


@scenario("evidence.feature", "ES-S-014 Measured skew withholds numerator eligibility")
def test_es_s_014_measured_skew_withholds_numerator() -> None:
    """Only issuer-measured skew may exclude the record and open the gap."""


@scenario("evidence.feature", "ES-S-021 Coverage computation maps truncation to null, not zero")
def test_es_s_021_truncation_is_null() -> None:
    """The coverage layer, not population recording or rendering, owns null."""


@scenario("meta.feature", "QA-S-002 Gap conservation holds, property 6")
def test_qa_s_002_gap_conservation_acceptance() -> None:
    """Scenario binding; randomized proof lives in the property test module."""


def _base_context(
    *,
    denominator_class: DenominatorClass,
    statuses: list[ReconciliationStatus],
) -> dict[str, object]:
    return {
        "population": coverage_population(len(statuses)),
        "results": reconciliation_results(statuses),
        "boundary": boundary(),
        "qualification_history": (qualification(denominator_class),),
        "action_evidence": action_evidence(statuses),
        "gaps": (),
    }


def _compute(context: dict[str, object]) -> None:
    context["report"] = compute_coverage(
        reconciliation_results=context["results"],  # type: ignore[arg-type]
        population=context["population"],  # type: ignore[arg-type]
        boundary=context["boundary"],  # type: ignore[arg-type]
        qualification_history=context["qualification_history"],  # type: ignore[arg-type]
        action_evidence=context["action_evidence"],  # type: ignore[arg-type]
        gaps=context["gaps"],  # type: ignore[arg-type]
    )


@given(
    parsers.parse('an action family "{family}" with denominator source class C4'),
    target_fixture="coverage_context",
)
def class_c4_family(family: str) -> dict[str, object]:
    assert family == "ticket.resolve"
    context = _base_context(
        denominator_class=DenominatorClass.C4,
        statuses=[ReconciliationStatus.MATCHED],
    )
    context["population"] = coverage_population(1).model_copy(
        update={
            "body": coverage_population(1).body.model_copy(
                update={"action_family": family}
            )
        }
    )
    context["qualification_history"] = (
        replace(qualification(DenominatorClass.C4), action_family=family),
    )
    return context


@when("coverage is computed for window W")
@when("coverage is computed")
@when("coverage is computed for its window")
@when("coverage eligibility is evaluated")
def coverage_is_computed(coverage_context: dict[str, object]) -> None:
    _compute(coverage_context)


@then("no coverage ratio is emitted")
def no_coverage_ratio(coverage_context: dict[str, object]) -> None:
    report = coverage_context["report"]
    assert report.coverage_ratio is None  # type: ignore[union-attr]
    assert report.to_payload()["coverage_ratio"] is None  # type: ignore[union-attr]


@then(parsers.parse('the maximum claimable coverage level is "{level}"'))
def maximum_claimable_level(coverage_context: dict[str, object], level: str) -> None:
    assert coverage_context["report"].claimed_level.value == level  # type: ignore[union-attr]


@then("the attestation states that the population is not independently enumerable")
def population_not_independently_enumerable(
    coverage_context: dict[str, object],
) -> None:
    assert coverage_context["report"].population_independently_enumerable is False  # type: ignore[union-attr]


@given(
    parsers.parse('a declared boundary for action family "{family}" at class C1'),
    target_fixture="coverage_context",
)
def fail_open_context(family: str) -> dict[str, object]:
    assert family == "refund.issue"
    statuses = [ReconciliationStatus.MATCHED] * 2 + [
        ReconciliationStatus.UNMATCHED_WITH_EVIDENCE
    ] * 10
    context = _base_context(
        denominator_class=DenominatorClass.C1,
        statuses=statuses,
    )
    context["action_evidence"] = action_evidence(
        statuses, occurred_at=at(10, 3)
    )[:2] + tuple(
        receipted_action_evidence(index, occurred_at=at(10, 3))
        for index in range(2, 12)
    )
    return context


@given("the checkpoint is unreachable from 10:00 to 10:07")
def checkpoint_unreachable(coverage_context: dict[str, object]) -> None:
    coverage_context["gaps"] = (
        gap(at(10), at(10, 7), cause="fail_open", actions_during_gap=12),
    )


@given("12 actions executed during that interval")
def twelve_actions(coverage_context: dict[str, object]) -> None:
    assert len(coverage_context["results"]) == 12  # type: ignore[arg-type]


@when("an attestation window covering 09:00-11:00 is generated")
def fail_open_window_generated(coverage_context: dict[str, object]) -> None:
    _compute(coverage_context)


@then(parsers.parse('the window does not claim "{level}" for 10:00-10:07'))
def no_level_inside_gap(coverage_context: dict[str, object], level: str) -> None:
    assert level == "enforced"
    report = coverage_context["report"]
    target = TimeInterval(at(10), at(10, 7))
    assert target in report.gap_intervals  # type: ignore[union-attr]
    assert all(not target.encloses(interval) for interval in report.covered_intervals)  # type: ignore[union-attr]


@then("a signed gap record for that interval is present")
def signed_gap_is_present(coverage_context: dict[str, object]) -> None:
    report = coverage_context["report"]
    assert report.gaps[0].evidence_record_ref is not None  # type: ignore[union-attr]


@then("the 12 actions are classified unknown, or reconciled if destination-matched")
def gap_actions_are_closed(coverage_context: dict[str, object]) -> None:
    gap_actions = coverage_context["report"].gap_actions  # type: ignore[union-attr]
    assert len(gap_actions) == 12
    assert {item.classification for item in gap_actions} == {
        GapActionClassification.UNKNOWN,
        GapActionClassification.RECONCILED,
    }


@then("no action in that interval is classified enforced")
def gap_action_cannot_be_enforced(coverage_context: dict[str, object]) -> None:
    assert not hasattr(GapActionClassification, "ENFORCED")


@given(
    parsers.parse('evidence sufficient to support "{level}" for every action in window W'),
    target_fixture="coverage_context",
)
def fully_supported(level: str) -> dict[str, object]:
    assert level == CoverageLevel.RECONCILED.value
    return _base_context(
        denominator_class=DenominatorClass.C1,
        statuses=[ReconciliationStatus.MATCHED],
    )


@given("a denominator source of class C3")
def source_is_c3(coverage_context: dict[str, object]) -> None:
    coverage_context["qualification_history"] = (
        qualification(DenominatorClass.C3),
    )


@then(parsers.parse('the claimed level is "{level}"'))
def claimed_level(coverage_context: dict[str, object], level: str) -> None:
    assert coverage_context["report"].claimed_level is CoverageLevel(level)  # type: ignore[union-attr]


@then("the attestation records that the level was capped by denominator class")
def cap_is_recorded(coverage_context: dict[str, object]) -> None:
    assert coverage_context["report"].capped_by_class is True  # type: ignore[union-attr]


@given(
    "a window in which the denominator source was unavailable for 90 minutes",
    target_fixture="coverage_context",
)
def unavailable_denominator() -> dict[str, object]:
    context = _base_context(
        denominator_class=DenominatorClass.C1,
        statuses=[ReconciliationStatus.MATCHED],
    )
    context["gaps"] = (gap(at(9, 15), at(10, 45), actions_during_gap=None),)
    return context


@when("the attestation is rendered")
def coverage_for_rendering(coverage_context: dict[str, object]) -> None:
    _compute(coverage_context)


@then("the unknown interval appears adjacent to the coverage claim")
def gap_adjacent(coverage_context: dict[str, object]) -> None:
    report = coverage_context["report"]
    assert report.gap_intervals == (TimeInterval(at(9, 15), at(10, 45)),)  # type: ignore[union-attr]
    assert report.covered_intervals == (  # type: ignore[union-attr]
        TimeInterval(at(9), at(9, 15)),
        TimeInterval(at(10, 45), at(11)),
    )


@then("it is expressed as a time range with cause and affected scope")
def gap_has_metadata(coverage_context: dict[str, object]) -> None:
    (gap_evidence,) = coverage_context["report"].gaps  # type: ignore[union-attr]
    assert gap_evidence.interval == TimeInterval(at(9, 15), at(10, 45))
    assert gap_evidence.cause.value == "denominator_unavailable"  # type: ignore[union-attr]
    assert gap_evidence.affected_scope == ("refund.issue",)


@then("it is not expressed as a reduction in the coverage percentage alone")
def gap_is_not_ratio_only(coverage_context: dict[str, object]) -> None:
    report = coverage_context["report"]
    assert report.gaps and report.gap_intervals  # type: ignore[union-attr]


@given("a record without authoritative_time", target_fixture="coverage_context")
def no_authoritative_time() -> dict[str, object]:
    receipt, receipt_record, receipt_keys = signed_ingestion_receipt(
        skew_ms=5_001, action_id="action-0", source_time=at(10)
    )
    context = _base_context(
        denominator_class=DenominatorClass.C1,
        statuses=[ReconciliationStatus.UNMATCHED_WITH_EVIDENCE],
    )
    context["action_evidence"] = (
        ActionEvidence(
            destination_record_id="destination-0",
            ingestion_receipt=receipt,
            receipt_record=receipt_record,
            receipt_verification_keys=receipt_keys,
            affected_interval=TimeInterval(at(9, 59), at(10, 1)),
        ),
    )
    return context


@given("its issuer-signed ingestion receipt exceeds the boundary clock-skew threshold")
def issuer_skew_exceeds_threshold(coverage_context: dict[str, object]) -> None:
    (item,) = coverage_context["action_evidence"]  # type: ignore[misc]
    measured = item.ingestion_receipt.payload.clock_skew_ms
    threshold = coverage_context["boundary"].clock_skew_threshold_ms  # type: ignore[union-attr]
    assert abs(measured) > threshold


@then("the record is excluded from the numerator")
def excluded_from_numerator(coverage_context: dict[str, object]) -> None:
    assert coverage_context["report"].numerator_count == 0  # type: ignore[union-attr]


@then("the affected interval is counted as unknown")
def skew_interval_unknown(coverage_context: dict[str, object]) -> None:
    report = coverage_context["report"]
    assert TimeInterval(at(9, 59), at(10, 1)) in report.gap_intervals  # type: ignore[union-attr]
    assert report.gap_actions[0].classification is GapActionClassification.UNKNOWN  # type: ignore[union-attr]


@given(
    "a stored PopulationRecord with result_cap_hit true or pagination_complete false",
    target_fixture="coverage_context",
)
def truncated_population() -> dict[str, object]:
    context = _base_context(
        denominator_class=DenominatorClass.C1,
        statuses=[ReconciliationStatus.MATCHED],
    )
    context["population"] = coverage_population(
        1, result_cap_hit=True, pagination_complete=False
    )
    return context


@then("coverage_ratio is null")
def coverage_ratio_is_null(coverage_context: dict[str, object]) -> None:
    report = coverage_context["report"]
    assert report.coverage_ratio is None  # type: ignore[union-attr]
    assert report.to_payload()["coverage_ratio"] is None  # type: ignore[union-attr]


@then("coverage_ratio is not zero")
def coverage_ratio_is_not_zero(coverage_context: dict[str, object]) -> None:
    assert coverage_context["report"].coverage_ratio != Decimal("0")  # type: ignore[union-attr]


@given("any generated evidence set over window W", target_fixture="coverage_context")
def generated_interval_set() -> dict[str, object]:
    context = _base_context(
        denominator_class=DenominatorClass.C1,
        statuses=[],
    )
    context["gaps"] = (
        gap(at(9, 5), at(9, 40)),
        gap(at(9, 20), at(10, 10)),
        gap(at(10, 30), at(10, 55)),
    )
    return context


@then("covered intervals and gap intervals partition W exactly")
def intervals_partition_window(coverage_context: dict[str, object]) -> None:
    report = coverage_context["report"]
    zero = report.window.duration * 0  # type: ignore[union-attr]
    total = sum(
        (item.duration for item in report.covered_intervals),  # type: ignore[union-attr]
        start=zero,
    )
    total += sum(
        (item.duration for item in report.gap_intervals),  # type: ignore[union-attr]
        start=zero,
    )
    assert total == report.window.duration  # type: ignore[union-attr]


@then("no interval is both")
def no_interval_is_both(coverage_context: dict[str, object]) -> None:
    report = coverage_context["report"]
    assert all(
        covered.end <= unknown.start or unknown.end <= covered.start
        for covered in report.covered_intervals  # type: ignore[union-attr]
        for unknown in report.gap_intervals  # type: ignore[union-attr]
    )


@then("no interval is neither")
def no_interval_is_neither(coverage_context: dict[str, object]) -> None:
    intervals_partition_window(coverage_context)
