"""CM-014 / QA property 6: time is covered or gap, exactly once."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from hypothesis import given
from hypothesis import strategies as st

from services.admin.qualification import DenominatorClass
from services.computation.coverage import GapEvidence, TimeInterval, compute_coverage
from tests.coverage_support import (
    boundary,
    coverage_population,
    qualification,
)


@given(
    st.lists(
        st.tuples(
            st.integers(min_value=0, max_value=119),
            st.integers(min_value=1, max_value=120),
        ).filter(lambda pair: pair[0] < pair[1]),
        max_size=30,
    )
)
def test_qa_s_002_gap_conservation_holds_for_generated_interval_sets(
    raw_intervals: list[tuple[int, int]],
) -> None:
    start = datetime(2026, 8, 11, 9, tzinfo=UTC)
    gaps = tuple(
        GapEvidence(
            interval=TimeInterval(
                start + timedelta(minutes=gap_start),
                start + timedelta(minutes=gap_end),
            ),
            cause="denominator_unavailable",
            affected_scope=("refund.issue",),
            detection_source="property-generator",
            actions_during_gap=None,
            evidence_record_ref=f"gap-{index}",
        )
        for index, (gap_start, gap_end) in enumerate(raw_intervals)
    )
    report = compute_coverage(
        reconciliation_results=(),
        population=coverage_population(0),
        boundary=boundary(),
        qualification_history=(qualification(DenominatorClass.C1),),
        action_evidence=(),
        gaps=gaps,
    )

    endpoints = {report.window.start, report.window.end}
    endpoints.update(
        point
        for interval in report.covered_intervals
        for point in (interval.start, interval.end)
    )
    endpoints.update(
        point
        for interval in report.gap_intervals
        for point in (interval.start, interval.end)
    )
    ordered = sorted(endpoints)
    for left, right in zip(ordered, ordered[1:], strict=False):
        if left == right:
            continue
        probe = left + (right - left) / 2
        covered = sum(interval.contains(probe) for interval in report.covered_intervals)
        unknown = sum(interval.contains(probe) for interval in report.gap_intervals)
        assert covered + unknown == 1
        assert not (covered and unknown)

    total = sum((interval.duration for interval in report.covered_intervals), timedelta())
    total += sum((interval.duration for interval in report.gap_intervals), timedelta())
    assert total == report.window.duration
