"""AR-027's effective interval, computed but not asserted (EV-12 / EV-17).

`interval_coverage` answers the question A-02 is conditioned on: was the
referenced boundary version in force for the whole attestation window? It does
not emit or withhold A-02, because assertion selection is EV-17's -- see the
story's disclosure notes on AR-S-007.

These tests are therefore about the *interval arithmetic* and about what the
result refuses to make easy. They are not AR-S-007, which asserts on an
attestation that this story cannot produce.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from services.admin.boundary import (
    BoundaryError,
    BoundaryVersion,
    DeclaredFamily,
    IntervalCoverage,
    effective_interval,
    interval_coverage,
)

FAMILY = DeclaredFamily(
    action_family="refund.issue",
    destination_system="payments-core",
    qualification_ref="q-1",
    fail_behaviour="fail_closed",
)


def at(*args: int) -> datetime:
    return datetime(*args, tzinfo=UTC)  # type: ignore[arg-type]


def version(
    *,
    number: int,
    window_start: datetime,
    window_end: datetime,
    recorded_at: datetime,
) -> BoundaryVersion:
    return BoundaryVersion(
        boundary_ref=f"acme:default:{number}",
        tenant_id="acme",
        name="default",
        version=number,
        window_start=window_start,
        window_end=window_end,
        recorded_at=recorded_at,
        families=(FAMILY,),
    )


# --- the floor: a boundary cannot be backdated into force --------------


def test_a_boundary_recorded_late_is_not_in_force_before_it_was_recorded() -> None:
    """AR-027's first clause, and the reason `recorded_at` is a hosted value.

    A version declaring a window from March but written in June was not in
    force in March, whatever it says about itself. Reading the start from the
    signed body alone would let a vendor draw the boundary after seeing the
    quarter's results.
    """
    v1 = version(
        number=1,
        window_start=at(2026, 3, 1),
        window_end=at(2026, 7, 1),
        recorded_at=at(2026, 6, 1),
    )
    interval = effective_interval(v1)
    assert interval.start == at(2026, 6, 1)
    assert interval.end == at(2026, 7, 1)

    coverage = interval_coverage(
        [v1],
        boundary_ref=v1.boundary_ref,
        window_start=at(2026, 3, 1),
        window_end=at(2026, 7, 1),
    )
    assert coverage.covered is False
    assert coverage.uncovered == ((at(2026, 3, 1), at(2026, 6, 1)),)


def test_a_window_running_past_the_declared_end_is_uncovered_at_the_tail() -> None:
    v1 = version(
        number=1,
        window_start=at(2026, 3, 1),
        window_end=at(2026, 6, 1),
        recorded_at=at(2026, 2, 1),
    )
    coverage = interval_coverage(
        [v1],
        boundary_ref=v1.boundary_ref,
        window_start=at(2026, 4, 1),
        window_end=at(2026, 7, 1),
    )
    assert coverage.covered is False
    assert coverage.uncovered == ((at(2026, 6, 1), at(2026, 7, 1)),)


def test_a_window_overhanging_both_ends_reports_both_bounds() -> None:
    """AR-027: "the uncovered interval is reported with its bounds"."""
    v1 = version(
        number=1,
        window_start=at(2026, 4, 1),
        window_end=at(2026, 5, 1),
        recorded_at=at(2026, 3, 1),
    )
    coverage = interval_coverage(
        [v1],
        boundary_ref=v1.boundary_ref,
        window_start=at(2026, 3, 1),
        window_end=at(2026, 6, 1),
    )
    assert coverage.uncovered == (
        (at(2026, 3, 1), at(2026, 4, 1)),
        (at(2026, 5, 1), at(2026, 6, 1)),
    )


# --- the ceiling: a successor closes the interval -----------------------


def test_a_later_version_ends_the_earlier_versions_interval() -> None:
    """AR-027's second clause.

    Version 1's declared window may run to July, but once version 2 takes
    effect in May, version 1 was no longer the boundary in force.
    """
    v1 = version(
        number=1,
        window_start=at(2026, 3, 1),
        window_end=at(2026, 7, 1),
        recorded_at=at(2026, 3, 1),
    )
    v2 = version(
        number=2,
        window_start=at(2026, 5, 1),
        window_end=at(2026, 9, 1),
        recorded_at=at(2026, 5, 1),
    )
    assert effective_interval(v1, successor=v2).end == at(2026, 5, 1)

    coverage = interval_coverage(
        [v1, v2],
        boundary_ref=v1.boundary_ref,
        window_start=at(2026, 3, 1),
        window_end=at(2026, 7, 1),
    )
    assert coverage.covered is False
    assert coverage.uncovered == ((at(2026, 5, 1), at(2026, 7, 1)),)


def test_a_later_version_does_not_extend_the_referenced_versions_interval() -> None:
    """AR-027 states this explicitly, so it is asserted explicitly.

    Versions 1 and 2 between them span the whole window. The attestation
    references version 1, which did not, and the result must say so. Answering
    "covered" here would be the union reading AR-027 forbids -- and it is the
    natural implementation, which is why it gets its own test.
    """
    v1 = version(
        number=1,
        window_start=at(2026, 3, 1),
        window_end=at(2026, 5, 1),
        recorded_at=at(2026, 3, 1),
    )
    v2 = version(
        number=2,
        window_start=at(2026, 5, 1),
        window_end=at(2026, 9, 1),
        recorded_at=at(2026, 5, 1),
    )
    coverage = interval_coverage(
        [v1, v2],
        boundary_ref=v1.boundary_ref,
        window_start=at(2026, 3, 1),
        window_end=at(2026, 8, 1),
    )
    assert coverage.covered is False
    assert coverage.uncovered == ((at(2026, 5, 1), at(2026, 8, 1)),)


def test_a_version_superseded_before_it_opened_was_never_in_force() -> None:
    """An empty interval, reported as such rather than normalised away.

    "In force for a shorter period than declared" and "never in force at all"
    are different facts, and the second is the one a relying party most needs
    to be told plainly.
    """
    v1 = version(
        number=1,
        window_start=at(2026, 6, 1),
        window_end=at(2026, 9, 1),
        recorded_at=at(2026, 6, 1),
    )
    v2 = version(
        number=2,
        window_start=at(2026, 4, 1),
        window_end=at(2026, 9, 1),
        recorded_at=at(2026, 5, 1),
    )
    interval = effective_interval(v1, successor=v2)
    assert interval.is_empty

    coverage = interval_coverage(
        [v1, v2],
        boundary_ref=v1.boundary_ref,
        window_start=at(2026, 6, 1),
        window_end=at(2026, 7, 1),
    )
    assert coverage.covered is False
    assert coverage.uncovered == ((at(2026, 6, 1), at(2026, 7, 1)),)


# --- what is covered ---------------------------------------------------


def test_a_version_enclosing_the_window_reports_no_uncovered_interval() -> None:
    v1 = version(
        number=1,
        window_start=at(2026, 1, 1),
        window_end=at(2027, 1, 1),
        recorded_at=at(2026, 1, 1),
    )
    coverage = interval_coverage(
        [v1],
        boundary_ref=v1.boundary_ref,
        window_start=at(2026, 4, 1),
        window_end=at(2026, 5, 1),
    )
    assert coverage.covered is True
    assert coverage.uncovered == ()


def test_a_window_exactly_matching_the_interval_is_covered() -> None:
    """The closed-interval boundary case, both endpoints inclusive."""
    v1 = version(
        number=1,
        window_start=at(2026, 4, 1),
        window_end=at(2026, 5, 1),
        recorded_at=at(2026, 3, 1),
    )
    coverage = interval_coverage(
        [v1],
        boundary_ref=v1.boundary_ref,
        window_start=at(2026, 4, 1),
        window_end=at(2026, 5, 1),
    )
    assert coverage.covered is True


def test_an_unknown_boundary_ref_is_refused_rather_than_answered() -> None:
    """A missing version resolves to no interval, and no interval is not "covered"."""
    v1 = version(
        number=1,
        window_start=at(2026, 4, 1),
        window_end=at(2026, 5, 1),
        recorded_at=at(2026, 3, 1),
    )
    with pytest.raises(BoundaryError):
        interval_coverage(
            [v1],
            boundary_ref="acme:default:9",
            window_start=at(2026, 4, 1),
            window_end=at(2026, 5, 1),
        )


def test_the_result_offers_no_covered_subinterval_to_restate_over() -> None:
    """AR-027 forbids a narrower restatement of A-02 in place of withholding.

    EV-17 makes that decision, but this type can decline to hand over the
    shape it would be built from. The check is structural rather than
    behavioural on purpose: it fails if a later change adds the convenient
    field back.
    """
    fields = set(IntervalCoverage.__dataclass_fields__)
    expected = {
        "boundary_ref",
        "effective",
        "window_start",
        "window_end",
        "uncovered",
    }
    assert fields == expected, (
        f"IntervalCoverage exposes {sorted(fields)} rather than exactly "
        f"{sorted(expected)}; extra result fields can make the covered part "
        "available for a narrower restatement of A-02"
    )
