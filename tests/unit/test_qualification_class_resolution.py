"""Which denominator class governs a window (CM-004, ES-010, TM-013).

The resolver is the second of the three guards described in
`services/admin/qualification.py`. These are unit tests of it: they construct
histories directly rather than through the database, because the cases that
matter most are the ones the write-time trigger already refuses -- a history
containing a backdated upgrade cannot be built through `record_qualification`,
and the resolver must still refuse to be fooled by one if it ever sees it.

That is the point of having more than one guard. A resolver tested only
against histories the database would accept is a resolver whose correctness
depends on the trigger, which makes it not an independent guard at all.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from services.admin.qualification import (
    QUALIFICATION_POSTDATES_WINDOW,
    ClassNotQualifiedError,
    CoverageLevel,
    DenominatorClass,
    Qualification,
    QualificationPostdatesWindowError,
    UnqualifiedWindowError,
    assert_class_claimable,
    class_in_force,
)

FAMILY = "refund.issue"
DESTINATION = "payments-core"


def qualification(
    *,
    ref: str,
    assigned_class: DenominatorClass,
    qualified_at: datetime,
    recorded_at: datetime | None = None,
    enumeration_capable: bool = True,
    confirmation_capable: bool = True,
) -> Qualification:
    return Qualification(
        qualification_ref=ref,
        tenant_id="acme",
        action_family=FAMILY,
        destination_system=DESTINATION,
        assigned_class=assigned_class,
        enumeration_capable=enumeration_capable,
        confirmation_capable=confirmation_capable,
        identity_isolation_attribute="service_principal_id",
        identity_vendor_settable=False,
        authoritative_time_available=True,
        settlement_lag_s=300,
        source_retention_days=400,
        deletion_traceless_possible=False,
        qualified_at=qualified_at,
        recorded_at=recorded_at or qualified_at,
        revalidate_after=qualified_at.replace(year=qualified_at.year + 1),
    )


def at(*args: int) -> datetime:
    return datetime(*args, tzinfo=UTC)  # type: ignore[arg-type]


# --- the refusals ------------------------------------------------------


def test_a_class_qualified_after_the_window_began_is_not_claimable() -> None:
    """TM-013. A C1 record dated 2026-09-01 does not entitle a window
    beginning 2026-08-01 to claim C1, however complete the evidence inside it.

    The threat-model scenario for retroactive upgrade uses these dates and is
    deliberately **not** named here. The traceability matrix reads a scenario
    ID in a test body as a test for that scenario, and this is not one: that
    scenario's `When` is "the verifier validates it", and the Go verifier is
    unbuilt. Citing it would turn the gate green over a demonstration of a
    different claim -- the citation-relocation failure QA-018 was numbered to
    stop. The scenario stays untested until EV-19 lands.
    """
    history = [
        qualification(
            ref="q-c4", assigned_class=DenominatorClass.C4, qualified_at=at(2026, 7, 1)
        ),
        qualification(
            ref="q-c1", assigned_class=DenominatorClass.C1, qualified_at=at(2026, 9, 1)
        ),
    ]
    with pytest.raises(QualificationPostdatesWindowError) as caught:
        assert_class_claimable(
            history,
            claimed=DenominatorClass.C1,
            window_start=at(2026, 8, 1),
            window_end=at(2026, 9, 1),
        )
    assert QUALIFICATION_POSTDATES_WINDOW in str(caught.value)


def test_a_class_qualified_at_the_instant_the_window_begins_is_not_claimable() -> None:
    """CM-004 says "beginning after that date", so the comparison is strict.

    Read the other way, a qualification recorded at 00:00:00.000 would govern
    a window starting at 00:00:00.000, and the retroactive upgrade TM-013
    forbids arrives one microsecond at a time.
    """
    history = [
        qualification(
            ref="q-c4", assigned_class=DenominatorClass.C4, qualified_at=at(2026, 7, 1)
        ),
        qualification(
            ref="q-c1", assigned_class=DenominatorClass.C1, qualified_at=at(2026, 8, 1)
        ),
    ]
    assert (
        class_in_force(
            history, window_start=at(2026, 8, 1), window_end=at(2026, 9, 1)
        )
        is DenominatorClass.C4
    )
    with pytest.raises(QualificationPostdatesWindowError):
        assert_class_claimable(
            history,
            claimed=DenominatorClass.C1,
            window_start=at(2026, 8, 1),
            window_end=at(2026, 9, 1),
        )


def test_a_backdated_upgrade_does_not_govern_a_window_it_predates() -> None:
    """The history the write-time trigger refuses, resolved anyway.

    If a C1 record dated before the C4 one ever reached the table -- through a
    restore, a replication artefact, or a trigger someone disabled -- the
    resolver must still not hand the window C1. It resolves the *weakest*
    class among the candidates rather than the latest, so the C4 record the
    upgrade was slipped behind still caps the window.
    """
    history = [
        qualification(
            ref="q-c1-backdated",
            assigned_class=DenominatorClass.C1,
            qualified_at=at(2026, 5, 1),
            recorded_at=at(2026, 7, 1),
        ),
        qualification(
            ref="q-c4",
            assigned_class=DenominatorClass.C4,
            qualified_at=at(2026, 6, 1),
            recorded_at=at(2026, 6, 1),
        ),
    ]
    assert (
        class_in_force(
            history, window_start=at(2026, 7, 1), window_end=at(2026, 8, 1)
        )
        is DenominatorClass.C4
    )


def test_a_backdated_upgrade_does_not_fill_the_gap_before_the_weaker_record() -> None:
    """The original resolver bug: latest-by-effective-time returned the C1.

    C4 was recorded first with a June effective date.  A C1 inserted later
    but dated May must not become the apparent baseline for a May window.
    """
    history = [
        qualification(
            ref="q-c4",
            assigned_class=DenominatorClass.C4,
            qualified_at=at(2026, 6, 1),
            recorded_at=at(2026, 6, 1),
        ),
        qualification(
            ref="q-c1-backdated",
            assigned_class=DenominatorClass.C1,
            qualified_at=at(2026, 5, 1),
            recorded_at=at(2026, 7, 1),
        ),
    ]
    with pytest.raises(UnqualifiedWindowError):
        class_in_force(
            history,
            window_start=at(2026, 5, 15),
            window_end=at(2026, 5, 20),
        )


def test_no_qualification_in_force_refuses_rather_than_defaulting() -> None:
    """CM-003. An undeclared class is not C5, and it is not observed-and-fine.

    Defaulting to the weakest class here would look conservative and would be
    a claim: that a denominator was assessed and found to be nothing. Nothing
    was assessed.
    """
    history = [
        qualification(
            ref="q-c1", assigned_class=DenominatorClass.C1, qualified_at=at(2026, 9, 1)
        )
    ]
    with pytest.raises(UnqualifiedWindowError):
        class_in_force(history, window_start=at(2026, 8, 1), window_end=at(2026, 9, 1))


def test_an_empty_history_refuses() -> None:
    with pytest.raises(UnqualifiedWindowError):
        class_in_force([], window_start=at(2026, 8, 1), window_end=at(2026, 9, 1))


def test_a_class_no_record_assigns_is_refused_as_unqualified_not_as_late() -> None:
    """The two refusals say different things and must not be conflated.

    "Qualified, but too late" and "never qualified at all" are different facts
    about the world, and a relying party reading the second as the first would
    expect the claim to become available by waiting.
    """
    history = [
        qualification(
            ref="q-c4", assigned_class=DenominatorClass.C4, qualified_at=at(2026, 6, 1)
        )
    ]
    with pytest.raises(ClassNotQualifiedError):
        assert_class_claimable(
            history,
            claimed=DenominatorClass.C1,
            window_start=at(2026, 8, 1),
            window_end=at(2026, 9, 1),
        )


def test_a_mid_window_downgrade_caps_the_whole_window() -> None:
    """CM-004 permits the downgrade; it does not permit splitting the window.

    Honouring it only from the downgrade onward would leave the earlier
    sub-interval claiming C1 on the strength of a denominator source since
    shown to be worse than believed -- a claim about a period whose basis has
    been withdrawn.
    """
    history = [
        qualification(
            ref="q-c1", assigned_class=DenominatorClass.C1, qualified_at=at(2026, 6, 1)
        ),
        qualification(
            ref="q-c4", assigned_class=DenominatorClass.C4, qualified_at=at(2026, 8, 15)
        ),
    ]
    assert (
        class_in_force(
            history, window_start=at(2026, 8, 1), window_end=at(2026, 9, 1)
        )
        is DenominatorClass.C4
    )
    with pytest.raises(ClassNotQualifiedError):
        assert_class_claimable(
            history,
            claimed=DenominatorClass.C1,
            window_start=at(2026, 8, 1),
            window_end=at(2026, 9, 1),
        )


def test_a_mid_window_upgrade_does_not_lift_the_window() -> None:
    """The direction CM-004 refuses, inside the window rather than before it."""
    history = [
        qualification(
            ref="q-c4", assigned_class=DenominatorClass.C4, qualified_at=at(2026, 6, 1)
        ),
        qualification(
            ref="q-c1", assigned_class=DenominatorClass.C1, qualified_at=at(2026, 8, 15)
        ),
    ]
    assert (
        class_in_force(
            history, window_start=at(2026, 8, 1), window_end=at(2026, 9, 1)
        )
        is DenominatorClass.C4
    )


# --- what is permitted -------------------------------------------------


def test_a_window_beginning_after_the_qualification_date_may_claim_it() -> None:
    """The other half of CM-S-009's second Then."""
    history = [
        qualification(
            ref="q-c4", assigned_class=DenominatorClass.C4, qualified_at=at(2026, 6, 1)
        ),
        qualification(
            ref="q-c1", assigned_class=DenominatorClass.C1, qualified_at=at(2026, 9, 1)
        ),
    ]
    assert (
        class_in_force(
            history, window_start=at(2026, 9, 2), window_end=at(2026, 10, 1)
        )
        is DenominatorClass.C1
    )
    assert_class_claimable(
        history,
        claimed=DenominatorClass.C1,
        window_start=at(2026, 9, 2),
        window_end=at(2026, 10, 1),
    )


def test_claiming_a_weaker_class_than_the_history_supports_is_permitted() -> None:
    """Understating the denominator class overclaims nothing.

    Refusing it would make the system insist on the strongest claim available,
    which is the opposite of the disposition this methodology is built on.
    """
    history = [
        qualification(
            ref="q-c1", assigned_class=DenominatorClass.C1, qualified_at=at(2026, 6, 1)
        )
    ]
    assert_class_claimable(
        history,
        claimed=DenominatorClass.C4,
        window_start=at(2026, 8, 1),
        window_end=at(2026, 9, 1),
    )


def test_a_window_that_does_not_advance_is_refused() -> None:
    history = [
        qualification(
            ref="q-c1", assigned_class=DenominatorClass.C1, qualified_at=at(2026, 6, 1)
        )
    ]
    with pytest.raises(ValueError, match="does not follow"):
        class_in_force(history, window_start=at(2026, 8, 1), window_end=at(2026, 8, 1))


# --- the §6 lattice, as data -------------------------------------------


@pytest.mark.parametrize(
    ("denominator_class", "level", "ratio"),
    [
        (DenominatorClass.C1, CoverageLevel.RECONCILED, True),
        (DenominatorClass.C2, CoverageLevel.RECONCILED, True),
        (DenominatorClass.C3, CoverageLevel.ENFORCED, True),
        (DenominatorClass.C4, CoverageLevel.OBSERVED, False),
        (DenominatorClass.C5, CoverageLevel.OBSERVED, False),
    ],
)
def test_the_admissibility_lattice_matches_the_methodology(
    denominator_class: DenominatorClass, level: CoverageLevel, ratio: bool
) -> None:
    """`coverage-methodology.md` §6, transcribed and checked against itself.

    This is the class-admissible input to CM-008, not CM-008. Taking the
    minimum with the evidence-supported level is EV-16's, and EV-16 should
    read these rather than write the table out a second time.
    """
    assert denominator_class.admissible_level is level
    assert denominator_class.emits_ratio is ratio


def test_the_class_order_is_strongest_first() -> None:
    """The ordering the Postgres enum and the resolver both depend on."""
    assert DenominatorClass.C1.is_stronger_than(DenominatorClass.C2)
    assert DenominatorClass.C4.is_stronger_than(DenominatorClass.C5)
    assert not DenominatorClass.C5.is_stronger_than(DenominatorClass.C1)
    assert not DenominatorClass.C3.is_stronger_than(DenominatorClass.C3)


def test_confirmation_capability_does_not_support_a_window_claim() -> None:
    """AC-008 at record level, both directions.

    The trap this guards is a connector reporting `confirm` and being read as
    reporting `enumerate`. A record with confirmation and no enumeration
    supports reconciling individual actions and no window-level ratio.
    """
    confirm_only = qualification(
        ref="q-confirm",
        assigned_class=DenominatorClass.C5,
        qualified_at=at(2026, 6, 1),
        enumeration_capable=False,
        confirmation_capable=True,
    )
    assert confirm_only.supports_window_coverage_claim is False

    enumerate_only = qualification(
        ref="q-enumerate",
        assigned_class=DenominatorClass.C1,
        qualified_at=at(2026, 6, 1),
        enumeration_capable=True,
        confirmation_capable=False,
    )
    assert enumerate_only.supports_window_coverage_claim is True
