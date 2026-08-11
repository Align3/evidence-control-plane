"""CM-S-009 -- Denominator class cannot be upgraded retroactively (CM-004).

    Given window W was recorded under denominator class C4
    When the connector is later upgraded to support enumeration at class C1
    Then attestations for W remain capped at the C4 admissible level
    And only windows beginning after the qualification date may claim C1

How far this goes, and where it stops
-------------------------------------
Every step below runs against a real database and real signed records. The
qualification history is built through `record_qualification`, and the class
governing W is resolved by `class_in_force`, not by reading a value the test
put there.

It stops short of QA-003 in one respect, disclosed rather than glossed:
QA-003 requires acceptance tests to assert **through the verifier**, and the
Go verifier is a stub (EV-05 is unlanded). The third step's "attestations for
W remain capped at the C4 admissible level" is therefore asserted as the class
in force for W together with the `coverage-methodology.md` §6 lattice entry
that caps it -- the two inputs an attestation's cap is computed from -- rather
than by rendering an attestation, which EV-17 has not been built to do.

So this binding demonstrates CM-004 and does not, on its own, close CM-S-009
as an acceptance scenario. What remains is the verifier's independent
enforcement, which is TM-013's actual requirement and TM-S-005's subject; both
belong to EV-19. See the story's disclosure notes.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from pytest_bdd import given, scenario, then, when
from sqlalchemy import Engine

from services.admin import (
    DenominatorClass,
    assert_class_claimable,
    class_in_force,
    qualification_history,
)
from services.admin.qualification import (
    ClassNotQualifiedError,
    QualificationPostdatesWindowError,
)
from tests.admin_support import AdminActor
from tests.ledger_support import TENANT_A

FAMILY = "cm.s.009.refund.issue"
DESTINATION = "payments-core"

#: The dates in TM-S-005, reused here so the two scenarios exercise one
#: timeline rather than two that happen to agree.
C4_QUALIFIED_AT = datetime(2026, 7, 1, tzinfo=UTC)
WINDOW_START = datetime(2026, 8, 1, tzinfo=UTC)
WINDOW_END = datetime(2026, 9, 1, tzinfo=UTC)
C1_QUALIFIED_AT = datetime(2026, 9, 1, tzinfo=UTC)


@scenario(
    "coverage.feature", "CM-S-009 Denominator class cannot be upgraded retroactively"
)
def test_cm_s_009() -> None:
    """Bound by pytest-bdd."""


@given("window W was recorded under denominator class C4", target_fixture="context")
def _window_recorded_at_c4(
    owner_engine: Engine,
    admin_actors: dict[str, AdminActor],
    default_boundaries: dict[str, str],
) -> Any:
    """A C4 qualification in force before W begins.

    C4 is sequence-derived: our own collector's monotonic sequence, with no
    enumerable population behind it, so the record declares no enumeration
    capability. That is what makes the later upgrade an upgrade.
    """
    actor = admin_actors[TENANT_A]
    connection = owner_engine.connect()
    transaction = connection.begin()
    actor.write_qualification(
        connection,
        action_family=FAMILY,
        destination_system=DESTINATION,
        assigned_class="C4",
        qualified_at=C4_QUALIFIED_AT,
        enumeration_capable=False,
    )
    context = {
        "actor": actor,
        "connection": connection,
        "transaction": transaction,
    }
    history = qualification_history(
        connection,
        tenant_id=TENANT_A,
        action_family=FAMILY,
        destination_system=DESTINATION,
    )
    assert (
        class_in_force(history, window_start=WINDOW_START, window_end=WINDOW_END)
        is DenominatorClass.C4
    ), "the premise failed: W was not recorded under C4"
    yield context
    transaction.rollback()
    connection.close()


@when("the connector is later upgraded to support enumeration at class C1")
def _connector_upgraded(context: dict[str, Any]) -> None:
    """A new record, not an amendment -- ES-010 permits nothing else.

    Dated after W began, which is the whole difficulty: the connector really
    can enumerate now, and the temptation is to let that reach backwards.
    """
    actor: AdminActor = context["actor"]
    context["c1_ref"] = actor.write_qualification(
        context["connection"],
        action_family=FAMILY,
        destination_system=DESTINATION,
        assigned_class="C1",
        qualified_at=C1_QUALIFIED_AT,
        enumeration_capable=True,
    )
    context["history"] = qualification_history(
        context["connection"],
        tenant_id=TENANT_A,
        action_family=FAMILY,
        destination_system=DESTINATION,
    )
    assert len(context["history"]) == 2, (
        "the upgrade must be a second record; amending the first is refused by "
        "the database and would not exercise this scenario"
    )


@then("attestations for W remain capped at the C4 admissible level")
def _window_remains_capped(context: dict[str, Any]) -> None:
    in_force = class_in_force(
        context["history"], window_start=WINDOW_START, window_end=WINDOW_END
    )
    assert in_force is DenominatorClass.C4

    # The cap itself: `coverage-methodology.md` §6. C4 admits `observed` and
    # emits no ratio, so an attestation over W can claim neither `reconciled`
    # nor a coverage percentage however complete the evidence inside it is.
    assert in_force.admissible_level.value == "observed"
    assert in_force.emits_ratio is False

    with pytest.raises(
        (QualificationPostdatesWindowError, ClassNotQualifiedError)
    ) as caught:
        assert_class_claimable(
            context["history"],
            claimed=DenominatorClass.C1,
            window_start=WINDOW_START,
            window_end=WINDOW_END,
        )
    assert "qualification postdates window" in str(caught.value)


@then("only windows beginning after the qualification date may claim C1")
def _only_later_windows_may_claim_c1(context: dict[str, Any]) -> None:
    """Both sides of "after", including the instant itself.

    A window beginning exactly at the qualification date has not begun
    *after* it, so it stays at C4. Stated here because the generous reading of
    that boundary is how the rule erodes.
    """
    history = context["history"]

    at_the_instant = class_in_force(
        history, window_start=C1_QUALIFIED_AT, window_end=datetime(2026, 10, 1, tzinfo=UTC)
    )
    assert at_the_instant is DenominatorClass.C4

    later = datetime(2026, 9, 2, tzinfo=UTC)
    assert (
        class_in_force(
            history, window_start=later, window_end=datetime(2026, 10, 1, tzinfo=UTC)
        )
        is DenominatorClass.C1
    )
    assert_class_claimable(
        history,
        claimed=DenominatorClass.C1,
        window_start=later,
        window_end=datetime(2026, 10, 1, tzinfo=UTC),
    )
