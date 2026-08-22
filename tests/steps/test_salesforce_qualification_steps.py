"""Acceptance bindings for EV-42's conditional qualification rulings."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from pytest_bdd import given, parsers, scenario, then, when

from services.admin.qualification import add_iso8601_duration
from services.connectors.salesforce import (
    AuditFieldPermissionOutcome,
    SalesforcePermissionCheck,
    UnconfirmedInterval,
)

T1 = datetime(2026, 8, 18, 10, tzinfo=UTC)
T2 = datetime(2026, 8, 18, 11, tzinfo=UTC)


@scenario(
    "coverage.feature",
    "CM-S-012 Conditional qualification failure is retroactive to the last clean check",
)
def test_cm_s_012_permission_grant_is_retroactive() -> None:
    """A poll detects a gap whose start is the previous clean observation."""


@scenario("coverage.feature", "CM-S-013 A failed qualification check remains unknown")
def test_cm_s_013_failed_permission_check_is_unknown() -> None:
    """Transport uncertainty is not relabelled as a definite permission state."""


@scenario("evidence.feature", "ES-S-026 Qualification cadence uses one ISO 8601 grammar")
def test_es_s_026_iso_duration_grammar() -> None:
    """Date-only and time-only cadence forms reach one parser."""


@given(
    "the Salesforce audit-field permission was confirmed clean at T1",
    target_fixture="permission_context",
)
def permission_clean_at_t1() -> dict[str, object]:
    return {"clean": SalesforcePermissionCheck.confirmed_clean(checked_at=T1)}


@given("the permission is confirmed granted at T2")
def permission_granted_at_t2(permission_context: dict[str, object]) -> None:
    permission_context["next_outcome"] = AuditFieldPermissionOutcome.CONFIRMED_GRANTED


@given("the permission query fails at T2")
def permission_query_fails_at_t2(permission_context: dict[str, object]) -> None:
    permission_context["next_outcome"] = AuditFieldPermissionOutcome.CHECK_FAILED


@when("conditional denominator qualification is revalidated")
def revalidate_permission(permission_context: dict[str, object]) -> None:
    clean = permission_context["clean"]
    assert isinstance(clean, SalesforcePermissionCheck)
    if permission_context["next_outcome"] is AuditFieldPermissionOutcome.CONFIRMED_GRANTED:
        result = SalesforcePermissionCheck.confirmed_granted(
            checked_at=T2, last_confirmed_clean_at=clean.checked_at
        )
    else:
        result = SalesforcePermissionCheck.check_failed(
            checked_at=T2,
            last_confirmed_clean_at=clean.checked_at,
            failure_code="permission_query_unavailable",
        )
    permission_context["result"] = result


@then(parsers.parse('the outcome is "{outcome}"'))
def outcome_is(permission_context: dict[str, object], outcome: str) -> None:
    result = permission_context["result"]
    assert isinstance(result, SalesforcePermissionCheck)
    assert result.outcome.value == outcome


@then(parsers.parse('it is not reported as "{outcome}"'))
def outcome_is_not(permission_context: dict[str, object], outcome: str) -> None:
    result = permission_context["result"]
    assert isinstance(result, SalesforcePermissionCheck)
    assert result.outcome.value != outcome


@then("the full interval T1 through T2 is marked unknown")
def full_interval_is_unknown(permission_context: dict[str, object]) -> None:
    result = permission_context["result"]
    assert isinstance(result, SalesforcePermissionCheck)
    assert result.unconfirmed_interval == UnconfirmedInterval(T1, T2)


@then(
    "an issued attestation overlapping that interval requires revocation or "
    "supersession review"
)
def issued_attestation_requires_review(permission_context: dict[str, object]) -> None:
    result = permission_context["result"]
    assert isinstance(result, SalesforcePermissionCheck)
    assert result.requires_attestation_revisit


@then("the unknown interval does not begin merely at T2")
def interval_is_not_prospective_only(permission_context: dict[str, object]) -> None:
    result = permission_context["result"]
    assert isinstance(result, SalesforcePermissionCheck)
    interval = result.unconfirmed_interval
    assert interval is not None
    assert interval.start == T1
    assert interval.start != result.checked_at


@given(
    "two QualificationRecords qualified at the same instant",
    target_fixture="duration_context",
)
def qualifications_at_same_instant() -> dict[str, object]:
    return {"qualified_at": T1}


@given('their revalidation cadences are "PT1H" and "P1D"')
def two_cadence_forms(duration_context: dict[str, object]) -> None:
    duration_context["cadences"] = ("PT1H", "P1D")


@when("each revalidation deadline is derived")
def derive_deadlines(duration_context: dict[str, object]) -> None:
    qualified_at = duration_context["qualified_at"]
    cadences = duration_context["cadences"]
    assert isinstance(qualified_at, datetime)
    assert isinstance(cadences, tuple)
    duration_context["deadlines"] = tuple(
        add_iso8601_duration(
            qualified_at, cadence, label="revalidation_cadence"
        )
        for cadence in cadences
    )


@then("the first deadline is exactly one hour after qualification")
def hourly_deadline(duration_context: dict[str, object]) -> None:
    deadlines = duration_context["deadlines"]
    assert isinstance(deadlines, tuple)
    assert deadlines[0] == T1 + timedelta(hours=1)


@then("the second deadline is exactly one day after qualification")
def daily_deadline(duration_context: dict[str, object]) -> None:
    deadlines = duration_context["deadlines"]
    assert isinstance(deadlines, tuple)
    assert deadlines[1] == T1 + timedelta(days=1)


@then("neither cadence is rejected by a unit-specific parser")
def both_cadences_share_parser(duration_context: dict[str, object]) -> None:
    deadlines = duration_context["deadlines"]
    assert isinstance(deadlines, tuple)
    assert len(deadlines) == 2
