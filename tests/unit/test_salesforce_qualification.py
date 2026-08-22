"""Adversarial tests for conditional-C1 permission revalidation."""

from __future__ import annotations

from datetime import UTC, datetime

from services.connectors.salesforce import (
    AuditFieldPermissionOutcome,
    SalesforcePermissionCheck,
    UnconfirmedInterval,
)


def at(hour: int) -> datetime:
    return datetime(2026, 8, 18, hour, tzinfo=UTC)


def test_permission_check_keeps_clean_granted_and_failed_as_three_states() -> None:
    clean = SalesforcePermissionCheck.confirmed_clean(checked_at=at(10))
    granted = SalesforcePermissionCheck.confirmed_granted(
        checked_at=at(11), last_confirmed_clean_at=at(10)
    )
    failed = SalesforcePermissionCheck.check_failed(
        checked_at=at(11),
        last_confirmed_clean_at=at(10),
        failure_code="salesforce_api_unavailable",
    )

    assert clean.outcome is AuditFieldPermissionOutcome.CONFIRMED_CLEAN
    assert granted.outcome is AuditFieldPermissionOutcome.CONFIRMED_GRANTED
    assert failed.outcome is AuditFieldPermissionOutcome.CHECK_FAILED
    assert clean.maximum_denominator_class == "C1"
    assert granted.maximum_denominator_class == "C5"
    assert failed.maximum_denominator_class is None


def test_detected_grant_retroactively_marks_since_last_clean_unconfirmed() -> None:
    result = SalesforcePermissionCheck.confirmed_granted(
        checked_at=at(11), last_confirmed_clean_at=at(10)
    )

    assert result.unconfirmed_interval == UnconfirmedInterval(at(10), at(11))
    assert result.requires_attestation_revisit is True
    # Mutation guard: a merely prospective downgrade would begin at detection.
    assert result.unconfirmed_interval.start != result.checked_at


def test_failed_check_has_the_same_retroactive_gap_without_claiming_a_grant() -> None:
    result = SalesforcePermissionCheck.check_failed(
        checked_at=at(11),
        last_confirmed_clean_at=at(10),
        failure_code="permission_query_forbidden",
    )

    assert result.outcome is AuditFieldPermissionOutcome.CHECK_FAILED
    assert result.unconfirmed_interval == UnconfirmedInterval(at(10), at(11))
    assert result.requires_attestation_revisit is True
    assert result.maximum_denominator_class is None
    assert result.failure_code == "permission_query_forbidden"


def test_initial_nonclean_check_refuses_c1_without_inventing_a_gap_start() -> None:
    granted = SalesforcePermissionCheck.confirmed_granted(checked_at=at(11))
    failed = SalesforcePermissionCheck.check_failed(
        checked_at=at(11), failure_code="permission_query_forbidden"
    )

    assert not granted.c1_eligible
    assert not failed.c1_eligible
    assert granted.unconfirmed_interval is None
    assert failed.unconfirmed_interval is None
