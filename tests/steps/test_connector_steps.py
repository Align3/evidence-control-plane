"""Acceptance steps for EV-13's independent connector capabilities."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pytest_bdd import given, scenario, then, when

from services.connectors import (
    ActionReference,
    AttributionSurface,
    MockConnectorConfig,
    MockDestinationRecord,
    WindowCoverageUnavailableError,
    create_mock_connector,
    require_confirmer,
    require_window_enumerator,
)


@scenario("architecture.feature", "AC-S-003 Confirmation-only connector blocks coverage")
def test_ac_s_003_confirmation_only_connector_blocks_coverage() -> None:
    """Confirmation remains usable without creating a denominator claim."""


@given(
    "a connector reporting capabilities {enumeration: false, confirmation: true}",
    target_fixture="connector_context",
)
def confirmation_only_connector() -> dict[str, object]:
    record = MockDestinationRecord(
        record_id="ticket-1",
        action_id="action-1",
        action_family="ticket.resolve",
        authoritative_timestamp=datetime(2026, 8, 10, 9, tzinfo=UTC),
    )
    connector = create_mock_connector(
        config=MockConnectorConfig(
            enumeration=False,
            confirmation=True,
            attribution_surface=AttributionSurface.ENUMERATION_UNAVAILABLE,
        ),
        records=(record,),
        retrieved_at=datetime(2026, 8, 10, 10, tzinfo=UTC),
    )
    capabilities = connector.capabilities()
    assert capabilities.enumeration is False
    assert capabilities.confirmation is True
    return {"connector": connector, "record": record}


@when("a window-level coverage claim is requested")
def request_window_coverage(connector_context: dict[str, object]) -> None:
    connector = connector_context["connector"]
    with pytest.raises(WindowCoverageUnavailableError) as refusal:
        require_window_enumerator(connector)  # type: ignore[arg-type]
    connector_context["coverage_refusal"] = refusal.value


@then("the coverage engine refuses")
def coverage_is_refused(connector_context: dict[str, object]) -> None:
    assert isinstance(
        connector_context.get("coverage_refusal"), WindowCoverageUnavailableError
    )


@then("per-action reconciliation results remain available")
def per_action_confirmation_remains_available(
    connector_context: dict[str, object],
) -> None:
    connector = connector_context["connector"]
    record = connector_context["record"]
    assert isinstance(record, MockDestinationRecord)
    confirmer = require_confirmer(connector)  # type: ignore[arg-type]
    confirmation = confirmer.confirm(
        ActionReference(
            action_id=record.action_id,
            destination_record_id=record.record_id,
        )
    )
    assert confirmation.body.reconciliation_status == "matched"
