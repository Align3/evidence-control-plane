"""Negative-first tests for the EV-13 connector boundary and mock."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from sdk_python.evidence.signing import verify_record_signature
from services.connectors import (
    ActionReference,
    AttributionSurface,
    ConfirmationConnector,
    ConnectorCapabilities,
    ConnectorContractError,
    ConnectorScope,
    EnumerationConnector,
    EnumerationUnusableError,
    EnumerationWindow,
    MockConnectorConfig,
    MockDestinationRecord,
    SettlementLagExceededError,
    SilentTruncationError,
    WindowCoverageUnavailableError,
    create_mock_connector,
    enumerate_for_window_coverage,
    require_confirmer,
    require_window_enumerator,
)

NOW = datetime(2026, 8, 11, 12, tzinfo=UTC)
WINDOW = EnumerationWindow(NOW - timedelta(hours=1), NOW + timedelta(hours=1))
SCOPE = ConnectorScope("ticket.resolve", "mock-destination")


def _records() -> tuple[MockDestinationRecord, ...]:
    return (
        MockDestinationRecord(
            record_id="ticket-1",
            action_id="action-1",
            action_family="ticket.resolve",
            authoritative_timestamp=NOW - timedelta(minutes=2),
            actor_attribute="agent-credential",
        ),
        MockDestinationRecord(
            record_id="ticket-2",
            action_id="action-2",
            action_family="ticket.resolve",
            authoritative_timestamp=NOW - timedelta(minutes=1),
            actor_attribute="agent-credential",
        ),
    )


def _mock(config: MockConnectorConfig | None = None):
    key = Ed25519PrivateKey.generate()
    connector = create_mock_connector(
        config=config,
        records=_records(),
        private_key=key,
        retrieved_at=NOW,
    )
    return connector, key


def test_confirmation_only_is_structurally_not_an_enumerator() -> None:
    connector, _ = _mock(
        MockConnectorConfig(
            enumeration=False,
            confirmation=True,
            attribution_surface=AttributionSurface.ENUMERATION_UNAVAILABLE,
        )
    )

    assert isinstance(connector, ConfirmationConnector)
    assert not isinstance(connector, EnumerationConnector)
    with pytest.raises(WindowCoverageUnavailableError):
        require_window_enumerator(connector)

    confirmation = require_confirmer(connector).confirm(
        ActionReference("action-1", "ticket-1")
    )
    assert confirmation.body.reconciliation_status == "matched"


class _LyingConnector:
    def capabilities(self) -> ConnectorCapabilities:
        return ConnectorCapabilities(
            enumeration=True,
            confirmation=False,
            authoritative_time=True,
            settlement_lag=timedelta(0),
            attribution_surface=AttributionSurface.RECORD_FIELD,
        )


def test_capability_boolean_cannot_unlock_a_missing_method() -> None:
    with pytest.raises(ConnectorContractError, match="does not implement enumerate"):
        require_window_enumerator(_LyingConnector())


@pytest.mark.parametrize(
    "attribution_surface",
    [
        AttributionSurface.CALLER_SETTABLE_FIELD,
        AttributionSurface.SEPARATE_SOURCE,
        AttributionSurface.NOT_RECORDED,
    ],
)
def test_capabilities_preserve_distinct_attribution_failure_shapes(
    attribution_surface: AttributionSurface,
) -> None:
    connector, _ = _mock(MockConnectorConfig(attribution_surface=attribution_surface))
    assert connector.capabilities().attribution_surface is attribution_surface
    # There is intentionally no "identity_isolated" connector capability.
    assert not hasattr(connector.capabilities(), "identity_isolated")


@pytest.mark.parametrize(
    ("config", "message"),
    [
        (MockConnectorConfig(result_cap_hit=True), "result cap was hit"),
        (
            MockConnectorConfig(pagination_complete=False),
            "pagination is incomplete",
        ),
    ],
)
def test_explicit_truncation_flags_make_enumeration_unusable(
    config: MockConnectorConfig, message: str
) -> None:
    connector, _ = _mock(config)

    with pytest.raises(EnumerationUnusableError, match=message) as refusal:
        enumerate_for_window_coverage(connector, SCOPE, WINDOW)

    rejected = refusal.value.population_record
    assert rejected.body.result_cap_hit is config.result_cap_hit
    assert rejected.body.pagination_complete is config.pagination_complete


def test_remote_silent_truncation_is_turned_into_a_loud_failure() -> None:
    connector, _ = _mock(MockConnectorConfig(silent_truncate_to=1))

    with pytest.raises(SilentTruncationError, match="silently truncated 2 records to 1"):
        require_window_enumerator(connector).enumerate(SCOPE, WINDOW)


def test_duplicates_and_missing_actor_attribution_are_returned_as_evidence() -> None:
    connector, key = _mock(
        MockConnectorConfig(duplicate_records=True, unattributable_records=True)
    )

    result = require_window_enumerator(connector).enumerate(SCOPE, WINDOW)

    assert result.body.record_identifiers == ["ticket-1", "ticket-2", "ticket-1"]
    assert result.body.count == 3
    observations = result.body.model_extra["attribution_observations"]
    assert isinstance(observations, list)
    assert all(observation["actor_attribute"] is None for observation in observations)
    assert verify_record_signature(
        result, public_keys={"mock-evidence-key": key.public_key()}
    ) == "mock-evidence-key"


def test_settlement_lag_beyond_declared_bound_is_reported_and_refused() -> None:
    connector, _ = _mock(
        MockConnectorConfig(
            settlement_lag=timedelta(minutes=5),
            observed_settlement_lag=timedelta(minutes=6),
        )
    )

    with pytest.raises(SettlementLagExceededError) as refusal:
        enumerate_for_window_coverage(connector, SCOPE, WINDOW)

    assert (
        refusal.value.population_record.body.model_extra["observed_settlement_lag_ms"]
        == 360_000
    )


def test_mock_returns_signed_population_and_confirmation_evidence() -> None:
    connector, key = _mock()
    public_keys = {"mock-evidence-key": key.public_key()}

    population = enumerate_for_window_coverage(connector, SCOPE, WINDOW)
    confirmation = require_confirmer(connector).confirm(
        ActionReference("action-1", "ticket-1")
    )

    assert population.record_type == "PopulationRecord"
    assert confirmation.record_type == "ExternalConfirmation"
    assert verify_record_signature(population, public_keys=public_keys)
    assert verify_record_signature(confirmation, public_keys=public_keys)
    assert confirmation.body.authoritative_timestamp == "2026-08-11T11:58:00.000Z"


def test_mock_cannot_escape_the_closed_confirmation_status_enumeration() -> None:
    bad_record = MockDestinationRecord(
        record_id="ticket-1",
        action_id="action-1",
        action_family="ticket.resolve",
        authoritative_timestamp=NOW,
        reconciliation_status="other",  # type: ignore[arg-type]
    )
    connector = create_mock_connector(records=(bad_record,), retrieved_at=NOW)

    with pytest.raises(ValidationError, match="reconciliation_status"):
        require_confirmer(connector).confirm(ActionReference("action-1", "ticket-1"))


def test_enumeration_capability_metadata_rejects_impossible_combinations() -> None:
    with pytest.raises(ValueError, match="settlement_lag requires enumeration"):
        ConnectorCapabilities(
            enumeration=False,
            confirmation=True,
            authoritative_time=True,
            settlement_lag=timedelta(seconds=1),
            attribution_surface=AttributionSurface.ENUMERATION_UNAVAILABLE,
        )
