"""Negative-first tests for the EV-13 connector boundary and mock."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from sdk_python.evidence.canonical import canonical_digest
from sdk_python.evidence.chain import verify_evidence_stream
from sdk_python.evidence.schema import ClocksModel, PopulationRecord
from sdk_python.evidence.signing import sign_record, verify_record_signature
from services.connectors import (
    ActionReference,
    AttributionSurface,
    ConfirmationConnector,
    ConnectorCapabilities,
    ConnectorCapabilityError,
    ConnectorContractError,
    ConnectorScope,
    EnumerationConnector,
    EnumerationResponseMismatchError,
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
from services.ingestion.receipts import RegisteredPublicKey

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


class _FixedEnumerationConnector:
    def __init__(
        self,
        record: PopulationRecord,
        capabilities: ConnectorCapabilities,
    ) -> None:
        self.record = record
        self.reported_capabilities = capabilities
        self.capability_calls = 0

    def capabilities(self) -> ConnectorCapabilities:
        self.capability_calls += 1
        return self.reported_capabilities

    def enumerate(
        self, scope: ConnectorScope, window: EnumerationWindow
    ) -> PopulationRecord:
        return self.record


def _resign_population(
    record: PopulationRecord,
    key: Ed25519PrivateKey,
    *,
    body_updates: dict[str, object] | None = None,
    clocks: ClocksModel | None = None,
) -> PopulationRecord:
    body = record.body.model_copy(update=body_updates or {}, deep=True)
    unsigned = record.model_copy(
        update={"body": body, "clocks": clocks or record.clocks, "signature": {}},
        deep=True,
    )
    return sign_record(unsigned, key_id="mock-evidence-key", private_key=key)


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

    assert issubclass(SilentTruncationError, ConnectorCapabilityError)


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


def test_duplicate_identifiers_pass_the_gate_for_reconciliation_classification() -> None:
    """Duplicates are raw population evidence; EV-15 owns their classification."""

    connector, _ = _mock(MockConnectorConfig(duplicate_records=True))

    result = enumerate_for_window_coverage(connector, SCOPE, WINDOW)

    assert result.body.count == 3
    assert result.body.record_identifiers == ["ticket-1", "ticket-2", "ticket-1"]


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
    assert population.clocks.authoritative_time == "2026-08-11T12:00:00.000Z"
    assert confirmation.clocks.authoritative_time == "2026-08-11T11:58:00.000Z"


def test_mock_records_form_a_valid_es_006a_stream() -> None:
    connector, key = _mock()
    population = enumerate_for_window_coverage(connector, SCOPE, WINDOW)
    confirmation = require_confirmer(connector).confirm(
        ActionReference("action-1", "ticket-1")
    )

    assert confirmation.prev_digest == canonical_digest(population)
    result = verify_evidence_stream(
        [population, confirmation],
        verification_keys={
            "mock-evidence-key": RegisteredPublicKey(
                namespace="evidence", public_key=key.public_key()
            )
        },
    )

    assert result.end_sequence == 2


@pytest.mark.parametrize(
    ("body_updates", "field"),
    [
        ({"action_family": "unrelated.family"}, "action_family"),
        ({"destination_system": "some-other-system"}, "destination_system"),
        ({"window_start": "2020-01-01T00:00:00.000Z"}, "window_start"),
        ({"window_end": "2020-01-01T00:01:00.000Z"}, "window_end"),
        (
            {
                "enumeration_query": {
                    "scope": {"actor": "someone-else"},
                    "window_start": "2026-08-11T11:00:00.000Z",
                    "window_end": "2026-08-11T13:00:00.000Z",
                }
            },
            "enumeration_query.scope",
        ),
    ],
)
def test_gate_rejects_population_that_does_not_match_its_request(
    body_updates: dict[str, object], field: str
) -> None:
    connector, key = _mock()
    original = require_window_enumerator(connector).enumerate(SCOPE, WINDOW)
    mismatched = _resign_population(original, key, body_updates=body_updates)
    fixed = _FixedEnumerationConnector(mismatched, connector.capabilities())

    with pytest.raises(EnumerationResponseMismatchError, match=field) as refusal:
        enumerate_for_window_coverage(fixed, SCOPE, WINDOW)

    assert refusal.value.population_record is mismatched


def test_gate_rejects_count_that_disagrees_with_inline_identifiers() -> None:
    connector, key = _mock()
    original = require_window_enumerator(connector).enumerate(SCOPE, WINDOW)
    mismatched = _resign_population(original, key, body_updates={"count": 5_000})
    fixed = _FixedEnumerationConnector(mismatched, connector.capabilities())

    with pytest.raises(EnumerationResponseMismatchError, match="count"):
        enumerate_for_window_coverage(fixed, SCOPE, WINDOW)


def test_gate_requires_declared_and_emitted_authoritative_time() -> None:
    unavailable, _ = _mock(MockConnectorConfig(authoritative_time=False))
    raw = require_window_enumerator(unavailable).enumerate(SCOPE, WINDOW)
    assert raw.clocks.authoritative_time is None
    assert raw.body.authoritative_timestamps == {"min": None, "max": None}
    with pytest.raises(WindowCoverageUnavailableError, match="authoritative time"):
        enumerate_for_window_coverage(unavailable, SCOPE, WINDOW)

    connector, key = _mock()
    original = require_window_enumerator(connector).enumerate(SCOPE, WINDOW)
    missing_clock = _resign_population(
        original,
        key,
        clocks=ClocksModel(source_time=original.clocks.source_time),
    )
    fixed = _FixedEnumerationConnector(missing_clock, connector.capabilities())
    with pytest.raises(EnumerationResponseMismatchError, match="omitted"):
        enumerate_for_window_coverage(fixed, SCOPE, WINDOW)


def test_gate_uses_one_capability_snapshot() -> None:
    connector, _ = _mock()
    record = require_window_enumerator(connector).enumerate(SCOPE, WINDOW)
    fixed = _FixedEnumerationConnector(record, connector.capabilities())

    assert enumerate_for_window_coverage(fixed, SCOPE, WINDOW) is record
    assert fixed.capability_calls == 1


def test_empty_but_exactly_bound_enumeration_is_a_valid_zero_denominator() -> None:
    key = Ed25519PrivateKey.generate()
    connector = create_mock_connector(
        records=(), private_key=key, retrieved_at=NOW
    )

    result = enumerate_for_window_coverage(connector, SCOPE, WINDOW)

    assert result.body.count == 0
    assert result.body.record_identifiers == []
    assert result.body.authoritative_timestamps == {"min": None, "max": None}
    assert result.clocks.authoritative_time is not None


def test_scope_parameters_are_deeply_immutable_hashable_and_json_compatible() -> None:
    scope = ConnectorScope(
        "ticket.resolve",
        "mock-destination",
        {"actor": "agent", "filters": [{"state": "closed"}]},
    )

    assert json.loads(json.dumps(scope.parameters)) == {
        "actor": "agent",
        "filters": [{"state": "closed"}],
    }
    assert isinstance(hash(scope), int)
    with pytest.raises(TypeError, match="immutable"):
        scope.parameters["actor"] = "human"  # type: ignore[index]
    filters = scope.parameters["filters"]
    assert isinstance(filters, list)
    with pytest.raises(TypeError, match="immutable"):
        filters.append("unsafe")


def test_fixed_retrieval_time_does_not_create_record_id_collisions() -> None:
    first, _ = _mock()
    second, _ = _mock()

    first_record = require_window_enumerator(first).enumerate(SCOPE, WINDOW)
    second_record = require_window_enumerator(second).enumerate(SCOPE, WINDOW)

    assert first_record.record_id != second_record.record_id


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
