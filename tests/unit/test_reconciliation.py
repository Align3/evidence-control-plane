"""Negative-first unit coverage for EV-15 reconciliation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from sdk_python.evidence.schema import PopulationRecord
from services.computation.reconciliation import (
    PopulationIdentifierDigestUnsupportedError,
    PopulationIntegrityError,
    ReconciliationStatus,
    reconcile,
)
from services.connectors import (
    ConnectorScope,
    EnumerationWindow,
    MockConnectorConfig,
    MockDestinationRecord,
    create_mock_connector,
    require_window_enumerator,
)
from tests.reconciliation_support import confirmation, digest, population, proposal, receipt


def test_status_vocabulary_is_exactly_the_closed_es_015_set() -> None:
    assert {status.value for status in ReconciliationStatus} == {
        "matched",
        "unmatched_with_evidence",
        "unmatched_without_evidence",
        "duplicate",
        "ambiguous",
        "out_of_scope",
    }


def test_missing_execution_identity_is_not_imputed_from_nearby_evidence() -> None:
    results = reconcile(
        population(["destination-100"]),
        (proposal("action-1"), receipt("action-1", "destination-101")),
        (confirmation("action-1", "destination-101"),),
    )

    assert [result.status for result in results] == ["unmatched_without_evidence"]


def test_execution_without_unique_confirmation_is_unmatched_with_evidence() -> None:
    results = reconcile(
        population(["destination-1"]),
        (proposal("action-1"), receipt("action-1", "destination-1")),
        (),
    )

    assert [result.status for result in results] == ["unmatched_with_evidence"]


def test_multiple_confirmations_are_ambiguous_before_unmatched() -> None:
    results = reconcile(
        population(["destination-1"]),
        (proposal("action-1"), receipt("action-1", "destination-1")),
        (
            confirmation("action-1", "destination-1", serial=30),
            confirmation("action-1", "destination-1", serial=31),
        ),
    )

    assert [result.status for result in results] == ["ambiguous"]
    assert results[0].confirmation_record_id is None


def test_one_action_linked_to_two_population_entries_is_ambiguous_on_both_sides() -> None:
    results = reconcile(
        population(["destination-1", "destination-2"]),
        (
            proposal("action-1"),
            receipt("action-1", "destination-1", serial=20),
            receipt("action-1", "destination-2", serial=21),
        ),
        (
            confirmation("action-1", "destination-1", serial=30),
            confirmation("action-1", "destination-2", serial=31),
        ),
    )

    assert [result.status for result in results] == ["ambiguous", "ambiguous"]


def test_scope_mismatch_is_out_of_scope_not_unmatched() -> None:
    family_results = reconcile(
        population(["destination-1"]),
        (proposal("action-1", family="ticket.resolve"), receipt("action-1", "destination-1")),
        (confirmation("action-1", "destination-1"),),
    )
    destination_results = reconcile(
        population(["destination-1"]),
        (proposal("action-1"), receipt("action-1", "destination-1")),
        (confirmation("action-1", "destination-1", destination_system="crm"),),
    )

    assert [result.status for result in family_results] == ["out_of_scope"]
    assert [result.status for result in destination_results] == ["out_of_scope"]


def test_missing_proposal_cannot_be_promoted_to_matched() -> None:
    results = reconcile(
        population(["destination-1"]),
        (receipt("action-1", "destination-1"),),
        (confirmation("action-1", "destination-1"),),
    )

    assert [result.status for result in results] == ["unmatched_with_evidence"]


def test_distinct_identifiers_with_identical_content_are_both_duplicate() -> None:
    same_digest = digest("d")
    results = reconcile(
        population(["destination-1", "destination-2"]),
        (
            proposal("action-1", serial=10),
            receipt("action-1", "destination-1", serial=20),
            proposal("action-2", serial=11),
            receipt("action-2", "destination-2", serial=21),
        ),
        (
            confirmation("action-1", "destination-1", digest=same_digest, serial=30),
            confirmation("action-2", "destination-2", digest=same_digest, serial=31),
        ),
    )

    assert [result.destination_record_id for result in results] == [
        "destination-1",
        "destination-2",
    ]
    assert [result.status for result in results] == ["duplicate", "duplicate"]


def test_repeated_identifier_is_a_named_population_integrity_refusal() -> None:
    with pytest.raises(PopulationIntegrityError, match="repeated identifier"):
        reconcile(population(["destination-1", "destination-1"]), (), ())


def test_digest_only_population_refuses_per_record_classification() -> None:
    with pytest.raises(
        PopulationIdentifierDigestUnsupportedError,
        match="identifier_digest",
    ):
        reconcile(population(None, count=1), (), ())


def test_count_mismatch_is_refused_instead_of_reinterpreted() -> None:
    with pytest.raises(PopulationIntegrityError, match="count"):
        reconcile(population(["destination-1"], count=2), (), ())


def test_inputs_are_not_mutated_and_replay_order_is_stable() -> None:
    pop = population(["destination-2", "destination-1"])
    evidence = (
        proposal("action-1", serial=10),
        receipt("action-1", "destination-1", serial=20),
    )
    confirmations = (confirmation("action-1", "destination-1"),)
    before = (
        pop.model_dump(mode="json"),
        tuple(record.model_dump(mode="json") for record in evidence),
        tuple(record.model_dump(mode="json") for record in confirmations),
    )

    first = reconcile(pop, evidence, confirmations)
    second = reconcile(pop, evidence, confirmations)

    assert first == second
    assert [result.destination_record_id for result in first] == [
        "destination-2",
        "destination-1",
    ]
    assert before == (
        pop.model_dump(mode="json"),
        tuple(record.model_dump(mode="json") for record in evidence),
        tuple(record.model_dump(mode="json") for record in confirmations),
    )


def _population_from_mock(config: MockConnectorConfig) -> PopulationRecord:
    now = datetime(2026, 8, 11, 12, tzinfo=UTC)
    connector = create_mock_connector(
        config=config,
        records=(
            MockDestinationRecord(
                record_id="destination-1",
                action_id="action-1",
                action_family="refund.issue",
                authoritative_timestamp=now - timedelta(minutes=1),
            ),
        ),
        destination_system="payments",
        retrieved_at=now,
    )
    observation = require_window_enumerator(connector).enumerate(
        ConnectorScope("refund.issue", "payments"),
        EnumerationWindow(now - timedelta(hours=1), now),
    )
    template = population(["destination-1"])
    return template.model_copy(
        update={"body": observation.body, "clocks": observation.clocks}, deep=True
    )


@pytest.mark.parametrize(
    "config",
    [
        MockConnectorConfig(result_cap_hit=True),
        MockConnectorConfig(pagination_complete=False),
        MockConnectorConfig(
            settlement_lag=timedelta(minutes=1),
            observed_settlement_lag=timedelta(minutes=2),
        ),
    ],
)
def test_ev_13_unusable_flags_are_preserved_but_not_reinterpreted_by_ev_15(
    config: MockConnectorConfig,
) -> None:
    pop = _population_from_mock(config)

    results = reconcile(pop, (), ())

    assert [result.status for result in results] == ["unmatched_without_evidence"]
    assert pop.body.result_cap_hit is config.result_cap_hit
    assert pop.body.pagination_complete is config.pagination_complete


def test_ev_13_repeated_identifier_mock_exposes_population_integrity_defect() -> None:
    pop = _population_from_mock(MockConnectorConfig(duplicate_records=True))

    with pytest.raises(PopulationIntegrityError, match="repeated identifier"):
        reconcile(pop, (), ())
