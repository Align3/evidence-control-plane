"""Pure, exact-identity reconciliation for EV-15.

The function in this module deliberately has no persistence dependency and no
clock.  A caller may materialise its immutable results in a rebuildable table,
but classification itself is a value transformation over signed inputs.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum

from sdk_python.evidence.schema import (
    ActionProposalRecord,
    EvidenceRecord,
    ExecutionReceiptRecord,
    ExternalConfirmationRecord,
    PopulationRecord,
)

COMPUTATION_VERSION = "0.1.0"


class ReconciliationStatus(StrEnum):
    """The closed CM-012 / ES-015 classification set."""

    MATCHED = "matched"
    UNMATCHED_WITH_EVIDENCE = "unmatched_with_evidence"
    UNMATCHED_WITHOUT_EVIDENCE = "unmatched_without_evidence"
    DUPLICATE = "duplicate"
    AMBIGUOUS = "ambiguous"
    OUT_OF_SCOPE = "out_of_scope"


@dataclass(frozen=True, slots=True)
class ReconciliationResult:
    """One immutable result for one explicit denominator identifier."""

    population_ref: str
    destination_record_id: str
    status: ReconciliationStatus
    action_id: str | None
    confirmation_record_id: str | None
    computation_version: str = COMPUTATION_VERSION


class ReconciliationError(ValueError):
    """An input cannot be classified without violating the methodology."""

    def __init__(self, population_ref: str, message: str) -> None:
        super().__init__(f"population {population_ref}: {message}")
        self.population_ref = population_ref


class PopulationIntegrityError(ReconciliationError):
    """The inline denominator violates a per-record classification invariant."""


class PopulationIdentifierDigestUnsupportedError(ReconciliationError):
    """A digest-only population cannot expose the identities EV-15 classifies."""


class ReconciliationInvariantError(RuntimeError):
    """The explicit decision matrix failed to classify a validated identifier."""


@dataclass(frozen=True, slots=True)
class _Indexes:
    proposals_by_action: Mapping[str, tuple[ActionProposalRecord, ...]]
    receipts_by_destination: Mapping[str, tuple[ExecutionReceiptRecord, ...]]
    confirmations_by_destination: Mapping[
        str, tuple[ExternalConfirmationRecord, ...]
    ]
    receipt_destinations_by_action: Mapping[str, frozenset[str]]


def _accepted_identifiers(population: PopulationRecord) -> tuple[str, ...]:
    identifiers = population.body.record_identifiers
    if identifiers is None:
        raise PopulationIdentifierDigestUnsupportedError(
            population.record_id,
            "identifier_digest cannot support per-record reconciliation",
        )
    if population.body.count != len(identifiers):
        raise PopulationIntegrityError(
            population.record_id,
            "signed count does not equal the number of inline record_identifiers",
        )
    if any(not identifier for identifier in identifiers):
        raise PopulationIntegrityError(
            population.record_id,
            "record_identifiers contains an empty stable identity",
        )
    if len(set(identifiers)) != len(identifiers):
        raise PopulationIntegrityError(
            population.record_id,
            "record_identifiers contains a repeated identifier",
        )
    return tuple(identifiers)


def _same_scope(record: EvidenceRecord, population: PopulationRecord) -> bool:
    return (
        record.tenant_id == population.tenant_id
        and record.boundary_ref == population.boundary_ref
    )


def _indexes(
    population: PopulationRecord,
    identifiers: tuple[str, ...],
    evidence_records: Sequence[EvidenceRecord],
    confirmations: Sequence[ExternalConfirmationRecord],
) -> _Indexes:
    proposals: defaultdict[str, list[ActionProposalRecord]] = defaultdict(list)
    receipts: defaultdict[str, list[ExecutionReceiptRecord]] = defaultdict(list)
    confirmations_by_destination: defaultdict[
        str, list[ExternalConfirmationRecord]
    ] = defaultdict(list)
    destinations_by_action: defaultdict[str, set[str]] = defaultdict(set)
    population_ids = frozenset(identifiers)

    for record in evidence_records:
        if not _same_scope(record, population):
            continue
        if isinstance(record, ActionProposalRecord):
            proposals[record.body.action_id].append(record)
            continue
        if isinstance(record, ExecutionReceiptRecord):
            destination_id = record.body.destination_record_ref
            if destination_id in population_ids:
                receipts[destination_id].append(record)
                destinations_by_action[record.body.action_id].add(destination_id)
            continue
        # Other evidence types do not carry the stable relation RC-001 names.

    for confirmation in confirmations:
        if not _same_scope(confirmation, population):
            continue
        if confirmation.body.destination_record_id in population_ids:
            confirmations_by_destination[
                confirmation.body.destination_record_id
            ].append(confirmation)

    return _Indexes(
        proposals_by_action={key: tuple(value) for key, value in proposals.items()},
        receipts_by_destination={key: tuple(value) for key, value in receipts.items()},
        confirmations_by_destination={
            key: tuple(value) for key, value in confirmations_by_destination.items()
        },
        receipt_destinations_by_action={
            key: frozenset(value) for key, value in destinations_by_action.items()
        },
    )


def _duplicate_identifiers(
    identifiers: tuple[str, ...],
    indexes: _Indexes,
    *,
    destination_system: str,
) -> frozenset[str]:
    """Return distinct IDs whose single in-scope confirmation has equal content."""

    by_digest: defaultdict[str, list[str]] = defaultdict(list)
    for identifier in identifiers:
        candidates = indexes.confirmations_by_destination.get(identifier, ())
        if len(candidates) != 1:
            continue
        confirmation = candidates[0]
        if confirmation.body.destination_system != destination_system:
            continue
        by_digest[confirmation.body.destination_record_digest].append(identifier)
    return frozenset(
        identifier
        for grouped_identifiers in by_digest.values()
        if len(grouped_identifiers) > 1
        for identifier in grouped_identifiers
    )


def _candidate_action_id(
    receipts: tuple[ExecutionReceiptRecord, ...],
) -> str | None:
    if len(receipts) == 1:
        return receipts[0].body.action_id
    return None


def _classify(
    population: PopulationRecord,
    destination_record_id: str,
    indexes: _Indexes,
    duplicate_identifiers: frozenset[str],
) -> ReconciliationResult:
    receipts = indexes.receipts_by_destination.get(destination_record_id, ())
    confirmations = indexes.confirmations_by_destination.get(
        destination_record_id, ()
    )
    linked_action_ids = {record.body.action_id for record in receipts} | {
        confirmation.body.action_id for confirmation in confirmations
    }
    linked_proposals = tuple(
        proposal
        for action_id in linked_action_ids
        for proposal in indexes.proposals_by_action.get(action_id, ())
    )
    action_id = _candidate_action_id(receipts)

    outside_family = any(
        proposal.body.action_family != population.body.action_family
        for proposal in linked_proposals
    )
    outside_destination = any(
        confirmation.body.destination_system != population.body.destination_system
        for confirmation in confirmations
    )
    if outside_family or outside_destination:
        return ReconciliationResult(
            population_ref=population.record_id,
            destination_record_id=destination_record_id,
            status=ReconciliationStatus.OUT_OF_SCOPE,
            action_id=action_id,
            confirmation_record_id=None,
        )

    proposal_ambiguous = any(
        len(indexes.proposals_by_action.get(candidate_action, ())) > 1
        for candidate_action in linked_action_ids
    )
    action_spans_destinations = any(
        len(indexes.receipt_destinations_by_action.get(candidate_action, ())) > 1
        for candidate_action in linked_action_ids
    )
    if (
        len(receipts) > 1
        or len(confirmations) > 1
        or proposal_ambiguous
        or action_spans_destinations
    ):
        return ReconciliationResult(
            population_ref=population.record_id,
            destination_record_id=destination_record_id,
            status=ReconciliationStatus.AMBIGUOUS,
            action_id=None,
            confirmation_record_id=None,
        )

    if destination_record_id in duplicate_identifiers:
        confirmation = confirmations[0]
        return ReconciliationResult(
            population_ref=population.record_id,
            destination_record_id=destination_record_id,
            status=ReconciliationStatus.DUPLICATE,
            action_id=action_id,
            confirmation_record_id=confirmation.record_id,
        )

    if len(receipts) == 1 and len(confirmations) == 1:
        receipt = receipts[0]
        confirmation = confirmations[0]
        proposals = indexes.proposals_by_action.get(receipt.body.action_id, ())
        exact_identity = receipt.body.action_id == confirmation.body.action_id
        exact_family = (
            len(proposals) == 1
            and proposals[0].body.action_family == population.body.action_family
        )
        if exact_identity and exact_family:
            return ReconciliationResult(
                population_ref=population.record_id,
                destination_record_id=destination_record_id,
                status=ReconciliationStatus.MATCHED,
                action_id=receipt.body.action_id,
                confirmation_record_id=confirmation.record_id,
            )

    if receipts:
        return ReconciliationResult(
            population_ref=population.record_id,
            destination_record_id=destination_record_id,
            status=ReconciliationStatus.UNMATCHED_WITH_EVIDENCE,
            action_id=action_id,
            confirmation_record_id=None,
        )

    if not receipts:
        return ReconciliationResult(
            population_ref=population.record_id,
            destination_record_id=destination_record_id,
            status=ReconciliationStatus.UNMATCHED_WITHOUT_EVIDENCE,
            action_id=None,
            confirmation_record_id=None,
        )

    raise ReconciliationInvariantError(  # pragma: no cover - explicit exhaustiveness guard
        f"validated identifier {destination_record_id!r} was not classified"
    )


def reconcile(
    population: PopulationRecord,
    evidence_records: Iterable[EvidenceRecord],
    confirmations: Iterable[ExternalConfirmationRecord],
) -> tuple[ReconciliationResult, ...]:
    """Classify every explicit denominator identity without approximation.

    Iterables are snapshotted once.  No input model is modified, no ledger or
    derived relation is accessed, and output ordering is the signed population
    ordering rather than caller or database iteration order.
    """

    identifiers = _accepted_identifiers(population)
    evidence_snapshot = tuple(evidence_records)
    confirmation_snapshot = tuple(confirmations)
    indexes = _indexes(
        population,
        identifiers,
        evidence_snapshot,
        confirmation_snapshot,
    )
    duplicate_identifiers = _duplicate_identifiers(
        identifiers,
        indexes,
        destination_system=population.body.destination_system,
    )
    results = tuple(
        _classify(population, identifier, indexes, duplicate_identifiers)
        for identifier in identifiers
    )
    if len(results) != population.body.count:
        raise ReconciliationInvariantError(  # pragma: no cover - guarded on input
            "result cardinality diverged from the signed population count"
        )
    return results


__all__ = [
    "COMPUTATION_VERSION",
    "PopulationIdentifierDigestUnsupportedError",
    "PopulationIntegrityError",
    "ReconciliationError",
    "ReconciliationInvariantError",
    "ReconciliationResult",
    "ReconciliationStatus",
    "reconcile",
]
