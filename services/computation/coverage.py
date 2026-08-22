"""Pure coverage computation for EV-16.

This module consumes EV-12's denominator-class properties and EV-15's closed
reconciliation results.  It contains no second class-to-level table, performs
no persistence, reads no clock, and makes no approximate record match.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import ROUND_DOWN, Decimal, localcontext
from enum import StrEnum
from typing import Any

from sdk_python.evidence.schema import (
    ExecutionReceiptRecord,
    ExternalConfirmationRecord,
    PopulationRecord,
)
from services.admin.qualification import (
    CoverageLevel,
    DenominatorClass,
    Qualification,
    class_in_force,
    governing_qualification,
)
from services.computation.reconciliation import (
    ReconciliationResult,
    ReconciliationStatus,
)
from services.ingestion.receipts import (
    RegisteredPublicKey,
    SignedIngestionReceipt,
    parse_timestamp,
    verify_ingestion_receipt,
)


class CoverageInputError(ValueError):
    """Coverage inputs disagree or omit a fact needed for an exact claim."""


class RatioState(StrEnum):
    """Why the required ``coverage_ratio`` field has its current value."""

    AVAILABLE = "available"
    DENOMINATOR_CLASS_WITHHOLDS_RATIO = "denominator_class_withholds_ratio"
    TRUNCATED_POPULATION = "truncated_population"
    POPULATION_NOT_ENUMERABLE = "population_not_enumerable"
    DIGEST_ONLY_POPULATION = "digest_only_population"
    EMPTY_POPULATION = "empty_population"
    # ES-017's zero denominator, reached by exclusion rather than by an empty
    # enumeration. Kept distinct from EMPTY_POPULATION because the two are
    # different facts about the destination: nothing was returned, versus
    # everything returned was outside the boundary's claim.
    DENOMINATOR_EMPTY_AFTER_EXCLUSIONS = "denominator_empty_after_exclusions"


class GapActionClassification(StrEnum):
    """CM-015's closed classifications for an action inside a gap.

    There is deliberately no ``enforced`` member.  A destination-matched
    action may retain reconciled status; every other action in the affected
    interval is unknown.
    """

    UNKNOWN = "unknown"
    RECONCILED = "reconciled"


class GapCause(StrEnum):
    """The closed evidence-spec §5.12 CoverageGap cause set."""

    COLLECTOR_UNREACHABLE = "collector_unreachable"
    FAIL_OPEN = "fail_open"
    SEQUENCE_BREAK = "sequence_break"
    DENOMINATOR_UNAVAILABLE = "denominator_unavailable"
    CLOCK_SKEW = "clock_skew"
    KEY_DISCONTINUITY = "key_discontinuity"


@dataclass(frozen=True, slots=True, order=True)
class TimeInterval:
    """A non-empty, timezone-aware half-open interval ``[start, end)``."""

    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        if self.start.tzinfo is None or self.end.tzinfo is None:
            raise CoverageInputError("coverage intervals must be timezone-aware")
        if self.end <= self.start:
            raise CoverageInputError("coverage interval end must be after start")

    @property
    def duration(self) -> timedelta:
        return self.end - self.start

    def contains(self, instant: datetime) -> bool:
        return self.start <= instant < self.end

    def encloses(self, other: TimeInterval) -> bool:
        return self.start <= other.start and other.end <= self.end


@dataclass(frozen=True, slots=True)
class CoverageBoundary:
    """The boundary facts coverage needs, with no persistence dependency."""

    boundary_ref: str
    window: TimeInterval
    clock_skew_threshold_ms: int

    def __post_init__(self) -> None:
        if not self.boundary_ref:
            raise CoverageInputError("boundary_ref must be non-empty")
        if self.clock_skew_threshold_ms < 0:
            raise CoverageInputError("clock_skew_threshold_ms cannot be negative")


@dataclass(frozen=True, slots=True)
class ActionEvidence:
    """Typed records from which support and occurrence time are derived.

    No caller supplies a level or timestamp as a detached scalar.  A matched
    confirmation proves reconciled support only after its action, destination,
    record id, and status bind to the EV-15 result.  A customer-origin record
    can locate an otherwise unmatched action only through its verified ES-030
    receipt.
    """

    destination_record_id: str
    confirmation: ExternalConfirmationRecord | None = None
    ingestion_receipt: SignedIngestionReceipt | None = None
    receipt_record: ExecutionReceiptRecord | None = None
    receipt_verification_keys: Mapping[str, RegisteredPublicKey] | None = None
    affected_interval: TimeInterval | None = None

    def __post_init__(self) -> None:
        if not self.destination_record_id:
            raise CoverageInputError("action evidence requires a destination identity")
        receipt_parts = (
            self.ingestion_receipt,
            self.receipt_record,
            self.receipt_verification_keys,
        )
        if any(part is not None for part in receipt_parts) and any(
            part is None for part in receipt_parts
        ):
            raise CoverageInputError(
                "ingestion receipt, bound record, and verification keys are all required"
            )


@dataclass(frozen=True, slots=True)
class GapEvidence:
    """Caller-verified signed gap metadata retained beside the partition."""

    interval: TimeInterval
    cause: GapCause | str
    affected_scope: tuple[str, ...]
    detection_source: str
    actions_during_gap: int | None
    evidence_record_ref: str | None

    def __post_init__(self) -> None:
        try:
            cause = GapCause(self.cause)
        except ValueError as error:
            raise CoverageInputError(f"unknown gap cause {self.cause!r}") from error
        object.__setattr__(self, "cause", cause)
        if not self.affected_scope or any(not item for item in self.affected_scope):
            raise CoverageInputError("gap affected_scope must name at least one scope")
        if not self.detection_source:
            raise CoverageInputError("gap detection_source must be non-empty")
        if self.actions_during_gap is not None and self.actions_during_gap < 0:
            raise CoverageInputError("actions_during_gap cannot be negative")


@dataclass(frozen=True, slots=True)
class GapAction:
    destination_record_id: str
    classification: GapActionClassification


@dataclass(frozen=True, slots=True)
class CoverageCounts:
    """Every EV-15 classification, conserved without a residual bucket."""

    matched: int
    unmatched_with_evidence: int
    unmatched_without_evidence: int
    duplicate: int
    ambiguous: int
    out_of_scope: int

    def as_dict(self) -> dict[str, int]:
        return {
            "matched": self.matched,
            "unmatched_with_evidence": self.unmatched_with_evidence,
            "unmatched_without_evidence": self.unmatched_without_evidence,
            "duplicate": self.duplicate,
            "ambiguous": self.ambiguous,
            "out_of_scope": self.out_of_scope,
        }


@dataclass(frozen=True, slots=True)
class CoverageReport:
    """Immutable EV-16 result for later assembly by EV-17."""

    population_ref: str
    boundary_ref: str
    window: TimeInterval
    denominator_class: DenominatorClass
    evidence_supported_level: CoverageLevel
    class_admissible_level: CoverageLevel
    claimed_level: CoverageLevel
    capped_by_class: bool
    coverage_ratio: Decimal | None
    ratio_state: RatioState
    population_independently_enumerable: bool
    numerator_count: int
    denominator_count: int
    counts: CoverageCounts
    covered_intervals: tuple[TimeInterval, ...]
    gap_intervals: tuple[TimeInterval, ...]
    gaps: tuple[GapEvidence, ...]
    gap_actions: tuple[GapAction, ...]

    def to_payload(self) -> dict[str, Any]:
        """Return a JSON-ready value with ``coverage_ratio`` always present."""
        ratio = None
        if self.coverage_ratio is not None:
            # ES-017 fixes the scale at exactly four places and forbids
            # stripping trailing zeros: "1.0000", never "1"; "0.5000", never
            # "0.5". A free scale lets two correct implementations serialize
            # the same ratio differently, and QA-008 compares golden bundles
            # byte-for-byte -- the diff would then report a divergence that
            # says nothing about either implementation.
            ratio = format(self.coverage_ratio, "f")
        return {
            "population_ref": self.population_ref,
            "boundary_ref": self.boundary_ref,
            "window_start": self.window.start.isoformat(),
            "window_end": self.window.end.isoformat(),
            "denominator_class": self.denominator_class.value,
            "evidence_supported_level": self.evidence_supported_level.value,
            "class_admissible_level": self.class_admissible_level.value,
            "coverage_level": self.claimed_level.value,
            "capped_by_class": self.capped_by_class,
            "coverage_ratio": ratio,
            "ratio_state": self.ratio_state.value,
            "population_independently_enumerable": (
                self.population_independently_enumerable
            ),
            "numerator_count": self.numerator_count,
            "denominator_count": self.denominator_count,
            "counts": self.counts.as_dict(),
            "covered_intervals": [
                _interval_payload(interval) for interval in self.covered_intervals
            ],
            "gap_intervals": [
                _interval_payload(interval) for interval in self.gap_intervals
            ],
            "gaps": [
                {
                    **_interval_payload(gap.interval),
                    "cause": GapCause(gap.cause).value,
                    "affected_scope": list(gap.affected_scope),
                    "detection_source": gap.detection_source,
                    "actions_during_gap": gap.actions_during_gap,
                    "evidence_record_ref": gap.evidence_record_ref,
                }
                for gap in self.gaps
            ],
            "gap_actions": [
                {
                    "destination_record_id": item.destination_record_id,
                    "classification": item.classification.value,
                }
                for item in self.gap_actions
            ],
        }


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _interval_payload(interval: TimeInterval) -> dict[str, str]:
    return {
        "start": interval.start.isoformat(timespec="milliseconds"),
        "end": interval.end.isoformat(timespec="milliseconds"),
    }


def _weaker_level(left: CoverageLevel, right: CoverageLevel) -> CoverageLevel:
    """Return the weaker level using EV-12's declared level order."""
    order = tuple(CoverageLevel)
    return min((left, right), key=order.index)


def _classification_counts(
    results: tuple[ReconciliationResult, ...],
) -> CoverageCounts:
    matched = 0
    unmatched_with_evidence = 0
    unmatched_without_evidence = 0
    duplicate = 0
    ambiguous = 0
    out_of_scope = 0
    for result in results:
        if not isinstance(result.status, ReconciliationStatus):
            raise CoverageInputError(
                f"unknown reconciliation status {result.status!r}; the set is closed"
            )
        match result.status:
            case ReconciliationStatus.MATCHED:
                matched += 1
            case ReconciliationStatus.UNMATCHED_WITH_EVIDENCE:
                unmatched_with_evidence += 1
            case ReconciliationStatus.UNMATCHED_WITHOUT_EVIDENCE:
                unmatched_without_evidence += 1
            case ReconciliationStatus.DUPLICATE:
                duplicate += 1
            case ReconciliationStatus.AMBIGUOUS:
                ambiguous += 1
            case ReconciliationStatus.OUT_OF_SCOPE:
                out_of_scope += 1
    return CoverageCounts(
        matched=matched,
        unmatched_with_evidence=unmatched_with_evidence,
        unmatched_without_evidence=unmatched_without_evidence,
        duplicate=duplicate,
        ambiguous=ambiguous,
        out_of_scope=out_of_scope,
    )


def _normalise_gap_intervals(
    window: TimeInterval, gaps: tuple[GapEvidence, ...]
) -> tuple[TimeInterval, ...]:
    ordered = sorted((gap.interval for gap in gaps), key=lambda item: (item.start, item.end))
    merged: list[TimeInterval] = []
    for interval in ordered:
        if not window.encloses(interval):
            raise CoverageInputError("every gap interval must be inside the coverage window")
        if not merged or merged[-1].end < interval.start:
            merged.append(interval)
            continue
        previous = merged[-1]
        merged[-1] = TimeInterval(previous.start, max(previous.end, interval.end))
    return tuple(merged)


def _covered_complement(
    window: TimeInterval, gap_intervals: tuple[TimeInterval, ...]
) -> tuple[TimeInterval, ...]:
    covered: list[TimeInterval] = []
    cursor = window.start
    for gap in gap_intervals:
        if cursor < gap.start:
            covered.append(TimeInterval(cursor, gap.start))
        cursor = gap.end
    if cursor < window.end:
        covered.append(TimeInterval(cursor, window.end))
    return tuple(covered)


def _validate_scope(
    *,
    population: PopulationRecord,
    boundary: CoverageBoundary,
    qualification_history: tuple[Qualification, ...],
) -> tuple[TimeInterval, DenominatorClass, bool]:
    population_window = TimeInterval(
        _parse_timestamp(population.body.window_start),
        _parse_timestamp(population.body.window_end),
    )
    if population.boundary_ref != boundary.boundary_ref:
        raise CoverageInputError("population and boundary refs differ")
    if population_window != boundary.window:
        raise CoverageInputError("population and boundary windows differ")
    if not qualification_history:
        raise CoverageInputError("qualification history cannot be empty")
    for qualification in qualification_history:
        if population.tenant_id != qualification.tenant_id:
            raise CoverageInputError("population and qualification tenants differ")
        if population.body.action_family != qualification.action_family:
            raise CoverageInputError("population and qualification action families differ")
        if population.body.destination_system != qualification.destination_system:
            raise CoverageInputError("population and qualification destinations differ")

    effective_class = class_in_force(
        qualification_history,
        window_start=population_window.start,
        window_end=population_window.end,
    )
    baseline = governing_qualification(
        qualification_history, window_start=population_window.start
    )
    relevant = (baseline,) + tuple(
        item
        for item in qualification_history
        if population_window.start <= item.qualified_at < population_window.end
    )
    enumeration_capable = all(item.enumeration_capable for item in relevant)
    if effective_class.emits_ratio and not enumeration_capable:
        raise CoverageInputError(
            "a ratio-emitting denominator class requires enumeration capability"
        )
    return population_window, effective_class, enumeration_capable


def _validate_results(
    population: PopulationRecord,
    results: tuple[ReconciliationResult, ...],
) -> bool:
    if any(result.population_ref != population.record_id for result in results):
        raise CoverageInputError("reconciliation result names a different population")
    result_ids = [result.destination_record_id for result in results]
    if len(result_ids) != len(set(result_ids)):
        raise CoverageInputError("reconciliation results repeat a destination identity")

    identifiers = population.body.record_identifiers
    if identifiers is None:
        if results:
            raise CoverageInputError("digest-only populations cannot carry per-record results")
        return False
    if population.body.count != len(identifiers):
        raise CoverageInputError("population count and inline identities differ")
    if len(identifiers) != len(set(identifiers)):
        raise CoverageInputError("population identities are not distinct")
    if set(result_ids) != set(identifiers):
        raise CoverageInputError(
            "reconciliation result identities must equal the inline population identities"
        )
    return True


def _ratio_state(
    *,
    population: PopulationRecord,
    denominator_class: DenominatorClass,
    enumeration_capable: bool,
    inline_population: bool,
    out_of_scope: int,
) -> RatioState:
    # The static decisions are read from EV-12. There is no local class table.
    if not denominator_class.emits_ratio:
        return RatioState.DENOMINATOR_CLASS_WITHHOLDS_RATIO
    if population.body.result_cap_hit or not population.body.pagination_complete:
        return RatioState.TRUNCATED_POPULATION
    if not enumeration_capable:
        return RatioState.POPULATION_NOT_ENUMERABLE
    if not inline_population:
        return RatioState.DIGEST_ONLY_POPULATION
    if population.body.count == 0:
        return RatioState.EMPTY_POPULATION
    if population.body.count - out_of_scope <= 0:
        return RatioState.DENOMINATOR_EMPTY_AFTER_EXCLUSIONS
    return RatioState.AVAILABLE


def _bound_action_facts(
    *,
    item: ActionEvidence,
    result: ReconciliationResult,
    population: PopulationRecord,
    boundary: CoverageBoundary,
) -> tuple[CoverageLevel | None, datetime | None, bool]:
    """Derive support, occurrence, and skew from identity-bound records."""
    confirmation = item.confirmation
    if confirmation is not None:
        confirmation_matches = (
            result.status is ReconciliationStatus.MATCHED
            and result.action_id is not None
            and result.confirmation_record_id == confirmation.record_id
            and confirmation.tenant_id == population.tenant_id
            and confirmation.boundary_ref == population.boundary_ref
            and confirmation.body.action_id == result.action_id
            and confirmation.body.destination_system
            == population.body.destination_system
            and confirmation.body.destination_record_id
            == result.destination_record_id
            and confirmation.body.reconciliation_status
            == ReconciliationStatus.MATCHED.value
        )
        if not confirmation_matches:
            raise CoverageInputError(
                "authoritative confirmation is not bound to the reconciliation result"
            )
        # Destination time governs whenever it exists (ES-020/CM-018).
        return (
            CoverageLevel.RECONCILED,
            _parse_timestamp(confirmation.body.authoritative_timestamp),
            False,
        )

    if result.status is ReconciliationStatus.MATCHED:
        raise CoverageInputError(
            "a matched reconciliation result requires its bound confirmation record"
        )

    record = item.receipt_record
    if record is None:
        return None, None, False
    if result.action_id is None:
        raise CoverageInputError(
            f"{result.status.value} cannot bind customer evidence without an action id"
        )
    record_matches = (
        record.tenant_id == population.tenant_id
        and record.boundary_ref == population.boundary_ref
        and record.body.action_id == result.action_id
    )
    record_matches = (
        record_matches
        and record.body.destination_record_ref == result.destination_record_id
    )
    if not record_matches:
        raise CoverageInputError(
            "receipt-bound record is not bound to the reconciliation result"
        )
    assert item.ingestion_receipt is not None
    assert item.receipt_verification_keys is not None
    receipt = verify_ingestion_receipt(
        item.ingestion_receipt,
        record=record,
        verification_keys=item.receipt_verification_keys,
    )
    skewed = abs(receipt.clock_skew_ms) > boundary.clock_skew_threshold_ms
    return CoverageLevel.OBSERVED, parse_timestamp(receipt.ingest_time), skewed


def compute_coverage(
    *,
    reconciliation_results: tuple[ReconciliationResult, ...],
    population: PopulationRecord,
    boundary: CoverageBoundary,
    qualification_history: tuple[Qualification, ...],
    action_evidence: tuple[ActionEvidence, ...],
    gaps: tuple[GapEvidence, ...] = (),
) -> CoverageReport:
    """Compute one deterministic coverage report without mutating any input."""
    window, denominator_class, enumeration_capable = _validate_scope(
        population=population,
        boundary=boundary,
        qualification_history=qualification_history,
    )
    inline_population = _validate_results(population, reconciliation_results)
    classification_counts = _classification_counts(reconciliation_results)
    results_by_id = {
        result.destination_record_id: result for result in reconciliation_results
    }
    evidence_by_id = {item.destination_record_id: item for item in action_evidence}
    if len(evidence_by_id) != len(action_evidence):
        raise CoverageInputError("action evidence repeats a destination identity")
    unknown_evidence_ids = set(evidence_by_id) - set(results_by_id)
    if unknown_evidence_ids:
        raise CoverageInputError(
            "action evidence names identities outside reconciliation: "
            f"{sorted(unknown_evidence_ids)}"
        )

    level_order = tuple(CoverageLevel)

    effective_gaps = list(gaps)
    skewed_ids: set[str] = set()
    occurrence_by_id: dict[str, datetime | None] = {}
    support_by_id: dict[str, CoverageLevel | None] = {}
    for item in action_evidence:
        result = results_by_id[item.destination_record_id]
        supported, occurrence, skewed = _bound_action_facts(
            item=item,
            result=result,
            population=population,
            boundary=boundary,
        )
        support_by_id[item.destination_record_id] = supported
        occurrence_by_id[item.destination_record_id] = occurrence
        if not skewed:
            continue
        if item.affected_interval is None:
            raise CoverageInputError(
                "skew beyond the boundary threshold requires an affected interval"
            )
        skewed_ids.add(item.destination_record_id)
        effective_gaps.append(
            GapEvidence(
                interval=item.affected_interval,
                cause=GapCause.CLOCK_SKEW,
                affected_scope=(population.body.action_family,),
                detection_source="issuer-signed ingestion receipt",
                actions_during_gap=None,
                evidence_record_ref=None,
            )
        )

    # Evidence support is derived from the bound records above.  There is no
    # caller-provided strength scalar that can manufacture a stronger claim.
    supported_levels = tuple(
        level for level in support_by_id.values() if level is not None
    )
    evidence_supported_level = (
        max(supported_levels, key=level_order.index)
        if supported_levels
        else CoverageLevel.OBSERVED
    )
    # Both properties below are EV-12's static lattice. This module adds only
    # the dynamic evidence minimum and never restates the class mapping.
    class_admissible_level = denominator_class.admissible_level
    claimed_level = _weaker_level(evidence_supported_level, class_admissible_level)
    capped_by_class = claimed_level != evidence_supported_level

    gap_tuple = tuple(effective_gaps)
    gap_intervals = _normalise_gap_intervals(window, gap_tuple)
    covered_intervals = _covered_complement(window, gap_intervals)

    for gap in gaps:
        if gap.actions_during_gap is None:
            continue
        located = sum(
            instant is not None and gap.interval.contains(instant)
            for instant in occurrence_by_id.values()
        )
        if located != gap.actions_during_gap:
            raise CoverageInputError(
                "known actions_during_gap does not equal temporally attributed actions"
            )

    numerator_count = 0
    gap_actions: list[GapAction] = []
    for destination_id in evidence_by_id:
        result = results_by_id[destination_id]
        occurrence = occurrence_by_id.get(destination_id)
        in_window = occurrence is not None and window.contains(occurrence)
        in_gap = destination_id in skewed_ids or (
            occurrence is not None
            and in_window
            and any(interval.contains(occurrence) for interval in gap_intervals)
        )
        reconciled_in_gap = (
            in_gap
            and result.status is ReconciliationStatus.MATCHED
            and support_by_id[destination_id] is CoverageLevel.RECONCILED
            and destination_id not in skewed_ids
        )
        if in_gap:
            gap_actions.append(
                GapAction(
                    destination_record_id=destination_id,
                    classification=(
                        GapActionClassification.RECONCILED
                        if reconciled_in_gap
                        else GapActionClassification.UNKNOWN
                    ),
                )
            )

        supported = support_by_id[destination_id]
        if supported is None or destination_id in skewed_ids:
            continue
        if occurrence is not None and not in_window:
            # ES-020 makes the bound destination/receipt time govern. Evidence
            # for a different window cannot enter this window's numerator.
            continue
        if not isinstance(result.status, ReconciliationStatus):
            raise CoverageInputError(
                f"unknown reconciliation status {result.status!r}; the set is closed"
            )
        if result.status in {
            ReconciliationStatus.UNMATCHED_WITHOUT_EVIDENCE,
            ReconciliationStatus.OUT_OF_SCOPE,
        }:
            raise CoverageInputError(
                f"{result.status.value} cannot carry numerator evidence"
            )
        if in_gap and not reconciled_in_gap:
            continue
        if in_gap and claimed_level is not CoverageLevel.RECONCILED:
            # CM-015: reconciliation may survive fail-open; it must not be
            # converted to enforced coverage by the denominator-class cap.
            continue
        if gaps and occurrence is None:
            # Its position relative to an affected interval is unknowable.  It
            # cannot enter the numerator merely because a timestamp is absent.
            continue
        if level_order.index(supported) >= level_order.index(claimed_level):
            numerator_count += 1

    state = _ratio_state(
        population=population,
        denominator_class=denominator_class,
        enumeration_capable=enumeration_capable,
        inline_population=inline_population,
        out_of_scope=classification_counts.out_of_scope,
    )
    # ES-017: the denominator is the enumerated population less out-of-scope
    # records. The boundary never claimed those actions, so leaving them in
    # would let the one number a relying party reads move with activity the
    # attestation makes no claim about. The count stays in `counts` as a
    # transparency figure: visible, and non-contributing.
    ratio_denominator = population.body.count - classification_counts.out_of_scope
    ratio: Decimal | None = None
    if state is RatioState.AVAILABLE:
        with localcontext() as context:
            context.prec = 28
            # ES-017 truncates toward zero: 2/3 encodes as "0.6666", never
            # "0.6667". Quantizing with ROUND_DOWN at four places does both
            # the scale and the rounding in one step.
            ratio = (
                Decimal(numerator_count) / Decimal(ratio_denominator)
            ).quantize(Decimal("0.0001"), rounding=ROUND_DOWN)

    independently_enumerable = (
        enumeration_capable
        and denominator_class.emits_ratio
        and not population.body.result_cap_hit
        and population.body.pagination_complete
    )
    return CoverageReport(
        population_ref=population.record_id,
        boundary_ref=boundary.boundary_ref,
        window=window,
        denominator_class=denominator_class,
        evidence_supported_level=evidence_supported_level,
        class_admissible_level=class_admissible_level,
        claimed_level=claimed_level,
        capped_by_class=capped_by_class,
        coverage_ratio=ratio,
        ratio_state=state,
        population_independently_enumerable=independently_enumerable,
        numerator_count=numerator_count,
        denominator_count=population.body.count,
        counts=classification_counts,
        covered_intervals=covered_intervals,
        gap_intervals=gap_intervals,
        gaps=gap_tuple,
        gap_actions=tuple(sorted(gap_actions, key=lambda item: item.destination_record_id)),
    )


__all__ = [
    "ActionEvidence",
    "CoverageBoundary",
    "CoverageCounts",
    "CoverageInputError",
    "CoverageReport",
    "GapAction",
    "GapActionClassification",
    "GapCause",
    "GapEvidence",
    "RatioState",
    "TimeInterval",
    "compute_coverage",
]
