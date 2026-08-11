"""The closed AR-003 attestation assertion catalogue.

Each catalogue entry has its own constructor.  There is intentionally no
``Assertion(id=...)`` escape hatch and no caller-supplied assertion text: an
off-catalogue claim is not a value this module can construct.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, ClassVar, Literal, assert_never

from services.admin.qualification import CoverageLevel, DenominatorClass


@dataclass(frozen=True, slots=True)
class AssertionScope:
    """The boundary, window, and action families to which one claim applies."""

    boundary_ref: str
    window_start: datetime
    window_end: datetime
    action_families: tuple[str, ...]


type AssertionCounts = tuple[tuple[str, int], ...]


@dataclass(frozen=True, slots=True)
class A01EvidenceChainValid:
    assertion_id: ClassVar[Literal["A-01"]] = "A-01"
    scope: AssertionScope
    counts: AssertionCounts
    evidence_record_count: int


@dataclass(frozen=True, slots=True)
class A02BoundaryInForce:
    assertion_id: ClassVar[Literal["A-02"]] = "A-02"
    scope: AssertionScope
    counts: AssertionCounts


@dataclass(frozen=True, slots=True)
class A03DenominatorQualified:
    assertion_id: ClassVar[Literal["A-03"]] = "A-03"
    scope: AssertionScope
    counts: AssertionCounts
    denominator_class: DenominatorClass


@dataclass(frozen=True, slots=True)
class A04PopulationMatched:
    assertion_id: ClassVar[Literal["A-04"]] = "A-04"
    scope: AssertionScope
    counts: AssertionCounts
    population_count: int
    matched_count: int
    coverage_level: CoverageLevel


@dataclass(frozen=True, slots=True)
class A05UnknownIntervals:
    assertion_id: ClassVar[Literal["A-05"]] = "A-05"
    scope: AssertionScope
    counts: AssertionCounts
    gap_count: int


@dataclass(frozen=True, slots=True)
class A06CoverageMinimum:
    assertion_id: ClassVar[Literal["A-06"]] = "A-06"
    scope: AssertionScope
    counts: AssertionCounts
    evidence_supported_level: CoverageLevel
    class_admissible_level: CoverageLevel
    claimed_level: CoverageLevel
    capped_by_class: bool


@dataclass(frozen=True, slots=True)
class A07ReviewsRecorded:
    assertion_id: ClassVar[Literal["A-07"]] = "A-07"
    scope: AssertionScope
    counts: AssertionCounts
    review_record_count: int


@dataclass(frozen=True, slots=True)
class A08ReversibleReviews:
    assertion_id: ClassVar[Literal["A-08"]] = "A-08"
    scope: AssertionScope
    counts: AssertionCounts
    reversible_review_count: int


@dataclass(frozen=True, slots=True)
class A09OutcomesConfirmed:
    assertion_id: ClassVar[Literal["A-09"]] = "A-09"
    scope: AssertionScope
    counts: AssertionCounts
    authoritative_source: str
    confirmed_action_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class A10Reproducible:
    assertion_id: ClassVar[Literal["A-10"]] = "A-10"
    scope: AssertionScope
    counts: AssertionCounts
    methodology_version: str
    verifier_version: str


type CatalogueAssertion = (
    A01EvidenceChainValid
    | A02BoundaryInForce
    | A03DenominatorQualified
    | A04PopulationMatched
    | A05UnknownIntervals
    | A06CoverageMinimum
    | A07ReviewsRecorded
    | A08ReversibleReviews
    | A09OutcomesConfirmed
    | A10Reproducible
)


def _scope_payload(scope: AssertionScope) -> dict[str, Any]:
    return {
        "boundary_ref": scope.boundary_ref,
        "window_start": scope.window_start.isoformat(),
        "window_end": scope.window_end.isoformat(),
        "action_families": list(scope.action_families),
    }


def _base_payload(assertion: CatalogueAssertion) -> dict[str, Any]:
    return {
        "assertion_id": assertion.assertion_id,
        "scope": _scope_payload(assertion.scope),
        "counts": dict(assertion.counts),
    }


def assertion_payload(assertion: CatalogueAssertion) -> dict[str, Any]:
    """Render a catalogue value with an exhaustive, no-residual dispatch."""

    match assertion:
        case A01EvidenceChainValid():
            details: dict[str, Any] = {"evidence_record_count": assertion.evidence_record_count}
        case A02BoundaryInForce():
            details = {"boundary_in_force": True}
        case A03DenominatorQualified():
            details = {"denominator_class": assertion.denominator_class.value.upper()}
        case A04PopulationMatched():
            details = {
                "population_count": assertion.population_count,
                "matched_count": assertion.matched_count,
                "coverage_level": assertion.coverage_level.value,
            }
        case A05UnknownIntervals():
            details = {"gap_count": assertion.gap_count}
        case A06CoverageMinimum():
            details = {
                "evidence_supported_level": assertion.evidence_supported_level.value,
                "class_admissible_level": assertion.class_admissible_level.value,
                "claimed_level": assertion.claimed_level.value,
                "capped_by_class": assertion.capped_by_class,
            }
        case A07ReviewsRecorded():
            details = {"review_record_count": assertion.review_record_count}
        case A08ReversibleReviews():
            details = {"reversible_review_count": assertion.reversible_review_count}
        case A09OutcomesConfirmed():
            details = {
                "authoritative_source": assertion.authoritative_source,
                "confirmed_action_ids": list(assertion.confirmed_action_ids),
            }
        case A10Reproducible():
            details = {
                "methodology_version": assertion.methodology_version,
                "verifier_version": assertion.verifier_version,
            }
        case _ as unreachable:
            assert_never(unreachable)
    payload = _base_payload(assertion)
    payload.update(details)
    return payload


__all__ = [
    "A01EvidenceChainValid",
    "A02BoundaryInForce",
    "A03DenominatorQualified",
    "A04PopulationMatched",
    "A05UnknownIntervals",
    "A06CoverageMinimum",
    "A07ReviewsRecorded",
    "A08ReversibleReviews",
    "A09OutcomesConfirmed",
    "A10Reproducible",
    "AssertionCounts",
    "AssertionScope",
    "CatalogueAssertion",
    "assertion_payload",
]
