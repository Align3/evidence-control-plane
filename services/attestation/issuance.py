"""Pure EV-17 assembly followed by the ES-023 two-proof issuance step."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sdk_python.evidence.schema import (
    AttestationWindowRecord,
    OutcomeRecord,
    validate_record,
)
from sdk_python.evidence.signing import counter_sign_attestation, sign_record
from services.admin.boundary import BoundaryVersion, IntervalCoverage, interval_coverage
from services.computation.coverage import CoverageReport, RatioState

from .assertions import (
    A02BoundaryInForce,
    A03DenominatorQualified,
    A04PopulationMatched,
    A05UnknownIntervals,
    A06CoverageMinimum,
    A09OutcomesConfirmed,
    AssertionCounts,
    AssertionScope,
    CatalogueAssertion,
    assertion_payload,
)


class AttestationInputError(ValueError):
    """The requested attestation cannot be supported by its supplied facts."""


class StandingExclusion(StrEnum):
    """AR-005 and coverage-methodology §12, fixed rather than caller-authored."""

    SEMANTIC_APPROPRIATENESS = "semantic_appropriateness"
    HUMAN_JUDGEMENT_QUALITY = "human_judgement_quality"
    OUTSIDE_DECLARED_BOUNDARY = "outside_declared_boundary"
    DESTINATION_SYSTEM_INTEGRITY = "destination_system_integrity"
    OUTSIDE_ATTESTATION_WINDOW = "outside_attestation_window"
    COMPLIANCE_OR_CERTIFICATION = "compliance_or_certification"


@dataclass(frozen=True, slots=True)
class EvidenceSigner:
    """Customer/evidence-namespace primary signer for AttestationWindow."""

    key_id: str
    private_key: Ed25519PrivateKey


@dataclass(frozen=True, slots=True)
class IssuerSigner:
    """Issuer-namespace counter-signer; never the attestation's primary proof."""

    key_id: str
    private_key: Ed25519PrivateKey


@dataclass(frozen=True, slots=True)
class AttestationSource:
    """Closed envelope-source metadata; it cannot carry assertion-like fields."""

    service: str
    version: str


@dataclass(frozen=True, slots=True)
class RelyingParty:
    """One named relying party, without a place for an aggregate judgement."""

    name: str
    relationship: str | None = None


@dataclass(frozen=True, slots=True)
class IssuerIdentity:
    """The issuer named by the body, separate from its counter-signing key."""

    name: str
    identifier: str | None = None


@dataclass(frozen=True, slots=True)
class AttestationRequest:
    tenant_id: str
    record_id: str
    stream_id: str
    sequence: int
    prev_digest: str | None
    source: AttestationSource
    coverage: CoverageReport
    boundary_versions: tuple[BoundaryVersion, ...]
    action_families: tuple[str, ...]
    operated_action_families: tuple[str, ...]
    outcome_action_ids: tuple[str, ...]
    authoritative_source: str | None
    outcome_records: tuple[OutcomeRecord, ...]
    methodology_version: str
    verifier_version: str
    verification_status: Literal["self_computed", "independently_reproduced"]
    relying_parties: tuple[RelyingParty, ...]
    validity_from: datetime
    validity_until: datetime
    liability_ref: str
    issued_at: datetime
    issuer: IssuerIdentity


@dataclass(frozen=True, slots=True)
class AttestationAssembly:
    assertions: tuple[CatalogueAssertion, ...]
    boundary_coverage: IntervalCoverage
    exclusions: tuple[dict[str, Any], ...]


@dataclass(frozen=True, slots=True)
class IssuedAttestation:
    record: AttestationWindowRecord
    assembly: AttestationAssembly


def _timestamp(value: datetime) -> str:
    return value.isoformat(timespec="milliseconds")


def _source_payload(source: AttestationSource) -> dict[str, str]:
    return {"service": source.service, "version": source.version}


def _relying_party_payload(party: RelyingParty) -> dict[str, str]:
    payload = {"name": party.name}
    if party.relationship is not None:
        payload["relationship"] = party.relationship
    return payload


def _issuer_payload(issuer: IssuerIdentity) -> dict[str, str]:
    payload = {"name": issuer.name}
    if issuer.identifier is not None:
        payload["identifier"] = issuer.identifier
    return payload


def _require_non_empty(values: tuple[str, ...], *, label: str) -> tuple[str, ...]:
    if not values or any(not value for value in values):
        raise AttestationInputError(f"{label} must contain non-empty values")
    if len(set(values)) != len(values):
        raise AttestationInputError(f"{label} must not contain duplicates")
    return tuple(sorted(values))


def _assertion_counts(coverage: CoverageReport) -> AssertionCounts:
    return tuple(sorted(coverage.counts.as_dict().items()))


def _outcome_assertion(
    *,
    scope: AssertionScope,
    counts: AssertionCounts,
    tenant_id: str,
    action_ids: tuple[str, ...],
    authoritative_source: str | None,
    outcome_records: tuple[OutcomeRecord, ...],
) -> A09OutcomesConfirmed | None:
    """Select A-09 from OutcomeRecord only; ExternalConfirmation is insufficient."""

    if authoritative_source is None:
        return None
    requested = frozenset(action_ids)
    confirmed = tuple(
        sorted(
            {
                record.body.action_id
                for record in outcome_records
                if record.tenant_id == tenant_id
                and record.boundary_ref == scope.boundary_ref
                and record.body.action_id in requested
                and record.body.authoritative_source == authoritative_source
                and not record.body.disputed
            }
        )
    )
    if not confirmed:
        return None
    return A09OutcomesConfirmed(
        scope=scope,
        counts=counts,
        authoritative_source=authoritative_source,
        confirmed_action_ids=confirmed,
    )


def assemble_attestation(request: AttestationRequest) -> AttestationAssembly:
    """Select only supportable catalogue assertions, with no persistence or clock."""

    coverage = request.coverage
    action_families = _require_non_empty(request.action_families, label="action_families")
    operated = _require_non_empty(
        request.operated_action_families, label="operated_action_families"
    )
    if coverage.boundary_ref not in {version.boundary_ref for version in request.boundary_versions}:
        raise AttestationInputError("coverage boundary is absent from boundary history")

    selected_boundary = next(
        version
        for version in request.boundary_versions
        if version.boundary_ref == coverage.boundary_ref
    )
    undeclared = set(action_families) - selected_boundary.declared_families
    if undeclared:
        raise AttestationInputError(
            f"attested action families are outside the boundary: {sorted(undeclared)}"
        )
    unoperated = set(action_families) - set(operated)
    if unoperated:
        raise AttestationInputError(
            f"attested action families are not among operated families: {sorted(unoperated)}"
        )

    boundary_result = interval_coverage(
        request.boundary_versions,
        boundary_ref=coverage.boundary_ref,
        window_start=coverage.window.start,
        window_end=coverage.window.end,
    )
    scope = AssertionScope(
        boundary_ref=coverage.boundary_ref,
        window_start=coverage.window.start,
        window_end=coverage.window.end,
        action_families=action_families,
    )
    counts = _assertion_counts(coverage)
    assertions: list[CatalogueAssertion] = []
    if boundary_result.covered:
        assertions.append(A02BoundaryInForce(scope=scope, counts=counts))
    assertions.extend(
        (
            A03DenominatorQualified(
                scope=scope,
                counts=counts,
                denominator_class=coverage.denominator_class,
            ),
            A04PopulationMatched(
                scope=scope,
                counts=counts,
                population_count=coverage.denominator_count,
                matched_count=coverage.numerator_count,
                coverage_level=coverage.claimed_level,
            ),
        )
    )
    if coverage.gap_intervals:
        assertions.append(
            A05UnknownIntervals(scope=scope, counts=counts, gap_count=len(coverage.gap_intervals))
        )
    assertions.append(
        A06CoverageMinimum(
            scope=scope,
            counts=counts,
            evidence_supported_level=coverage.evidence_supported_level,
            class_admissible_level=coverage.class_admissible_level,
            claimed_level=coverage.claimed_level,
            capped_by_class=coverage.capped_by_class,
        )
    )
    outcome = _outcome_assertion(
        scope=scope,
        counts=counts,
        tenant_id=request.tenant_id,
        action_ids=request.outcome_action_ids,
        authoritative_source=request.authoritative_source,
        outcome_records=request.outcome_records,
    )
    if outcome is not None:
        assertions.append(outcome)

    exclusions: list[dict[str, Any]] = [
        {"kind": "standing_exclusion", "claim": exclusion.value} for exclusion in StandingExclusion
    ]
    outside_boundary = sorted(set(operated) - selected_boundary.declared_families)
    if outside_boundary:
        exclusions.append(
            {"kind": "operated_outside_boundary", "action_families": outside_boundary}
        )
    if boundary_result.uncovered:
        exclusions.append(
            {
                "kind": "boundary_not_in_force_for_full_window",
                "uncovered": [
                    {"start": start.isoformat(), "end": end.isoformat()}
                    for start, end in boundary_result.uncovered
                ],
            }
        )
    if coverage.ratio_state is RatioState.TRUNCATED_POPULATION:
        exclusions.append({"kind": "enumeration_truncated"})
    if request.authoritative_source is not None and outcome is None:
        exclusions.append(
            {
                "kind": "outcome_assertion_withheld",
                "authoritative_source": request.authoritative_source,
                "confirmed_action_count": 0,
            }
        )
    return AttestationAssembly(
        assertions=tuple(assertions),
        boundary_coverage=boundary_result,
        exclusions=tuple(exclusions),
    )


def issue_attestation(
    request: AttestationRequest,
    *,
    evidence_signer: EvidenceSigner,
    issuer_signer: IssuerSigner,
) -> IssuedAttestation:
    """Assemble, customer-sign, then issuer-counter-sign an AttestationWindow."""

    if not isinstance(evidence_signer, EvidenceSigner):
        raise AttestationInputError("AttestationWindow primary proof requires evidence signer")
    if not isinstance(issuer_signer, IssuerSigner):
        raise AttestationInputError("AttestationWindow counter-proof requires issuer signer")
    if request.validity_until <= request.validity_from:
        raise AttestationInputError("validity_until must be after validity_from")
    if request.sequence < 1:
        raise AttestationInputError("sequence must be positive")

    assembly = assemble_attestation(request)
    coverage_payload = request.coverage.to_payload()
    unsigned = validate_record(
        {
            "record_id": request.record_id,
            "record_type": "AttestationWindow",
            "schema_version": "1.0.0",
            "tenant_id": request.tenant_id,
            "boundary_ref": request.coverage.boundary_ref,
            "stream_id": request.stream_id,
            "sequence": request.sequence,
            "prev_digest": request.prev_digest,
            "source": _source_payload(request.source),
            "clocks": {"source_time": _timestamp(request.issued_at)},
            "body": {
                "boundary_ref": request.coverage.boundary_ref,
                "window_start": _timestamp(request.coverage.window.start),
                "window_end": _timestamp(request.coverage.window.end),
                "methodology_version": request.methodology_version,
                "denominator_class": request.coverage.denominator_class.value.upper(),
                "population_record_refs": [request.coverage.population_ref],
                "coverage_level": request.coverage.claimed_level.value,
                "verification_status": request.verification_status,
                # ES-017: copied as a required explicit value, including null.
                "coverage_ratio": coverage_payload["coverage_ratio"],
                "capped_by_class": request.coverage.capped_by_class,
                "counts": request.coverage.counts.as_dict(),
                "gaps": coverage_payload["gaps"],
                "assertions": [assertion_payload(assertion) for assertion in assembly.assertions],
                "exclusions": list(assembly.exclusions),
                "relying_parties": [
                    _relying_party_payload(party) for party in request.relying_parties
                ],
                "validity_from": _timestamp(request.validity_from),
                "validity_until": _timestamp(request.validity_until),
                "liability_ref": request.liability_ref,
                "issued_at": _timestamp(request.issued_at),
                "issuer": _issuer_payload(request.issuer),
                "verifier_version": request.verifier_version,
            },
            "signature": {},
        }
    )
    if not isinstance(unsigned, AttestationWindowRecord):  # pragma: no cover
        raise AttestationInputError("record dispatcher did not produce AttestationWindow")
    customer_signed = sign_record(
        unsigned,
        key_id=evidence_signer.key_id,
        private_key=evidence_signer.private_key,
    )
    issued = counter_sign_attestation(
        customer_signed,
        issuer_key_id=issuer_signer.key_id,
        issuer_private_key=issuer_signer.private_key,
    )
    return IssuedAttestation(record=issued, assembly=assembly)


__all__ = [
    "AttestationAssembly",
    "AttestationInputError",
    "AttestationRequest",
    "AttestationSource",
    "EvidenceSigner",
    "IssuerIdentity",
    "IssuedAttestation",
    "IssuerSigner",
    "RelyingParty",
    "StandingExclusion",
    "assemble_attestation",
    "issue_attestation",
]
