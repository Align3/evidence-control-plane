"""Typed builders shared by EV-17 acceptance and unit tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta

from services.admin.boundary import BoundaryVersion, DeclaredFamily
from services.admin.qualification import DenominatorClass
from services.attestation import (
    AttestationRequest,
    AttestationSource,
    IssuerIdentity,
    RelyingParty,
)
from services.computation.coverage import CoverageReport, compute_coverage
from services.computation.reconciliation import ReconciliationStatus
from tests.coverage_support import (
    action_evidence,
    at,
    boundary,
    coverage_population,
    qualification,
    reconciliation_results,
)


def coverage_report(
    denominator_class: DenominatorClass = DenominatorClass.C1,
    *,
    result_cap_hit: bool = False,
) -> CoverageReport:
    statuses = [ReconciliationStatus.MATCHED]
    return compute_coverage(
        reconciliation_results=reconciliation_results(statuses),
        population=coverage_population(1, result_cap_hit=result_cap_hit),
        boundary=boundary(),
        qualification_history=(qualification(denominator_class),),
        action_evidence=action_evidence(statuses),
    )


def boundary_version(
    *,
    action_families: tuple[str, ...] = ("refund.issue",),
    recorded_at: datetime | None = None,
) -> BoundaryVersion:
    return BoundaryVersion(
        boundary_ref="acme:boundary:1",
        tenant_id="acme",
        name="boundary",
        version=1,
        window_start=at(8),
        window_end=at(12),
        recorded_at=recorded_at or at(8),
        families=tuple(
            DeclaredFamily(
                action_family=family,
                destination_system="payments",
                qualification_ref=f"qualification:{family}",
                fail_behaviour="fail_closed",
            )
            for family in action_families
        ),
    )


def attestation_request(
    *,
    report: CoverageReport | None = None,
    version: BoundaryVersion | None = None,
    action_families: tuple[str, ...] = ("refund.issue",),
    operated_action_families: tuple[str, ...] = ("refund.issue",),
    authoritative_source: str | None = "payments-ledger",
) -> AttestationRequest:
    return AttestationRequest(
        tenant_id="acme",
        record_id="01890f47-2f58-7cc0-98c4-000000000517",
        stream_id="attestation-stream",
        sequence=1,
        prev_digest=None,
        source=AttestationSource(service="attestation", version="0.1.0"),
        coverage=report or coverage_report(),
        boundary_versions=(version or boundary_version(),),
        action_families=action_families,
        operated_action_families=operated_action_families,
        review_action_ids=(),
        human_reviews=(),
        outcome_action_ids=("action-0",),
        authoritative_source=authoritative_source,
        outcome_records=(),
        methodology_version="0.1.0",
        verifier_version="0.1.0",
        verification_status="self_computed",
        relying_parties=(RelyingParty(name="buyer"),),
        validity_from=at(11),
        validity_until=at(11) + timedelta(days=30),
        liability_ref="terms:standard:1",
        issued_at=at(11),
        issuer=IssuerIdentity(name="Evidence Control Plane"),
    )


def with_report(request: AttestationRequest, report: CoverageReport) -> AttestationRequest:
    return replace(request, coverage=report)
