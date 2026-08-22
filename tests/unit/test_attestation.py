"""Focused EV-17 assertion-selection and issuance invariants."""

from __future__ import annotations

from dataclasses import fields, replace
from typing import get_args

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sdk_python.evidence.schema import OutcomeRecord, validate_record
from sdk_python.evidence.signing import verify_attestation_signatures
from services.admin.qualification import DenominatorClass
from services.attestation import (
    A01EvidenceChainValid,
    A02BoundaryInForce,
    A03DenominatorQualified,
    A04PopulationMatched,
    A05UnknownIntervals,
    A06CoverageMinimum,
    A07ReviewsRecorded,
    A08ReversibleReviews,
    A09OutcomesConfirmed,
    A10Reproducible,
    AttestationInputError,
    AttestationRequest,
    CatalogueAssertion,
    EvidenceSigner,
    IssuerSigner,
    assemble_attestation,
    assertion_payload,
    issue_attestation,
)
from tests.attestation_support import (
    attestation_request,
    boundary_version,
    coverage_report,
)
from tests.coverage_support import at

CATALOGUE_TYPES = {
    A01EvidenceChainValid,
    A02BoundaryInForce,
    A03DenominatorQualified,
    A04PopulationMatched,
    A05UnknownIntervals,
    A06CoverageMinimum,
    A07ReviewsRecorded,
    A08ReversibleReviews,
    A09OutcomesConfirmed,
    A10Reproducible,
}


def _signers() -> tuple[EvidenceSigner, IssuerSigner]:
    return (
        EvidenceSigner("evidence-key", Ed25519PrivateKey.generate()),
        IssuerSigner("issuer-key", Ed25519PrivateKey.generate()),
    )


def _outcome(
    *,
    source: str = "payments-ledger",
    disputed: bool = False,
    boundary_ref: str = "acme:boundary:1",
) -> OutcomeRecord:
    record = validate_record(
        {
            "record_id": "01890f47-2f58-7cc0-98c4-000000000909",
            "record_type": "OutcomeRecord",
            "schema_version": "1.0.0",
            "tenant_id": "acme",
            "boundary_ref": boundary_ref,
            "stream_id": "outcome-stream",
            "sequence": 1,
            "prev_digest": None,
            "source": {"collector": "future-outcome-adapter"},
            "clocks": {"source_time": at(10).isoformat(timespec="milliseconds")},
            "body": {
                "action_id": "action-0",
                "outcome_contract_ref": "contract:refund:1",
                "authoritative_source": source,
                "result": {"settled": True},
                "finalised_at": at(10).isoformat(timespec="milliseconds"),
                "disputed": disputed,
                "reversal_ref": None,
            },
            "signature": {},
        }
    )
    assert isinstance(record, OutcomeRecord)
    return record


def test_catalogue_is_a_closed_union_of_ten_distinct_constructors() -> None:
    assert set(get_args(CatalogueAssertion.__value__)) == CATALOGUE_TYPES
    assert {item.assertion_id for item in CATALOGUE_TYPES} == {  # type: ignore[attr-defined]
        f"A-{number:02d}" for number in range(1, 11)
    }
    assert all(
        "assertion_id" not in {field.name for field in fields(item)} for item in CATALOGUE_TYPES
    )


def test_renderer_has_no_residual_assertion_bucket() -> None:
    with pytest.raises(AssertionError, match="Expected code to be unreachable"):
        assertion_payload(object())  # type: ignore[arg-type]


def test_assembly_is_pure_and_never_accepts_caller_assertions() -> None:
    request = attestation_request()
    assert assemble_attestation(request) == assemble_attestation(request)
    assert "assertions" not in {field.name for field in fields(type(request))}


def test_boundary_partial_window_withholds_a02_and_reports_exact_uncovered_bounds() -> None:
    request = attestation_request(version=boundary_version(recorded_at=at(9, 30)))
    assembly = assemble_attestation(request)

    assert not any(isinstance(item, A02BoundaryInForce) for item in assembly.assertions)
    assert assembly.boundary_coverage.uncovered == ((at(9), at(9, 30)),)
    disclosure = next(
        item
        for item in assembly.exclusions
        if item["kind"] == "boundary_not_in_force_for_full_window"
    )
    assert disclosure["uncovered"] == [{"start": at(9).isoformat(), "end": at(9, 30).isoformat()}]


def test_a09_withheld_from_current_empty_outcome_record_set() -> None:
    assembly = assemble_attestation(attestation_request())

    assert not any(isinstance(item, A09OutcomesConfirmed) for item in assembly.assertions)
    disclosure = next(
        item for item in assembly.exclusions if item["kind"] == "outcome_assertion_withheld"
    )
    assert disclosure["authoritative_source"] == "payments-ledger"
    assert disclosure["confirmed_action_count"] == 0


def test_future_outcome_population_uses_the_same_selector_without_empty_special_case() -> None:
    request = replace(attestation_request(), outcome_records=(_outcome(),))
    assertion = next(
        item
        for item in assemble_attestation(request).assertions
        if isinstance(item, A09OutcomesConfirmed)
    )
    assert assertion.confirmed_action_ids == ("action-0",)
    assert assertion.authoritative_source == "payments-ledger"


@pytest.mark.parametrize(
    "outcome",
    [
        _outcome(source="other-ledger"),
        _outcome(disputed=True),
        _outcome(boundary_ref="acme:other:1"),
    ],
)
def test_a09_rejects_wrong_source_dispute_and_boundary(outcome: OutcomeRecord) -> None:
    request = replace(attestation_request(), outcome_records=(outcome,))
    assert not any(
        isinstance(item, A09OutcomesConfirmed) for item in assemble_attestation(request).assertions
    )


def test_issued_attestation_has_both_proofs_and_no_composite_field() -> None:
    evidence, issuer = _signers()
    issued = issue_attestation(
        attestation_request(), evidence_signer=evidence, issuer_signer=issuer
    )
    body = issued.record.body.model_dump(mode="json")

    assert verify_attestation_signatures(
        issued.record,
        evidence_public_keys={evidence.key_id: evidence.private_key.public_key()},
        issuer_public_keys={issuer.key_id: issuer.private_key.public_key()},
    ) == (evidence.key_id, issuer.key_id)
    forbidden = {"score", "rating", "grade", "overall", "summary"}
    assert forbidden.isdisjoint(body)
    for assertion in body["assertions"]:
        assert "scope" in assertion
        assert "counts" in assertion


@pytest.mark.parametrize("denominator_class", [DenominatorClass.C4, DenominatorClass.C5])
def test_null_ratio_is_explicit_in_signed_output(
    denominator_class: DenominatorClass,
) -> None:
    evidence, issuer = _signers()
    request = attestation_request(report=coverage_report(denominator_class))
    body = issue_attestation(
        request, evidence_signer=evidence, issuer_signer=issuer
    ).record.model_dump(mode="json")["body"]

    assert "coverage_ratio" in body
    assert body["coverage_ratio"] is None
    assert "capped_by_class" in body


def test_truncated_population_is_null_and_disclosed() -> None:
    evidence, issuer = _signers()
    request = attestation_request(report=coverage_report(result_cap_hit=True))
    body = issue_attestation(
        request, evidence_signer=evidence, issuer_signer=issuer
    ).record.model_dump(mode="json")["body"]

    assert body["coverage_ratio"] is None
    assert {item["kind"] for item in body["exclusions"]} >= {"enumeration_truncated"}


def test_operated_families_outside_boundary_are_disclosed() -> None:
    request = attestation_request(
        operated_action_families=("refund.issue", "refund.quote", "refund.cancel")
    )
    exclusion = next(
        item
        for item in assemble_attestation(request).exclusions
        if item["kind"] == "operated_outside_boundary"
    )
    assert exclusion["action_families"] == ["refund.cancel", "refund.quote"]


def test_signer_roles_cannot_be_swapped() -> None:
    evidence, issuer = _signers()
    request = attestation_request()
    with pytest.raises(AttestationInputError, match="primary proof requires evidence"):
        issue_attestation(
            request,
            evidence_signer=issuer,  # type: ignore[arg-type]
            issuer_signer=issuer,
        )
    with pytest.raises(AttestationInputError, match="counter-proof requires issuer"):
        issue_attestation(
            request,
            evidence_signer=evidence,
            issuer_signer=evidence,  # type: ignore[arg-type]
        )


def test_assertion_scope_refuses_action_family_outside_boundary() -> None:
    with pytest.raises(AttestationInputError, match="outside the boundary"):
        assemble_attestation(attestation_request(action_families=("refund.cancel",)))


def test_a02_is_never_emitted_while_es_032_minting_does_not_exist() -> None:
    """Unconditional withholding, including where AR-027 would be satisfied.

    This is the case every attempted gate got wrong: the boundary *did*
    enclose the window, so any check resting on a caller-supplied token of
    attestation emitted A-02 here. Nothing this system can mint attests the
    recording time, so the assertion is unavailable however good the interval
    looks.
    """
    assembly = assemble_attestation(attestation_request())

    # The interval is fine. The instant underneath it is what is unattested.
    assert assembly.boundary_coverage.covered
    assert not any(isinstance(item, A02BoundaryInForce) for item in assembly.assertions)
    # AR-027 forbids a narrower restatement in its place.
    assert all(item.assertion_id != "A-02" for item in assembly.assertions)


def test_no_request_field_can_re_enable_a02() -> None:
    """There is nothing for a caller to supply, correctly or otherwise.

    Successive gates were defeated through the very parameter that enabled
    them: a boolean is a claim, and a receipt carried with its own trust roots
    proves only that the caller signed with the caller's key. The absence of
    the parameter is the property worth pinning, because it is the one that
    cannot be got wrong.
    """
    import dataclasses

    fields = {field.name for field in dataclasses.fields(AttestationRequest)}
    assert "boundary_recording_attested" not in fields
    assert "boundary_recording" not in fields
    assert not any("attest" in name for name in fields)

    # No combination of the fields that do exist produces it either.
    for version in (boundary_version(), boundary_version(recorded_at=at(7))):
        assembly = assemble_attestation(attestation_request(version=version))
        assert all(item.assertion_id != "A-02" for item in assembly.assertions)
