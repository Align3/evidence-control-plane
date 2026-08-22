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
    assemble_with,
    attestation_request,
    boundary_version,
    coverage_report,
    issue_with,
)
from tests.coverage_support import at
from tests.unit.test_oversight import human_review

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
    assert assemble_with(request) == assemble_with(request)
    assert "assertions" not in {field.name for field in fields(type(request))}


def test_boundary_partial_window_withholds_a02_and_reports_exact_uncovered_bounds() -> None:
    request = attestation_request()
    version = boundary_version(recorded_at=at(9, 30), recording_time_attested=True)
    assembly = assemble_with(request, version)

    assert not any(isinstance(item, A02BoundaryInForce) for item in assembly.assertions)
    assert assembly.boundary_coverage.uncovered == ((at(9), at(9, 30)),)
    disclosure = next(
        item
        for item in assembly.exclusions
        if item["kind"] == "boundary_not_in_force_for_full_window"
    )
    assert disclosure["uncovered"] == [{"start": at(9).isoformat(), "end": at(9, 30).isoformat()}]


def test_a09_withheld_from_current_empty_outcome_record_set() -> None:
    assembly = assemble_with(attestation_request())

    assert not any(isinstance(item, A09OutcomesConfirmed) for item in assembly.assertions)
    disclosure = next(
        item for item in assembly.exclusions if item["kind"] == "outcome_assertion_withheld"
    )
    assert disclosure["authoritative_source"] == "payments-ledger"
    assert disclosure["confirmed_action_count"] == 0


def test_committed_review_is_recorded_but_never_asserted_as_reversible() -> None:
    request = replace(
        attestation_request(),
        review_action_ids=("action-1",),
        human_reviews=(human_review(state="committed"),),
    )
    assembly = assemble_with(request)

    recorded = next(item for item in assembly.assertions if isinstance(item, A07ReviewsRecorded))
    assert recorded.review_record_count == 1
    assert not any(isinstance(item, A08ReversibleReviews) for item in assembly.assertions)
    assert {
        "kind": "human_review_ineffective",
        "record_id": "01890f47-2f58-7cc0-98c4-000000000311",
        "action_id": "action-1",
        "reason": "review after commitment",
    } in assembly.exclusions


def test_timely_review_selects_a08_once_per_action() -> None:
    request = replace(
        attestation_request(),
        review_action_ids=("action-1",),
        human_reviews=(
            human_review(),
            human_review(record_id="01890f47-2f58-7cc0-98c4-000000000312"),
        ),
    )
    assembly = assemble_with(request)

    recorded = next(item for item in assembly.assertions if isinstance(item, A07ReviewsRecorded))
    reversible = next(
        item for item in assembly.assertions if isinstance(item, A08ReversibleReviews)
    )
    assert recorded.review_record_count == 2
    assert reversible.reversible_review_count == 1


def test_server_reconstructed_review_caps_attestation_claim() -> None:
    request = replace(
        attestation_request(),
        review_action_ids=("action-1",),
        human_reviews=(human_review(provenance="server_reconstructed"),),
    )
    assembly = assemble_with(request)

    assert any(isinstance(item, A07ReviewsRecorded) for item in assembly.assertions)
    assert not any(isinstance(item, A08ReversibleReviews) for item in assembly.assertions)
    assert any(
        item.get("reason") == "server-reconstructed evidence"
        for item in assembly.exclusions
    )


def test_missing_required_review_is_disclosed_without_oversight_assertions() -> None:
    request = replace(attestation_request(), review_action_ids=("action-1",))
    assembly = assemble_with(request)

    assert not any(
        isinstance(item, (A07ReviewsRecorded, A08ReversibleReviews))
        for item in assembly.assertions
    )
    assert {"kind": "human_review_missing", "action_ids": ["action-1"]} in assembly.exclusions


def test_issued_attestation_signs_late_review_reason() -> None:
    evidence, issuer = _signers()
    request = replace(
        attestation_request(),
        review_action_ids=("action-1",),
        human_reviews=(human_review(state="committed"),),
    )
    body = issue_with(
        request, evidence_signer=evidence, issuer_signer=issuer
    ).record.body.model_dump(mode="json")

    assert any(
        item.get("kind") == "human_review_ineffective"
        and item.get("reason") == "review after commitment"
        for item in body["exclusions"]
    )


def test_future_outcome_population_uses_the_same_selector_without_empty_special_case() -> None:
    request = replace(attestation_request(), outcome_records=(_outcome(),))
    assertion = next(
        item
        for item in assemble_with(request).assertions
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
        isinstance(item, A09OutcomesConfirmed) for item in assemble_with(request).assertions
    )


def test_issued_attestation_has_both_proofs_and_no_composite_field() -> None:
    evidence, issuer = _signers()
    issued = issue_with(
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
    body = issue_with(
        request, evidence_signer=evidence, issuer_signer=issuer
    ).record.model_dump(mode="json")["body"]

    assert "coverage_ratio" in body
    assert body["coverage_ratio"] is None
    assert "capped_by_class" in body


def test_truncated_population_is_null_and_disclosed() -> None:
    evidence, issuer = _signers()
    request = attestation_request(report=coverage_report(result_cap_hit=True))
    body = issue_with(
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
        for item in assemble_with(request).exclusions
        if item["kind"] == "operated_outside_boundary"
    )
    assert exclusion["action_families"] == ["refund.cancel", "refund.quote"]


def test_signer_roles_cannot_be_swapped() -> None:
    evidence, issuer = _signers()
    request = attestation_request()
    with pytest.raises(AttestationInputError, match="primary proof requires evidence"):
        issue_with(
            request,
            evidence_signer=issuer,  # type: ignore[arg-type]
            issuer_signer=issuer,
        )
    with pytest.raises(AttestationInputError, match="counter-proof requires issuer"):
        issue_with(
            request,
            evidence_signer=evidence,
            issuer_signer=evidence,  # type: ignore[arg-type]
        )


def test_assertion_scope_refuses_action_family_outside_boundary() -> None:
    with pytest.raises(AttestationInputError, match="outside the boundary"):
        assemble_with(attestation_request(action_families=("refund.cancel",)))


def test_a02_is_emitted_when_an_attested_recording_covered_the_window() -> None:
    """The positive path, which nothing else asserts.

    Every other A-02 test asserts absence -- here, in the step suite, and in
    the interval-coverage unit tests. Without this, a change that withheld
    A-02 unconditionally would pass the entire suite while silently removing
    the assertion from every attestation the product issues. That is not
    hypothetical: an earlier revision of this branch did exactly that, and
    only this test distinguishes the two behaviours.
    """
    assembly = assemble_with(attestation_request())

    assert assembly.boundary_coverage.covered
    assert any(isinstance(item, A02BoundaryInForce) for item in assembly.assertions)


def test_a02_is_withheld_when_the_recording_time_is_unattested() -> None:
    """ES-032, reached through EV-31's re-verified receipt rather than a flag.

    `recording_time_attested` is derived by `boundary_versions` re-checking
    the stored issuer receipt against the registered keys, so this models a
    boundary whose receipt does not verify. The interval arithmetic never
    runs on the unattested instant.
    """
    request = attestation_request()
    version = boundary_version(recording_time_attested=False)

    assembly = assemble_with(request, version)

    assert not assembly.boundary_coverage.covered
    assert not any(isinstance(item, A02BoundaryInForce) for item in assembly.assertions)
    # AR-027 forbids a narrower restatement in its place.
    assert all(item.assertion_id != "A-02" for item in assembly.assertions)


def test_issuance_accepts_no_caller_supplied_boundary_history() -> None:
    """The request carries no boundary history, receipt, keyring, or flag.

    Checking top-level field names alone is not enough and was the hole in an
    earlier version of this test: the bypass lived one level down, in a
    caller-constructed `BoundaryVersion(recording_time_attested=True)` reached
    through a `boundary_versions` field. The history is loaded from the ledger
    now, so there is nothing nested to fabricate either.
    """
    import dataclasses

    fields = {field.name for field in dataclasses.fields(AttestationRequest)}
    for forbidden in ("boundary_versions", "boundary_recording", "receipt"):
        assert not any(forbidden in name for name in fields), forbidden
    assert not any("attested" in name or "verification_key" in name for name in fields)

    # And the public entry points require a connection, so there is no
    # signature through which a history could be passed instead.
    import inspect

    for entry in (assemble_attestation, issue_attestation):
        assert "connection" in inspect.signature(entry).parameters, entry.__name__


def test_a_fabricated_attested_boundary_version_cannot_reach_issuance() -> None:
    """The reviewer's construction: a hand-built version claiming attestation.

    `BoundaryVersion` is an ordinary dataclass, so one can always be built
    with `recording_time_attested=True` and caller-chosen window bounds. What
    must not exist is a route from there into issuance. There is no such
    parameter, and the public entry points read the history from the ledger.
    """
    import dataclasses

    fabricated = boundary_version(recording_time_attested=True)
    assert fabricated.recording_time_attested is True

    with pytest.raises(TypeError):
        dataclasses.replace(attestation_request(), boundary_versions=(fabricated,))
    with pytest.raises(TypeError):
        assemble_attestation(attestation_request(), boundary_versions=(fabricated,))  # type: ignore[call-arg]


def test_boundary_version_is_unattested_unless_something_says_otherwise() -> None:
    """Defence in depth: the dangerous value is not the default.

    A version built without mentioning the field is unattested, so code that
    forgets it withholds A-02 rather than asserting it.
    """
    from services.admin.boundary import BoundaryVersion

    bare = BoundaryVersion(
        boundary_ref="acme:boundary:1",
        tenant_id="acme",
        name="boundary",
        version=1,
        window_start=at(8),
        window_end=at(12),
        recorded_at=at(8),
        families=(),
    )

    assert bare.recording_time_attested is False