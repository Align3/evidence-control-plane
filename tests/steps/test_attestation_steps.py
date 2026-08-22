"""Executable acceptance bindings for EV-17 attestation issuance."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pytest_bdd import given, scenario, then, when

from sdk_python.evidence.canonical import canonicalize
from sdk_python.evidence.schema import validate_record
from sdk_python.evidence.signing import sign_record
from services.admin.qualification import DenominatorClass
from services.attestation import (
    A02BoundaryInForce,
    A09OutcomesConfirmed,
    CatalogueAssertion,
    EvidenceSigner,
    IssuerSigner,
    assertion_payload,
)
from services.ingestion.receipts import (
    KeyNamespaceError,
    RegisteredPublicKey,
    verify_canonical_evidence_record,
)
from tests.attestation_support import (
    assemble_with,
    attestation_request,
    boundary_version,
    coverage_report,
    issue_with,
)
from tests.coverage_support import at


@scenario("attestation.feature", "AR-S-001 No assertion outside the catalogue")
def test_ar_s_001() -> None:
    """Only the ten typed constructors can enter an attestation."""


@scenario("attestation.feature", "AR-S-002 No aggregate score")
def test_ar_s_002() -> None:
    """Assertions remain independently scoped and counted."""


@scenario("attestation.feature", "AR-S-003 Excluded scope disclosed")
def test_ar_s_003() -> None:
    """Operated families beyond the selected boundary remain visible."""


@scenario(
    "attestation.feature",
    "AR-S-007 A-02 is withheld where the boundary did not span the window",
)
def test_ar_s_007() -> None:
    """EV-12 arithmetic drives EV-17 assertion selection."""


@scenario(
    "attestation.feature",
    "AR-S-008 A-09 is withheld where outcomes were not confirmed",
)
def test_ar_s_008() -> None:
    """The present empty OutcomeRecord set cannot support A-09."""


@scenario("evidence.feature", "ES-S-002 Truncated enumeration blocks ratio")
def test_es_s_002_attestation() -> None:
    """EV-17 preserves EV-16's null and renders the truncation disclosure."""


@scenario("evidence.feature", "ES-S-006 Null ratio is explicit, not omitted")
def test_es_s_006_attestation() -> None:
    """A signed C5 window serializes the explicit null field."""


@scenario(
    "evidence.feature",
    "ES-S-017 An unattested recording time withholds the boundary assertion",
)
def test_es_s_017_constitutive_receipt() -> None:
    """A stored timestamp has no standing without its issuer receipt."""


@scenario("security.feature", "SE-S-001 Issuer cannot sign evidence records")
def test_se_s_001_attestation() -> None:
    """The issuer key remains counter-signature-only for customer evidence."""


def _issue(context: dict[str, Any]) -> None:
    evidence_key = Ed25519PrivateKey.generate()
    issuer_key = Ed25519PrivateKey.generate()
    context["issued"] = issue_with(
        context["request"],
        evidence_signer=EvidenceSigner("evidence-key", evidence_key),
        issuer_signer=IssuerSigner("issuer-key", issuer_key),
        version=context.get("version"),
    )


@given("an attestation generation request", target_fixture="attestation_context")
def generation_request() -> dict[str, Any]:
    return {"request": attestation_request()}


@when("the assertion set is assembled")
def assertion_set_assembled(attestation_context: dict[str, Any]) -> None:
    attestation_context["assembly"] = assemble_with(
        attestation_context["request"], attestation_context.get("version")
    )


@then("every assertion maps to a catalogue ID")
def every_assertion_catalogued(attestation_context: dict[str, Any]) -> None:
    assertions: tuple[CatalogueAssertion, ...] = attestation_context["assembly"].assertions
    assert assertions
    catalogue_ids = {f"A-{number:02d}" for number in range(1, 11)}
    assert all(assertion.assertion_id in catalogue_ids for assertion in assertions)


@then("any unmapped assertion causes generation to fail")
def unmapped_assertion_fails() -> None:
    with pytest.raises(AssertionError):
        assertion_payload(object())  # type: ignore[arg-type]


@when("an attestation is rendered", target_fixture="attestation_context")
def attestation_rendered() -> dict[str, Any]:
    context: dict[str, Any] = {"request": attestation_request()}
    _issue(context)
    return context


def _keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | set().union(*(_keys(item) for item in value.values()), set())
    if isinstance(value, list):
        return set().union(*(_keys(item) for item in value), set())
    return set()


@then("no single composite score, rating, or grade appears")
def no_composite(attestation_context: dict[str, Any]) -> None:
    body = attestation_context["issued"].record.body.model_dump(mode="json")
    assert {"score", "rating", "grade", "overall", "summary"}.isdisjoint(_keys(body))


@then("each assertion carries its own scope and counts")
def each_assertion_scoped(attestation_context: dict[str, Any]) -> None:
    assertions = attestation_context["issued"].record.body.assertions
    assert assertions
    assert all("scope" in item and "counts" in item for item in assertions)


@given(
    "a customer operating action families [X, Y, Z]",
    target_fixture="attestation_context",
)
def three_operated_families() -> dict[str, Any]:
    return {
        "request": attestation_request(
            action_families=("X",),
            operated_action_families=("X", "Y", "Z"),
        ),
        "version": boundary_version(
            action_families=("X",), recording_time_attested=True
        ),
    }


@given("a boundary covering only [X]")
def boundary_only_x(attestation_context: dict[str, Any]) -> None:
    assert attestation_context["version"].declared_families == {"X"}


@when("an attestation is issued")
@when("the attestation is generated")
@when("an attestation referencing that boundary version is generated")
def attestation_generated(attestation_context: dict[str, Any]) -> None:
    _issue(attestation_context)


@then("it states that other families exist and are out of scope")
def other_families_disclosed(attestation_context: dict[str, Any]) -> None:
    exclusions = attestation_context["issued"].record.body.exclusions
    disclosure = next(item for item in exclusions if item["kind"] == "operated_outside_boundary")
    assert disclosure["action_families"] == ["Y", "Z"]


@given(
    "the referenced assurance boundary version has effective interval B1 to B2 "
    "after applying its declared window, signed ingest time, and any next version",
    target_fixture="attestation_context",
)
def partial_boundary() -> dict[str, Any]:
    return {
        "request": attestation_request(),
        "version": boundary_version(recorded_at=at(9, 30), recording_time_attested=True),
    }


@given(
    "an AssuranceBoundary recorded without an issuer-signed receipt",
    target_fixture="attestation_context",
)
def boundary_without_receipt() -> dict[str, Any]:
    return {
        "request": attestation_request(),
        "version": boundary_version(recording_time_attested=False),
    }


@given("an attestation window from W1 to W2 where W1 < B1 or W2 > B2")
def window_extends_boundary(attestation_context: dict[str, Any]) -> None:
    request = attestation_context["request"]
    assert request.coverage.window.start < attestation_context["version"].recorded_at


@then("A-02 is withheld")
def a02_withheld(attestation_context: dict[str, Any]) -> None:
    assert not any(
        isinstance(item, A02BoundaryInForce)
        for item in attestation_context["issued"].assembly.assertions
    )


@then("the uncovered interval is reported with its bounds")
def uncovered_reported(attestation_context: dict[str, Any]) -> None:
    coverage = attestation_context["issued"].assembly.boundary_coverage
    assert coverage.uncovered == ((at(9), at(9, 30)),)


@then("the effective interval is not computed from the stored recording time")
def no_effective_interval_from_unattested_time(
    attestation_context: dict[str, Any],
) -> None:
    coverage = attestation_context["issued"].assembly.boundary_coverage
    assert coverage.effective is None


@then("no narrower restatement of A-02 is emitted in its place")
def no_narrow_a02(attestation_context: dict[str, Any]) -> None:
    body_assertions = attestation_context["issued"].record.body.assertions
    assert all(item["assertion_id"] != "A-02" for item in body_assertions)


@given(
    "R actions claimed as confirmed against a named authoritative source",
    target_fixture="attestation_context",
)
def named_outcome_source() -> dict[str, Any]:
    return {"request": attestation_request(authoritative_source="payments-ledger")}


@given("S of them have no OutcomeRecord whose authoritative_source matches that source")
def no_matching_outcomes(attestation_context: dict[str, Any]) -> None:
    assert attestation_context["request"].outcome_records == ()


@then("A-09 is withheld unless R is restated as R - S")
def a09_withheld(attestation_context: dict[str, Any]) -> None:
    assert not any(
        isinstance(item, A09OutcomesConfirmed)
        for item in attestation_context["issued"].assembly.assertions
    )


@then("the named source is identified in the attestation")
def outcome_source_identified(attestation_context: dict[str, Any]) -> None:
    exclusion = next(
        item
        for item in attestation_context["issued"].record.body.exclusions
        if item["kind"] == "outcome_assertion_withheld"
    )
    assert exclusion["authoritative_source"] == "payments-ledger"


@then("an unnamed or absent source withholds A-09 outright")
def absent_source_withholds_a09(attestation_context: dict[str, Any]) -> None:
    request = replace(attestation_context["request"], authoritative_source=None)
    assert not any(
        isinstance(item, A09OutcomesConfirmed) for item in assemble_with(request).assertions
    )


@given("a PopulationRecord with result_cap_hit true", target_fixture="attestation_context")
def truncated_population() -> dict[str, Any]:
    return {"request": attestation_request(report=coverage_report(result_cap_hit=True))}


@when("an attestation window is generated")
def attestation_window_generated(attestation_context: dict[str, Any]) -> None:
    _issue(attestation_context)


@then("coverage_ratio is null")
def ratio_null(attestation_context: dict[str, Any]) -> None:
    assert attestation_context["issued"].record.body.coverage_ratio is None


@then("the attestation states that enumeration was truncated")
def truncation_disclosed(attestation_context: dict[str, Any]) -> None:
    assert any(
        item["kind"] == "enumeration_truncated"
        for item in attestation_context["issued"].record.body.exclusions
    )


@given("denominator_class C5", target_fixture="attestation_context")
def denominator_c5() -> dict[str, Any]:
    return {"request": attestation_request(report=coverage_report(DenominatorClass.C5))}


@when("an AttestationWindow is serialized")
def attestation_serialized(attestation_context: dict[str, Any]) -> None:
    _issue(attestation_context)
    attestation_context["serialized"] = attestation_context["issued"].record.model_dump(mode="json")


@then("coverage_ratio is present with value null")
def explicit_null(attestation_context: dict[str, Any]) -> None:
    assert attestation_context["serialized"]["body"]["coverage_ratio"] is None


@then("the record does not omit the field")
def ratio_not_omitted(attestation_context: dict[str, Any]) -> None:
    assert "coverage_ratio" in attestation_context["serialized"]["body"]


@given("the issuer counter-signing key", target_fixture="namespace_context")
def issuer_counter_key() -> dict[str, Any]:
    return {"key": Ed25519PrivateKey.generate()}


@when("an attempt is made to sign an evidence record with it")
def issuer_signs_evidence(namespace_context: dict[str, Any]) -> None:
    raw = {
        "record_id": "01890f47-2f58-7cc0-98c4-000000000701",
        "record_type": "AgentIdentity",
        "schema_version": "1.0.0",
        "tenant_id": "acme",
        "boundary_ref": "acme:boundary:1",
        "stream_id": "collector-1",
        "sequence": 1,
        "prev_digest": None,
        "source": {"collector": "sdk-python"},
        "clocks": {"source_time": at(10).isoformat(timespec="milliseconds")},
        "body": {
            "agent_id": "agent-1",
            "deployment": "prod",
            "runtime": "python-3.12",
            "tenant_scope": "acme",
            "service_identity": "agent@example.invalid",
            "model_versions": ["model-1"],
            "tool_versions": ["tool-1"],
            "credential_ref": "service_identity",
        },
        "signature": {},
    }
    record = validate_record(raw)
    signed = sign_record(record, key_id="issuer-key", private_key=namespace_context["key"])
    try:
        verify_canonical_evidence_record(
            canonicalize(signed),
            verification_keys={
                "issuer-key": RegisteredPublicKey(
                    namespace="issuer", public_key=namespace_context["key"].public_key()
                )
            },
        )
    except KeyNamespaceError as error:
        namespace_context["error"] = str(error)


@then("the record is rejected at ingestion")
def rejected_at_ingestion(namespace_context: dict[str, Any]) -> None:
    assert "error" in namespace_context


@then('the rejection reason is "key namespace mismatch"')
def namespace_mismatch(namespace_context: dict[str, Any]) -> None:
    assert "key namespace mismatch" in namespace_context["error"]
