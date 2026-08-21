"""Executable binding for ES-S-003."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pytest_bdd import given, parsers, scenario, then, when

from services.attestation import EvidenceSigner, IssuerSigner, issue_attestation
from tests.attestation_support import attestation_request
from tests.unit.test_oversight import human_review


@scenario(
    "../features/evidence.feature",
    "ES-S-003 Review after commitment is not effective oversight",
)
def test_review_after_commitment_is_not_effective_oversight() -> None:
    pass


@given(
    parsers.parse('a HumanReview with action_state_at_review "{state}"'),
    target_fixture="oversight_context",
)
def committed_review(state: str) -> dict[str, Any]:
    return {"review": human_review(state=state)}


@given(parsers.parse('decision "{decision}"'))
def approved(oversight_context: dict[str, Any], decision: str) -> None:
    assert oversight_context["review"].body.decision == decision


@when("oversight effectiveness is evaluated")
def evaluate(oversight_context: dict[str, Any]) -> None:
    review = oversight_context["review"]
    request = replace(
        attestation_request(),
        review_action_ids=(review.body.action_id,),
        human_reviews=(review,),
    )
    oversight_context["issued"] = issue_attestation(
        request,
        evidence_signer=EvidenceSigner("evidence-key", Ed25519PrivateKey.generate()),
        issuer_signer=IssuerSigner("issuer-key", Ed25519PrivateKey.generate()),
    )


@then("the review is not counted as effective oversight")
def not_effective(oversight_context: dict[str, Any]) -> None:
    assertions = oversight_context["issued"].record.body.assertions
    assert all(item["assertion_id"] != "A-08" for item in assertions)


@then('the attestation records it as "review after commitment"')
def attestation_reason(oversight_context: dict[str, Any]) -> None:
    exclusions = oversight_context["issued"].record.body.exclusions
    assert any(item.get("reason") == "review after commitment" for item in exclusions)
