"""Offline integrity checks for the live Salesforce demo fixture set.

These assert **coherence**, not a remembered outcome. The matched count is
whatever the ledger and EV-15 produced when the set was generated, so a test
that pinned it to zero would pass for a fabricated zero and fail for a genuine
match -- exactly backwards. What is checked instead is that every number in the
set traces to the same computation: the reconciliation statuses agree with the
coverage counts, the coverage counts agree with the attestation body, and the
ratio is the ES-017 encoding of the numerator over the denominator.

Both published sets are checked by the same assertions, parameterised over the
fixture directory: the honest-zero set, where the ledger holds evidence that
names no enumerated record, and the honest-match set, where it names one. If a
rule held for only one of them it would be describing that run rather than the
pipeline.
"""

from __future__ import annotations

import base64
import json
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from sdk_python.evidence.bundle import parse_bundle
from sdk_python.evidence.canonical import canonicalize
from sdk_python.evidence.schema import (
    AssuranceBoundaryRecord,
    AttestationWindowRecord,
    ExternalConfirmationRecord,
    PopulationRecord,
    QualificationRecord,
    parse_record,
)
from sdk_python.evidence.signing import verify_attestation_signatures
from sdk_python.evidence.versions import (
    require_published_methodology_version,
    require_published_schema_version,
)
from services.computation.reconciliation import ReconciliationStatus, reconcile
from services.ingestion.receipts import (
    RegisteredPublicKey,
    verify_record_origin_signature,
)
from services.ledger import digest_bytes, digest_ref

FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "fixtures"
#: The honest-zero set and the honest-match set. Both come from one code path.
FIXTURE_SETS = ("salesforce-live", "salesforce-live-matched")
EVIDENCE_KEY_ID = "salesforce-live-evidence-dev-1"
ISSUER_KEY_ID = "salesforce-live-issuer-dev-1"

pytestmark = pytest.mark.parametrize("fixtures", FIXTURE_SETS)


def _json(fixtures: str, name: str) -> Any:
    return json.loads(
        (FIXTURE_ROOT / fixtures / name).read_text(encoding="utf-8")
    )


def _bytes(fixtures: str, name: str) -> bytes:
    return (FIXTURE_ROOT / fixtures / name).read_bytes()


def _public_key(value: str) -> Ed25519PublicKey:
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    return Ed25519PublicKey.from_public_bytes(raw)


def _keyring(fixtures: str) -> dict[str, RegisteredPublicKey]:
    keys = _json(fixtures, "09-manifest.json")["verification_keys"]
    return {
        key_id: RegisteredPublicKey(
            namespace=entry["namespace"],
            public_key=_public_key(entry["public_key_base64url"]),
        )
        for key_id, entry in keys.items()
    }


def _confirmations(fixtures: str) -> list[ExternalConfirmationRecord]:
    records = [
        parse_record(json.dumps(saved).encode("utf-8"))
        for saved in _json(fixtures, "05-external-confirmations.json")
    ]
    assert all(isinstance(record, ExternalConfirmationRecord) for record in records)
    return records  # type: ignore[return-value]


def test_live_population_and_confirmation_preserve_exact_connector_outputs(fixtures: str) -> None:
    population_observation = _json(fixtures, "02-population-observation.json")
    confirmation_observations = _json(fixtures, "04-confirmation-observations.json")
    population = parse_record(_bytes(fixtures, "03-population-record.json"))
    confirmations = _confirmations(fixtures)
    assert isinstance(population, PopulationRecord)
    assert len(confirmations) == len(confirmation_observations)

    assert population.body.model_dump(mode="json", exclude_unset=True) == (
        population_observation["body"]
    )
    assert population.source["connector"] == population_observation["source"]
    for confirmation, observation in zip(
        confirmations, confirmation_observations, strict=True
    ):
        assert confirmation.body.model_dump(mode="json", exclude_unset=True) == (
            observation["body"]
        )
        assert confirmation.source["connector"] == observation["source"]
        assert confirmation.body.destination_record_id in (
            population.body.record_identifiers or []
        )


def test_live_confirmation_action_ids_are_not_composed_from_the_case_id(fixtures: str) -> None:
    """EV-15 binds a confirmation to a receipt by action identity.

    An id composed from the destination record cannot equal one minted when
    the action was proposed, so composing one guarantees the matched case is
    unreachable -- silently, because every record stays well-formed.
    """
    for confirmation in _confirmations(fixtures):
        action_id = confirmation.body.action_id
        assert confirmation.body.destination_record_id not in action_id, (
            "a confirmation action id derived from the Case id can never bind "
            "to a ledger receipt"
        )


def test_live_fixture_versions_are_published(fixtures: str) -> None:
    """ES-035 and CM-025: a fixture signed under an unpublished version is
    refused by every conformant verifier, however well-formed it is."""
    manifest = _json(fixtures, "09-manifest.json")
    attestation = _json(fixtures, "08-attestation-window.json")

    for name in (
        "03-population-record.json",
        "08-attestation-window.json",
        "10-qualification-record.json",
        "11-assurance-boundary.json",
    ):
        require_published_schema_version(_json(fixtures, name)["schema_version"])
    require_published_methodology_version(
        attestation["body"]["methodology_version"]
    )
    assert manifest["schema_version"] == attestation["schema_version"]


def test_live_constitutive_records_are_signed_and_referenced(fixtures: str) -> None:
    """TM-013: the class a bundle claims must be checkable from the bundle.

    An attestation claiming C1 with no qualification assigning C1 before the
    window opens is refused by the independent verifier, correctly.
    """
    keyring = _keyring(fixtures)
    qualification = parse_record(
        _bytes(fixtures, "10-qualification-record.json")
    )
    boundary = parse_record(_bytes(fixtures, "11-assurance-boundary.json"))
    attestation = parse_record(_bytes(fixtures, "08-attestation-window.json"))
    assert isinstance(qualification, QualificationRecord)
    assert isinstance(boundary, AssuranceBoundaryRecord)
    assert isinstance(attestation, AttestationWindowRecord)

    # ES-033: both constitutive records carry an evidence-namespace proof.
    assert (
        verify_record_origin_signature(qualification, verification_keys=keyring)
        == EVIDENCE_KEY_ID
    )
    assert (
        verify_record_origin_signature(boundary, verification_keys=keyring)
        == EVIDENCE_KEY_ID
    )

    assert qualification.record_id in boundary.body.qualification_refs
    assert boundary.boundary_ref == attestation.body.boundary_ref
    assert qualification.body.assigned_class == attestation.body.denominator_class
    assert qualification.body.qualified_at < attestation.body.window_start


def test_live_signed_records_verify_with_published_fixture_keys(fixtures: str) -> None:
    keyring = _keyring(fixtures)
    evidence_key = keyring[EVIDENCE_KEY_ID].public_key
    issuer_key = keyring[ISSUER_KEY_ID].public_key
    population = parse_record(_bytes(fixtures, "03-population-record.json"))
    attestation = parse_record(_bytes(fixtures, "08-attestation-window.json"))
    assert isinstance(attestation, AttestationWindowRecord)

    # ES-033: hosted observations carry an issuer-namespace proof.
    assert (
        verify_record_origin_signature(population, verification_keys=keyring)
        == ISSUER_KEY_ID
    )
    for confirmation in _confirmations(fixtures):
        assert (
            verify_record_origin_signature(confirmation, verification_keys=keyring)
            == ISSUER_KEY_ID
        )
    assert verify_attestation_signatures(
        attestation,
        evidence_public_keys={EVIDENCE_KEY_ID: evidence_key},
        issuer_public_keys={ISSUER_KEY_ID: issuer_key},
    ) == (EVIDENCE_KEY_ID, ISSUER_KEY_ID)


def test_live_attestation_is_the_exact_canonical_wire_artifact(fixtures: str) -> None:
    """The committed verifier input is signed wire, not display JSON.

    Signature verification alone is insufficient here: reparsing a signed
    record and writing it with indentation preserves its semantic content and
    signed digest, but ES-001 correctly makes the independent verifier refuse
    those different received bytes as non-canonical.
    """
    received = _bytes(fixtures, "08-attestation-window.json")
    record = parse_record(received)

    assert isinstance(record, AttestationWindowRecord)
    assert received == canonicalize(record)


def test_live_bundle_parses_as_an_es_034_container(fixtures: str) -> None:
    """The published bundle is what a relying party actually verifies."""
    bundle = parse_bundle(
        _bytes(fixtures, "12-bundle.json"), verification_keys=_keyring(fixtures)
    )

    carried = {record.record_type for record in bundle.records}
    assert {
        "AssuranceBoundary",
        "QualificationRecord",
        "PopulationRecord",
        "AttestationWindow",
    } <= carried
    assert bundle.boundary is not None
    assert bundle.attestation.record_id == _json(fixtures, "08-attestation-window.json")[
        "record_id"
    ]


def test_live_matched_count_traces_to_the_ledger_read(fixtures: str) -> None:
    """The claim this fixture set exists to make.

    A matched count is only evidence if it came from somewhere. The manifest
    records the ledger read that produced it -- partition, record types, rows
    returned -- so a reader can tell a genuine zero from an evidence side that
    was never consulted. Without this block the number is an assertion; with
    it, it is checkable.
    """
    manifest = _json(fixtures, "09-manifest.json")
    ledger = manifest["evidence_ledger"]
    computation = manifest["computation"]
    reconciliation = _json(fixtures, "06-reconciliation-results.json")

    assert ledger["queried"] is True
    assert ledger["rows_returned"] == (
        ledger["action_proposals"] + ledger["execution_receipts"]
    )
    assert ledger["partition"].endswith(ledger["tenant_id"])

    matched = sum(item["status"] == "matched" for item in reconciliation)
    assert computation["matched_count"] == matched
    # A match requires evidence in the ledger; a zero-row read cannot produce
    # one. This is the property that fails loudly if the evidence side is ever
    # short-circuited again.
    if ledger["rows_returned"] == 0:
        assert matched == 0


def test_live_coverage_and_attestation_agree_with_reconciliation(fixtures: str) -> None:
    population = _json(fixtures, "03-population-record.json")
    reconciliation = _json(fixtures, "06-reconciliation-results.json")
    coverage = _json(fixtures, "07-coverage-report.json")
    attestation = _json(fixtures, "08-attestation-window.json")

    # Every population identity is classified exactly once (CM-012).
    identifiers = population["body"]["record_identifiers"]
    assert [item["destination_record_id"] for item in reconciliation] == identifiers
    assert len(reconciliation) == population["body"]["count"]

    counts: dict[str, int] = {}
    for item in reconciliation:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    for status, total in counts.items():
        assert coverage["counts"][status] == total, status
    assert sum(coverage["counts"].values()) == population["body"]["count"]

    assert coverage["population_ref"] == population["record_id"]
    assert coverage["numerator_count"] == counts.get("matched", 0)
    assert attestation["body"]["population_record_refs"] == [population["record_id"]]
    assert attestation["body"]["counts"] == coverage["counts"]
    assert attestation["body"]["coverage_ratio"] == coverage["coverage_ratio"]


def test_live_coverage_ratio_uses_the_es_017_encoding(fixtures: str) -> None:
    """ES-017: exactly four decimal places, out-of-scope excluded, truncated."""
    coverage = _json(fixtures, "07-coverage-report.json")
    ratio = coverage["coverage_ratio"]

    if coverage["ratio_state"] != "available":
        assert ratio is None
        return

    assert isinstance(ratio, str)
    assert ratio.split(".")[1] == ratio.split(".")[1].ljust(4, "0")
    assert len(ratio.split(".")[1]) == 4, "ES-017 forbids stripping trailing zeros"

    denominator = coverage["denominator_count"] - coverage["counts"]["out_of_scope"]
    expected = (
        Decimal(coverage["numerator_count"]) / Decimal(denominator)
        if denominator > 0
        else None
    )
    assert expected is not None
    assert Decimal(ratio) <= expected
    assert expected - Decimal(ratio) < Decimal("0.0001")


def test_live_reconciliation_reruns_from_the_published_artifacts(
    fixtures: str,
) -> None:
    """Re-derive the matched count instead of reading it.

    `matched_count` in the manifest is the generator's word for what EV-15
    produced. This runs EV-15 again over the published population, the
    published confirmations, and the exact ledger wire bytes -- so a set whose
    numbers were edited, or whose evidence was never published, fails here
    rather than being taken on trust.
    """
    published = _json(fixtures, "13-ledger-evidence.json")
    population = parse_record(_bytes(fixtures, "03-population-record.json"))
    assert isinstance(population, PopulationRecord)

    # Parsed from the received wire bytes, not from the convenience copy.
    evidence = tuple(
        parse_record(bytes.fromhex(item["received_wire_utf8_hex"]))
        for item in published
    )
    manifest = _json(fixtures, "09-manifest.json")
    assert len(evidence) == manifest["evidence_ledger"]["rows_returned"]

    results = reconcile(population, evidence, tuple(_confirmations(fixtures)))
    rederived = sum(
        result.status is ReconciliationStatus.MATCHED for result in results
    )

    assert rederived == manifest["computation"]["matched_count"]
    assert rederived == _json(fixtures, "07-coverage-report.json")["numerator_count"]
    # And the published per-record verdicts agree with the rerun.
    assert [result.status.value for result in results] == [
        item["status"] for item in _json(fixtures, "06-reconciliation-results.json")
    ]


def test_live_published_evidence_carries_its_ingestion_receipt(
    fixtures: str,
) -> None:
    """ES-030: the receipt is what makes a hosted observation checkable.

    A published evidence record without one is a record this service says it
    received, with nothing to distinguish that from a record it composed.
    """
    published = _json(fixtures, "13-ledger-evidence.json")
    assert published, "the reconciliation read no evidence to publish"

    for item in published:
        receipt = item.get("ingestion_receipt")
        assert receipt is not None, item["record"]["record_type"]
        payload = json.loads(bytes.fromhex(receipt["canonical_utf8_hex"]))
        # ES-030 fixes the payload to exactly these three members.
        assert set(payload) == {"record_digest", "ingest_time", "clock_skew_ms"}
        # The receipt binds the complete wire artifact, signature included.
        assert payload["record_digest"] == digest_ref(
            digest_bytes(bytes.fromhex(item["received_wire_utf8_hex"]))
        )


def test_live_bundle_carries_the_evidence_the_claim_rests_on(
    fixtures: str,
) -> None:
    """A matched count is not checkable from a bundle that omits its evidence."""
    bundle = parse_bundle(
        _bytes(fixtures, "12-bundle.json"), verification_keys=_keyring(fixtures)
    )
    carried = [record.record_type for record in bundle.records]
    published = _json(fixtures, "13-ledger-evidence.json")

    for item in published:
        assert item["record"]["record_id"] in {
            record.record_id for record in bundle.records
        }, f"{item['record']['record_type']} is missing from the bundle"
    assert carried.count("AttestationWindow") == 1
