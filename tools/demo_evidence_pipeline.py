#!/usr/bin/env python3
"""Narrated, reproducible walkthrough of the committed evidence fixtures.

Nothing in this demo regenerates data.  Every displayed claim is checked against
the committed fixture that supplies it, and the attestation records are handed
to the repository's Go verifier as their exact on-disk bytes.
"""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

# Running a file under tools/ makes that directory Python's import root.  Add
# the repository itself so this remains a runnable script without requiring an
# editable package install; third-party dependencies still come from the
# project's normal environment.
REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: E402

from sdk_python.evidence.schema import (  # noqa: E402
    AttestationWindowRecord,
    ExecutionReceiptRecord,
    HumanReviewRecord,
    IngestionReceipt,
    parse_record,
)
from services.computation.oversight import evaluate_review  # noqa: E402
from services.ingestion.receipts import (  # noqa: E402
    RegisteredPublicKey,
    SignedIngestionReceipt,
    verify_ingestion_receipt,
    verify_record_origin_signature,
)

FIXTURE_ROOT = REPO / "tests" / "fixtures"
VERIFIER_DIR = REPO / "verifier-go"
GO_VERIFIER_UNCERTAIN_EXIT = 3

FIXTURE_FILES = (
    "03-population-record.json",
    "06-reconciliation-results.json",
    "07-coverage-report.json",
    "08-attestation-window.json",
    "09-manifest.json",
    "12-bundle.json",
    "13-ledger-evidence.json",
)


class DemoError(RuntimeError):
    """A committed artifact does not support the claim the demo would print."""


@dataclass(frozen=True, slots=True)
class FixtureFacts:
    label: str
    directory: Path
    population_count: int
    matched_count: int
    coverage_ratio: str
    case_id: str
    reconciliation_status: str
    action_id: str | None
    proposal_record_id: str | None
    receipt_record_id: str | None
    verification_as_of: str


@dataclass(frozen=True, slots=True)
class OversightFacts:
    label: str
    population_count: int
    matched_count: int
    coverage_ratio: str
    a08_present: bool
    ineffective_exclusion: bool
    review_offset_ms: int
    effective: bool
    decision: str


def _json(path: Path) -> Any:
    try:
        return json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise DemoError(f"cannot read {path.relative_to(REPO)}: {exc}") from exc


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise DemoError(message)


def _executable(name: str) -> str:
    resolved = shutil.which(name)
    if resolved is None:
        raise DemoError(f"{name!r} is required for this demo")
    return resolved


def _relative(path: Path) -> str:
    return str(path.relative_to(REPO))


def _require_committed(paths: tuple[Path, ...]) -> None:
    """Refuse to demonstrate working-tree data as if it were committed evidence."""

    git = _executable("git")
    relative_paths = [_relative(path) for path in paths]
    tracked = subprocess.run(  # noqa: S603
        [git, "ls-files", "--error-unmatch", "--", *relative_paths],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    if tracked.returncode != 0:
        raise DemoError("demo input is not committed: " + tracked.stderr.strip())
    changed = subprocess.run(  # noqa: S603
        [git, "diff", "--quiet", "HEAD", "--", *relative_paths],
        cwd=REPO,
        check=False,
    )
    if changed.returncode != 0:
        raise DemoError("demo input differs from HEAD; refusing to present it as committed")


def _decode_base64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _verification_keys(manifest: dict[str, Any]) -> dict[str, RegisteredPublicKey]:
    raw_keys = manifest.get("verification_keys")
    if not isinstance(raw_keys, dict):
        raise DemoError("manifest verification_keys must be an object")
    result: dict[str, RegisteredPublicKey] = {}
    for key_id, raw_key in raw_keys.items():
        _require(isinstance(key_id, str), "manifest key ids must be strings")
        _require(isinstance(raw_key, dict), f"manifest key {key_id!r} must be an object")
        namespace = raw_key.get("namespace")
        encoded_key = raw_key.get("public_key_base64url")
        _require(isinstance(namespace, str), f"manifest key {key_id!r} has no namespace")
        _require(isinstance(encoded_key, str), f"manifest key {key_id!r} has no public key")
        result[key_id] = RegisteredPublicKey(
            namespace=namespace,
            public_key=Ed25519PublicKey.from_public_bytes(_decode_base64url(encoded_key)),
        )
    return result


def _verified_ledger_records(
    ledger_document: Any,
    *,
    keys: dict[str, RegisteredPublicKey],
) -> list[Any]:
    """Return records only after verifying their signatures and ES-030 receipts."""

    _require(isinstance(ledger_document, list), "ledger evidence must be a JSON array")
    verified: list[Any] = []
    for index, item in enumerate(ledger_document):
        _require(isinstance(item, dict), f"ledger item {index} must be an object")
        wire_hex = item.get("received_wire_utf8_hex")
        raw_receipt = item.get("ingestion_receipt")
        _require(isinstance(wire_hex, str), f"ledger item {index} has no received wire")
        _require(isinstance(raw_receipt, dict), f"ledger item {index} has no receipt")
        wire = bytes.fromhex(wire_hex)
        record = parse_record(wire)
        _require(
            json.loads(wire) == item.get("record"),
            f"ledger item {index} display record differs from received wire",
        )
        verify_record_origin_signature(record, verification_keys=keys)

        receipt_hex = raw_receipt.get("canonical_utf8_hex")
        receipt_key_id = raw_receipt.get("key_id")
        receipt_signature = raw_receipt.get("signature_base64url")
        _require(isinstance(receipt_hex, str), f"ledger item {index} receipt has no bytes")
        _require(isinstance(receipt_key_id, str), f"ledger item {index} receipt has no key")
        _require(
            isinstance(receipt_signature, str),
            f"ledger item {index} receipt has no signature",
        )
        receipt_bytes = bytes.fromhex(receipt_hex)
        receipt = SignedIngestionReceipt(
            payload=IngestionReceipt.model_validate_json(receipt_bytes),
            canonical_bytes=receipt_bytes,
            key_id=receipt_key_id,
            signature=_decode_base64url(receipt_signature),
        )
        verify_ingestion_receipt(
            receipt,
            record=record,
            verification_keys=keys,
            received_wire_bytes=wire,
        )
        verified.append(record)
    return verified


def _load_fixture(label: str, directory_name: str, *, expected_match: bool) -> FixtureFacts:
    directory = FIXTURE_ROOT / directory_name
    paths = tuple(directory / name for name in FIXTURE_FILES)
    _require_committed(paths)

    population = _json(directory / "03-population-record.json")
    reconciliation = _json(directory / "06-reconciliation-results.json")
    coverage = _json(directory / "07-coverage-report.json")
    attestation = _json(directory / "08-attestation-window.json")
    manifest = _json(directory / "09-manifest.json")
    ledger = _json(directory / "13-ledger-evidence.json")
    for name, document in (
        ("population", population),
        ("coverage", coverage),
        ("attestation", attestation),
        ("manifest", manifest),
    ):
        _require(isinstance(document, dict), f"{label} {name} must be an object")
    _require(isinstance(reconciliation, list), f"{label} reconciliation must be an array")

    population_body = population.get("body")
    _require(isinstance(population_body, dict), f"{label} population has no body")
    identifiers = population_body.get("record_identifiers")
    population_count = population_body.get("count")
    _require(isinstance(identifiers, list), f"{label} population identifiers must be an array")
    _require(
        population_count == len(identifiers) == 1 and isinstance(identifiers[0], str),
        f"{label} demo requires exactly one enumerated Case",
    )
    case_id = identifiers[0]
    _require(len(reconciliation) == 1, f"{label} requires one reconciliation result")
    result = reconciliation[0]
    _require(isinstance(result, dict), f"{label} reconciliation result must be an object")
    matched_count = coverage.get("numerator_count")
    denominator_count = coverage.get("denominator_count")
    coverage_ratio = coverage.get("coverage_ratio")
    expected_count = 1 if expected_match else 0
    expected_ratio = "1.0000" if expected_match else "0.0000"
    expected_status = "matched" if expected_match else "unmatched_without_evidence"
    _require(
        matched_count == expected_count
        and denominator_count == population_count
        and coverage_ratio == expected_ratio,
        f"{label} coverage does not support the expected {expected_count}/{population_count}",
    )
    _require(result.get("destination_record_id") == case_id, f"{label} result names another Case")
    _require(
        result.get("status") == expected_status,
        f"{label} has unexpected reconciliation status",
    )
    _require(
        result.get("population_ref")
        == population.get("record_id")
        == coverage.get("population_ref"),
        f"{label} population references disagree",
    )

    attestation_body = attestation.get("body")
    computation = manifest.get("computation")
    ledger_provenance = manifest.get("evidence_ledger")
    _require(isinstance(attestation_body, dict), f"{label} attestation has no body")
    _require(isinstance(computation, dict), f"{label} manifest has no computation")
    _require(isinstance(ledger_provenance, dict), f"{label} manifest has no ledger provenance")
    _require(
        attestation_body.get("coverage_ratio") == coverage_ratio
        and attestation_body.get("counts") == coverage.get("counts"),
        f"{label} attestation and coverage report disagree",
    )
    verification_as_of = attestation_body.get("issued_at")
    _require(isinstance(verification_as_of, str), f"{label} attestation has no issued_at")
    _require(
        computation.get("population_count") == population_count
        and computation.get("matched_count") == matched_count
        and computation.get("coverage_ratio") == coverage_ratio,
        f"{label} manifest and pipeline outputs disagree",
    )

    keys = _verification_keys(manifest)
    records = _verified_ledger_records(ledger, keys=keys)
    _require(ledger_provenance.get("queried") is True, f"{label} ledger was not queried")
    _require(
        ledger_provenance.get("rows_returned") == len(records),
        f"{label} ledger provenance row count disagrees with published evidence",
    )
    proposals = [record for record in records if record.record_type == "ActionProposal"]
    receipts = [record for record in records if record.record_type == "ExecutionReceipt"]
    _require(
        ledger_provenance.get("action_proposals") == len(proposals)
        and ledger_provenance.get("execution_receipts") == len(receipts),
        f"{label} ledger type counts disagree with published evidence",
    )
    matching_receipts = [
        record for record in receipts if record.body.destination_record_ref == case_id
    ]
    action_id = result.get("action_id")
    _require(action_id is None or isinstance(action_id, str), f"{label} has invalid action_id")

    proposal_id: str | None = None
    receipt_id: str | None = None
    if expected_match:
        _require(isinstance(action_id, str), f"{label} match has no action id")
        _require(len(matching_receipts) == 1, f"{label} has no unique receipt for its Case")
        matching_proposals = [record for record in proposals if record.body.action_id == action_id]
        _require(
            matching_receipts[0].body.action_id == action_id and len(matching_proposals) == 1,
            f"{label} ActionProposal and ExecutionReceipt do not bind the same action",
        )
        _require(
            matching_proposals[0].source.get("implementation") == "sdk-python"
            and matching_receipts[0].source.get("implementation") == "sdk-python",
            f"{label} evidence was not emitted by the Python EV-08 SDK",
        )
        _require(
            computation.get("confirmations_with_ledger_derived_action_id") == 1,
            f"{label} manifest does not identify the ledger-derived match",
        )
        proposal_id = matching_proposals[0].record_id
        receipt_id = matching_receipts[0].record_id
    else:
        _require(action_id is None, f"{label} unexpectedly assigns evidence to the Case")
        _require(not matching_receipts, f"{label} Case actually has a signed receipt")
        _require(
            computation.get("confirmations_with_ledger_derived_action_id") == 0,
            f"{label} manifest incorrectly claims a ledger-derived identity",
        )

    return FixtureFacts(
        label=label,
        directory=directory,
        population_count=population_count,
        matched_count=matched_count,
        coverage_ratio=coverage_ratio,
        case_id=case_id,
        reconciliation_status=expected_status,
        action_id=action_id,
        proposal_record_id=proposal_id,
        receipt_record_id=receipt_id,
        verification_as_of=verification_as_of,
    )


def _print_stage_one(zero: FixtureFacts, matched: FixtureFacts) -> None:
    print("STAGE 1 — THE CONTRAST")
    print()
    print(f"{'Metric':<22}{'Honest-zero':<18}{'Honest-match'}")
    print(f"{'Population':<22}{zero.population_count:<18}{matched.population_count}")
    print(f"{'Matched':<22}{zero.matched_count:<18}{matched.matched_count}")
    print(f"{'Coverage ratio':<22}{zero.coverage_ratio:<18}{matched.coverage_ratio}")
    print()
    print(f"Honest-zero Case: {zero.case_id}")
    print(
        "  Sources: 03-population-record.json body.count; "
        "06-reconciliation-results.json status; 07-coverage-report.json numerator_count "
        "and coverage_ratio; 13-ledger-evidence.json contains no receipt for this Case."
    )
    print(
        "  This action exists in Salesforce but has no signed evidence trail on our side — "
        "we refuse to claim credit for it."
    )
    print()
    print(f"Honest-match Case: {matched.case_id}")
    print(
        f"  Sources: ActionProposal {matched.proposal_record_id} and ExecutionReceipt "
        f"{matched.receipt_record_id} in 13-ledger-evidence.json have verified customer "
        "signatures, verified issuer receipts, and bind the same action_id."
    )
    print(
        "  This action has a genuine signed ActionProposal and ExecutionReceipt — "
        "the coverage claim is earned, not assumed."
    )


def _go_keyring(manifest_path: Path) -> dict[str, dict[str, str]]:
    manifest = _json(manifest_path)
    _require(isinstance(manifest, dict), "verifier manifest must be an object")
    raw_keys = manifest.get("verification_keys")
    _require(isinstance(raw_keys, dict), "verifier manifest has no verification_keys")
    result: dict[str, dict[str, str]] = {}
    for key_id, entry in raw_keys.items():
        _require(isinstance(key_id, str) and isinstance(entry, dict), "malformed verifier key")
        namespace = entry.get("namespace")
        public_key = entry.get("public_key_base64url")
        _require(
            isinstance(namespace, str) and isinstance(public_key, str),
            f"malformed verifier key {key_id!r}",
        )
        result[key_id] = {"namespace": namespace, "public_key": public_key}
    return result


def _print_stage_two(fixtures: tuple[FixtureFacts, ...]) -> None:
    print()
    print("STAGE 2 — INDEPENDENT VERIFICATION, LIVE")
    print()
    print("Independently verified by a Go binary that has never read this project's Python code.")

    go = _executable("go")
    with tempfile.TemporaryDirectory(prefix="evidence-demo-") as temporary:
        temporary_path = Path(temporary)
        verifier = temporary_path / "verify"
        built = subprocess.run(  # noqa: S603
            [go, "build", "-buildvcs=false", "-o", str(verifier), "./cmd/verify"],
            cwd=VERIFIER_DIR,
            capture_output=True,
            text=True,
            check=False,
        )
        if built.returncode != 0:
            raise DemoError("Go verifier build failed:\n" + built.stdout + built.stderr)

        for index, fixture in enumerate(fixtures):
            keyring_path = temporary_path / f"keyring-{index}.json"
            keyring_path.write_text(
                json.dumps(
                    _go_keyring(fixture.directory / "09-manifest.json"),
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                encoding="utf-8",
            )
            attestation_path = fixture.directory / "08-attestation-window.json"
            completed = subprocess.run(  # noqa: S603
                [
                    str(verifier),
                    "-mode",
                    "record",
                    "-keyring",
                    str(keyring_path),
                    str(attestation_path),
                ],
                cwd=REPO,
                capture_output=True,
                text=True,
                check=False,
            )
            literal = completed.stdout if completed.returncode == 0 else completed.stderr
            print()
            print(f"{fixture.label} — {_relative(attestation_path)}")
            print(literal.rstrip())
            if completed.returncode != 0 or not literal.startswith("VALID "):
                raise DemoError(f"Go verifier refused the {fixture.label} attestation")

            bundle_path = fixture.directory / "12-bundle.json"
            bundle = subprocess.run(  # noqa: S603
                [
                    str(verifier),
                    "-mode",
                    "bundle",
                    "-offline",
                    "-keyring",
                    str(keyring_path),
                    "-as-of",
                    fixture.verification_as_of,
                    str(bundle_path),
                ],
                cwd=REPO,
                capture_output=True,
                text=True,
                check=False,
            )
            bundle_literal = bundle.stdout if bundle.returncode == 0 else bundle.stderr
            print()
            print(f"{fixture.label} full bundle — {_relative(bundle_path)}")
            print(bundle_literal.rstrip())
            # TM-014 deliberately gives offline verification its distinct
            # "uncertain", rather than success or invalid, process status.
            if (
                bundle.returncode != GO_VERIFIER_UNCERTAIN_EXIT
                or not bundle_literal.startswith("VERDICT unchecked_revocation")
                or "checks run       [coverage]" not in bundle_literal
                or "REFUSED" in bundle_literal
            ):
                raise DemoError(f"Go verifier refused the {fixture.label} evidence bundle")


def _instant(value: object, *, label: str) -> datetime:
    if not isinstance(value, str):
        raise DemoError(f"{label} must be an RFC 3339 string")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DemoError(f"{label} is not an RFC 3339 instant") from exc


def _load_oversight_fixture(
    label: str,
    directory_name: str,
) -> OversightFacts:
    directory = FIXTURE_ROOT / directory_name
    attestation_path = directory / "09-attestation-window.json"
    report_path = directory / "03-oversight-report.json"
    timeline_path = directory / "01-timeline.json"
    reviews_path = directory / "02-human-reviews.json"
    evidence_path = directory / "06-evidence-records.json"
    _require_committed(
        (attestation_path, report_path, timeline_path, reviews_path, evidence_path)
    )

    attestation_document = _json(attestation_path)
    report = _json(report_path)
    timeline = _json(timeline_path)
    reviews = _json(reviews_path)
    evidence_records = _json(evidence_path)
    _require(isinstance(attestation_document, dict), f"{label} attestation must be an object")
    _require(isinstance(report, dict), f"{label} oversight report must be an object")
    _require(isinstance(timeline, dict), f"{label} timeline must be an object")
    _require(
        isinstance(reviews, list) and len(reviews) == 1 and isinstance(reviews[0], dict),
        f"{label} must contain exactly one HumanReview",
    )
    _require(isinstance(evidence_records, list), f"{label} evidence records must be an array")

    attestation = parse_record(attestation_document)
    review = parse_record(reviews[0])
    if not isinstance(attestation, AttestationWindowRecord):
        raise DemoError(f"{label} 09-attestation-window.json is not an AttestationWindow")
    if not isinstance(review, HumanReviewRecord):
        raise DemoError(f"{label} review is malformed")

    assertions = attestation_document.get("body", {}).get("assertions")
    exclusions = attestation_document.get("body", {}).get("exclusions")
    _require(isinstance(assertions, list), f"{label} attestation assertions must be an array")
    _require(isinstance(exclusions, list), f"{label} attestation exclusions must be an array")
    assertion_ids = {
        item.get("assertion_id") for item in assertions if isinstance(item, dict)
    }
    a04 = [
        item
        for item in assertions
        if isinstance(item, dict) and item.get("assertion_id") == "A-04"
    ]
    _require(len(a04) == 1, f"{label} must contain exactly one A-04 assertion")
    population_count = a04[0].get("population_count")
    matched_count = a04[0].get("matched_count")
    coverage_ratio = attestation.body.coverage_ratio
    _require(
        isinstance(population_count, int)
        and isinstance(matched_count, int)
        and isinstance(coverage_ratio, str)
        and population_count == matched_count == 1
        and coverage_ratio == "1.0000",
        f"{label} must establish identical 1/1, 1.0000 coverage",
    )
    assert isinstance(population_count, int)
    assert isinstance(matched_count, int)
    assert isinstance(coverage_ratio, str)

    reviewed_at = _instant(timeline.get("reviewed_at"), label=f"{label} reviewed_at")
    committed_at = _instant(timeline.get("committed_at"), label=f"{label} committed_at")
    review_offset_ms = round((reviewed_at - committed_at).total_seconds() * 1000)
    review_decided_at = _instant(
        review.body.decided_at,
        label=f"{label} HumanReview decided_at",
    )
    _require(
        review_decided_at == reviewed_at,
        f"{label} HumanReview and timeline disagree on review time",
    )
    execution_receipts = [
        parsed
        for document in evidence_records
        if isinstance(document, dict)
        and isinstance((parsed := parse_record(document)), ExecutionReceiptRecord)
        and parsed.body.action_id == review.body.action_id
    ]
    _require(
        len(execution_receipts) == 1,
        f"{label} must contain one ExecutionReceipt for the reviewed action",
    )
    receipt_committed_at = _instant(
        execution_receipts[0].body.responded_at,
        label=f"{label} ExecutionReceipt responded_at",
    )
    _require(
        committed_at == receipt_committed_at,
        f"{label} timeline commitment time disagrees with its ExecutionReceipt",
    )
    # Derive lifecycle position from the two observed instants.  The fixture's
    # action_state_at_review is corroborating evidence, not an answer flag fed
    # into the evaluator.
    derived_state = "proposed" if reviewed_at < committed_at else "committed"
    _require(
        timeline.get("action_state_at_review")
        == review.body.action_state_at_review
        == derived_state,
        f"{label} lifecycle state disagrees with its review/commit timing",
    )
    timed_review = review.model_copy(
        update={
            "body": review.body.model_copy(
                update={"action_state_at_review": derived_state},
            )
        }
    )
    evaluated = evaluate_review(timed_review)
    _require(
        (review_offset_ms < 0) is evaluated.effective,
        f"{label} timing and oversight effectiveness disagree",
    )

    evaluations = report.get("evaluations")
    _require(
        isinstance(evaluations, list)
        and len(evaluations) == 1
        and isinstance(evaluations[0], dict),
        f"{label} oversight report must contain one evaluation",
    )
    evaluation = evaluations[0]
    _require(
        evaluation.get("action_id") == review.body.action_id == timeline.get("action_id"),
        f"{label} action identity differs across review, report, and timeline",
    )
    _require(
        evaluation.get("effective") is evaluated.effective
        and evaluation.get("reason") == evaluated.reason,
        f"{label} committed report disagrees with the timing-derived evaluation",
    )
    effective_action_ids = report.get("effective_action_ids")
    expected_effective_ids = [review.body.action_id] if evaluated.effective else []
    _require(
        effective_action_ids == expected_effective_ids,
        f"{label} effective action ids disagree with the evaluation",
    )

    _require(review.body.decision == "approve", f"{label} decision is not approve")
    _require(
        isinstance(timeline.get("destination_record_id"), str)
        and timeline["destination_record_id"].startswith("mock-"),
        f"{label} does not identify the reviewed mock destination",
    )

    ineffective = [
        item
        for item in exclusions
        if isinstance(item, dict) and item.get("kind") == "human_review_ineffective"
    ]
    _require(
        ("A-08" in assertion_ids) is evaluated.effective,
        f"{label} A-08 presence disagrees with effective oversight",
    )
    _require(
        bool(ineffective) is (not evaluated.effective),
        f"{label} human_review_ineffective exclusion disagrees with effective oversight",
    )
    if ineffective:
        _require(
            len(ineffective) == 1
            and ineffective[0].get("action_id") == review.body.action_id
            and ineffective[0].get("reason") == "review after commitment",
            f"{label} ineffective-review exclusion is not bound to the reviewed action",
        )

    return OversightFacts(
        label=label,
        population_count=population_count,
        matched_count=matched_count,
        coverage_ratio=coverage_ratio,
        a08_present="A-08" in assertion_ids,
        ineffective_exclusion=bool(ineffective),
        review_offset_ms=review_offset_ms,
        effective=evaluated.effective,
        decision=review.body.decision,
    )


def _print_stage_three(in_time: OversightFacts, late: OversightFacts) -> None:
    _require(
        in_time.population_count
        == in_time.matched_count
        == late.population_count
        == late.matched_count
        == 1
        and in_time.coverage_ratio == late.coverage_ratio == "1.0000",
        "Stage 3 coverage contrast is not the required identical 1/1, 1.0000",
    )
    _require(
        in_time.review_offset_ms == -12
        and in_time.effective
        and in_time.a08_present
        and not in_time.ineffective_exclusion,
        "reviewed-in-time fixture is not the required 12ms-before effective case",
    )
    _require(
        late.review_offset_ms == 10
        and not late.effective
        and not late.a08_present
        and late.ineffective_exclusion,
        "reviewed-late fixture is not the required 10ms-after ineffective case",
    )
    _require(
        in_time.decision == late.decision == "approve",
        "Stage 3 decisions are not both approve",
    )

    in_time_a08 = "present" if in_time.a08_present else "absent"
    late_a08 = "present" if late.a08_present else "absent"
    in_time_timing = f"{abs(in_time.review_offset_ms)}ms BEFORE"
    late_timing = f"{abs(late.review_offset_ms)}ms AFTER"

    print()
    print("STAGE 3 — HUMAN OVERSIGHT, BEFORE VS AFTER")
    print()
    print(
        "This pair runs against a mock destination, not the live Salesforce org used in "
        "Stages 1 and 2."
    )
    print()
    print(f"{'Metric':<22}{'Reviewed in time':<22}{'Reviewed late'}")
    print(f"{'Population':<22}{in_time.population_count:<22}{late.population_count}")
    print(f"{'Matched':<22}{in_time.matched_count:<22}{late.matched_count}")
    print(f"{'Coverage ratio':<22}{in_time.coverage_ratio:<22}{late.coverage_ratio}")
    print(f"{'A-08':<22}{in_time_a08:<22}{late_a08}")
    print(f"{'Review timing':<22}{in_time_timing:<22}{late_timing}")
    print()
    print("Coverage is identical in both cases: 1/1, 1.0000. Coverage isn't what's different here.")
    print()
    print("Reviewed in time")
    print(f"  A-08: {in_time_a08}")
    print(f"  Review: {in_time_timing} commitment")
    print("  Reviewed while the action could still be stopped. Oversight counts.")
    print()
    print("Reviewed late")
    print(f"  A-08: {late_a08}")
    if late.ineffective_exclusion:
        print("  Exclusion: human_review_ineffective")
    print(f"  Review: {late_timing} commitment")
    print(
        f"  Reviewed after the action had already committed. The decision was "
        f"'{late.decision}' — it doesn't matter. Oversight after the fact isn't oversight."
    )
    print()
    print(
        "Neither fixture tells the evaluator which answer to produce. The only difference "
        "between the two runs is WHEN the review happened; the same code decided both outcomes."
    )


def main() -> int:
    started = time.monotonic()
    try:
        zero = _load_fixture("Honest-zero", "salesforce-live", expected_match=False)
        matched = _load_fixture("Honest-match", "salesforce-live-matched", expected_match=True)
        _print_stage_one(zero, matched)
        _print_stage_two((zero, matched))
        in_time = _load_oversight_fixture(
            "Reviewed in time",
            "oversight-reviewed-in-time",
        )
        late = _load_oversight_fixture(
            "Reviewed late",
            "oversight-reviewed-late",
        )
        _print_stage_three(in_time, late)
    except (DemoError, ValueError, TypeError) as exc:
        print(f"DEMO REFUSED: {exc}", file=sys.stderr)
        return 1
    elapsed = time.monotonic() - started
    print()
    print(f"Completed from committed fixtures in {elapsed:.2f}s.")
    if elapsed >= 60:
        print("DEMO REFUSED: runtime exceeded 60 seconds", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
