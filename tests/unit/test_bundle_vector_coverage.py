"""QA-019 coverage checks for EV-41's now-published bundle vectors."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sdk_python.evidence.instants import parse_instant
from sdk_python.evidence.revocation import RevocationStatus, classify_revocation
from sdk_python.evidence.schema import RevocationRecord, validate_record
from sdk_python.evidence.versions import require_published_schema_version

CORPUS = Path(__file__).resolve().parents[1] / "vectors" / "vectors-v0.1.json"
DOCUMENT: dict[str, Any] = json.loads(CORPUS.read_text(encoding="utf-8"))

#: Requirements for which EV-41 publishes cross-implementation vectors.
COVERED_REQUIREMENTS = (
    "ES-034",  # the bundle container
    "ES-035",  # the schema-version registry
    "CM-025",  # the methodology-version registry
    "AR-029",  # the revocation endpoint protocol
    "AR-030",  # superseding_ref as the discriminator
    "AR-031",  # the effective-date boundary
)


def _vector(vector_id: str) -> dict[str, Any]:
    return next(
        vector for vector in DOCUMENT["vectors"] if vector["id"] == vector_id
    )


def test_bundle_operation_is_present_and_executable_by_both_harnesses() -> None:
    bundle_vectors = [
        vector for vector in DOCUMENT["vectors"] if vector["operation"] == "verify_bundle"
    ]
    assert bundle_vectors
    assert all(vector.get("bundle_utf8_hex") for vector in bundle_vectors)


def test_each_ev41_requirement_is_attributed_and_not_declared_absent() -> None:
    coverage = DOCUMENT["requirement_coverage"]
    assert set(COVERED_REQUIREMENTS) <= coverage["covered"].keys()
    assert set(COVERED_REQUIREMENTS).isdisjoint(coverage["declared_absent"])


def test_the_published_revocation_record_authenticates_and_classifies() -> None:
    """The one piece of normative evidence available to this story.

    It reaches `classify_revocation` rather than `check_revocation` because the
    corpus publishes no endpoint exchange: there is no 404, no unauthenticated
    answer, and no attestation for its `attestation_ref` to name.  Those are
    precisely the AR-029 cases with nothing behind them.
    """

    vector = _vector("accept-revocationrecord-signed-by-issuer-key")
    record = validate_record(vector["record"])
    assert isinstance(record, RevocationRecord)
    require_published_schema_version(record.schema_version)

    effective_at = record.body.effective_at
    assert record.body.superseding_ref is None

    after = classify_revocation(
        record, evaluated_at=parse_instant("2026-12-01T00:00:00.000Z")
    )
    assert after.status is RevocationStatus.REVOKED

    at_the_boundary = classify_revocation(
        record, evaluated_at=parse_instant(effective_at)
    )
    assert at_the_boundary.status is RevocationStatus.REVOKED

    before = classify_revocation(
        record, evaluated_at=parse_instant("2026-01-01T00:00:00.000Z")
    )
    assert before.status is RevocationStatus.VALID
    assert before.pending_status is RevocationStatus.REVOKED


def test_supersession_has_normative_non_null_vector_coverage() -> None:
    vector = _vector("revocation-superseding-reference-is-distinct")
    response = vector["revocation_response"]
    record = json.loads(bytes.fromhex(response["body_utf8_hex"]))
    assert record["body"]["superseding_ref"] == "attestation-2"
    assert vector["expected"]["verdict"] == "superseded"


@pytest.mark.parametrize("requirement", COVERED_REQUIREMENTS)
def test_each_requirement_in_scope_is_named_in_its_owning_document(
    requirement: str,
) -> None:
    """A declared absence is worthless if it names a requirement that moved."""

    docs = Path(__file__).resolve().parents[2] / "docs"
    corpus = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(docs.glob("*.md"))
    )
    assert f"**{requirement}" in corpus
