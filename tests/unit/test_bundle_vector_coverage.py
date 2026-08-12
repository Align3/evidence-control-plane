"""What the published corpus does and does not say about this story's subject.

QA-019: a requirement no vector exercises has nothing behind it, and the honest
response is to record the absence rather than to manufacture a confirming case
from the implementation under test.  ES-034, ES-035, CM-025 and AR-029 through
AR-031 have no vector coverage, and this file states that as an executable
fact so it stops being invisible.

One vector *is* relevant and is used here: `accept-revocationrecord-signed-by-
issuer-key` carries a real issuer-signed `RevocationRecord`.  It was published
for ES-033 rather than for AR-030, so it pins the record's authentication and
not the protocol's verdicts — but it is normative bytes this implementation did
not write, which is worth more than a fixture for the part it does cover.
"""

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

#: Requirements in this story's scope, and what the corpus offers for each.
UNCOVERED_REQUIREMENTS = (
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


def test_no_vector_operation_exercises_a_bundle_or_a_revocation_verdict() -> None:
    """The declared absence, as a tripwire rather than as a comment.

    Every operation in the corpus is a record-level or stream-level check.
    None parses a container, none consults a version registry, and none asks
    what a `RevocationRecord` *means* — only whether it authenticates.  When a
    bundle or revocation-status vector is published this test fails, which is
    the point: the absence should not be able to persist unnoticed, and neither
    should its removal.
    """

    operations = {vector["operation"] for vector in DOCUMENT["vectors"]}
    assert not {
        operation
        for operation in operations
        if "bundle" in operation or "revocation" in operation
    }
    assert UNCOVERED_REQUIREMENTS  # named above so the gap has a subject


def test_the_corpus_carries_no_attestation_bundle() -> None:
    for vector in DOCUMENT["vectors"]:
        subject = vector.get("record") or vector.get("input_json")
        assert not isinstance(subject, list) or "records" not in vector


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


def test_no_published_vector_carries_a_non_null_superseding_ref() -> None:
    """AR-030's `superseded` half rests on prose alone.

    The corpus contains exactly one `RevocationRecord` and its `superseding_ref`
    is null, so the state that distinguishes supersession from revocation has
    never been exercised by anything ES-029 makes authoritative.  Writing a
    vector for it here would be QA-019's forbidden move — a case manufactured
    by the implementation whose reading it would then appear to confirm.
    """

    revocation_records = [
        vector["record"]
        for vector in DOCUMENT["vectors"] + DOCUMENT["adversarial_vectors"]
        if isinstance(vector.get("record"), dict)
        and vector["record"].get("record_type") == "RevocationRecord"
    ]
    assert revocation_records
    assert all(
        record["body"]["superseding_ref"] is None for record in revocation_records
    )


@pytest.mark.parametrize("requirement", UNCOVERED_REQUIREMENTS)
def test_each_requirement_in_scope_is_named_in_its_owning_document(
    requirement: str,
) -> None:
    """A declared absence is worthless if it names a requirement that moved."""

    docs = Path(__file__).resolve().parents[2] / "docs"
    corpus = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(docs.glob("*.md"))
    )
    assert f"**{requirement}" in corpus
