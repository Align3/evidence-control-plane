"""Fixture builders for the ES-034 bundle and AR-029 revocation tests.

These are *fixtures*, not vectors.  QA-019 forbids manufacturing a vector to
validate the reading that produced it, and the published corpus in
`tests/vectors/` is deliberately untouched by this story: it carries no bundle,
registry or revocation vector, and the honest record of that is the declared
absence, not a confirming case written by the implementation under test.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sdk_python.evidence.canonical import canonical_digest, canonicalize
from sdk_python.evidence.schema import (
    AttestationWindowRecord,
    RecordEnvelope,
    validate_record,
)
from sdk_python.evidence.signing import counter_sign_attestation, sign_record
from services.ingestion.receipts import RegisteredPublicKey

TS = "2026-08-01T12:00:00.000Z"

EVIDENCE_KEY_ID = "EVIDENCE1"
ISSUER_KEY_ID = "ISSUER1"

EVIDENCE_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
ISSUER_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))

EVIDENCE_STREAM = "collector-1"
ISSUER_STREAM = "issuer:observations"


def verification_keys() -> Mapping[str, RegisteredPublicKey]:
    """A truthful keyring: each key carries the namespace it is registered in."""

    return {
        EVIDENCE_KEY_ID: RegisteredPublicKey(
            namespace="evidence", public_key=EVIDENCE_PRIVATE_KEY.public_key()
        ),
        ISSUER_KEY_ID: RegisteredPublicKey(
            namespace="issuer", public_key=ISSUER_PRIVATE_KEY.public_key()
        ),
    }


def _record_id(suffix: int) -> str:
    return f"01890f47-2f58-7cc0-98c4-{suffix:012d}"


def envelope(
    *,
    record_type: str,
    body: Mapping[str, Any],
    record_id: str,
    stream_id: str,
    sequence: int = 1,
    prev_digest: str | None = None,
    tenant_id: str = "tenant-1",
    schema_version: str = "1.0.0",
    boundary_ref: str = "boundary-1",
    source_time: str = TS,
) -> dict[str, Any]:
    return {
        "record_id": record_id,
        "record_type": record_type,
        "schema_version": schema_version,
        "tenant_id": tenant_id,
        "boundary_ref": boundary_ref,
        "stream_id": stream_id,
        "sequence": sequence,
        "prev_digest": prev_digest,
        "source": {"collector": "sdk-python"},
        "clocks": {"source_time": source_time},
        "body": dict(body),
        "signature": {},
    }


def attestation_body(
    *,
    methodology_version: str = "1.0.0",
    coverage_ratio: str | None = "1.0000",
) -> dict[str, Any]:
    return {
        "boundary_ref": "boundary-1",
        "window_start": TS,
        "window_end": TS,
        "methodology_version": methodology_version,
        "denominator_class": "C1",
        "population_record_refs": [],
        "coverage_level": "observed",
        "verification_status": "self_computed",
        "coverage_ratio": coverage_ratio,
        "counts": {
            "matched": 1,
            "unmatched_with_evidence": 0,
            "unmatched_without_evidence": 0,
            "duplicate": 0,
            "ambiguous": 0,
            "out_of_scope": 0,
        },
        "gaps": [],
        "assertions": [],
        "exclusions": [],
        "relying_parties": [],
        "validity_from": TS,
        "validity_until": TS,
        "liability_ref": "liability-1",
        "issued_at": TS,
        "issuer": "issuer-1",
        "verifier_version": "0.1.0",
    }


def coverage_gap_body(*, cause: str = "collector_unreachable") -> dict[str, Any]:
    return {
        "gap_start": TS,
        "gap_end": TS,
        "affected_scope": {"families": ["payments"]},
        "cause": cause,
        "detection_source": "collector",
        "exposure": "known",
        "actions_during_gap": None,
    }


def population_body() -> dict[str, Any]:
    return {
        "action_family": "payments",
        "destination_system": "ledger",
        "window_start": TS,
        "window_end": TS,
        "enumeration_query": {"api": "list_actions", "scope": "payments"},
        "identifier_digest": canonical_digest(["action-1"]),
        "count": 1,
        "pagination_complete": True,
        "result_cap_hit": False,
        "retrieved_at": TS,
        "authoritative_timestamps": {"min": TS, "max": TS},
    }


def revocation_body(
    *,
    attestation_ref: str,
    effective_at: str,
    superseding_ref: str | None,
    reason: str = "discovered defect in computation",
) -> dict[str, Any]:
    return {
        "attestation_ref": attestation_ref,
        "reason": reason,
        "issuer": "issuer-1",
        "effective_at": effective_at,
        "superseding_ref": superseding_ref,
        "relying_party_notification_status": "pending",
    }


def sign_evidence(record: RecordEnvelope) -> RecordEnvelope:
    return sign_record(
        record, key_id=EVIDENCE_KEY_ID, private_key=EVIDENCE_PRIVATE_KEY
    )


def sign_issuer(record: RecordEnvelope) -> RecordEnvelope:
    return sign_record(record, key_id=ISSUER_KEY_ID, private_key=ISSUER_PRIVATE_KEY)


def signed_attestation(
    *,
    record_id: str | None = None,
    sequence: int = 1,
    prev_digest: str | None = None,
    methodology_version: str = "1.0.0",
    schema_version: str = "1.0.0",
) -> AttestationWindowRecord:
    record = validate_record(
        envelope(
            record_type="AttestationWindow",
            body=attestation_body(methodology_version=methodology_version),
            record_id=record_id or _record_id(1),
            stream_id=EVIDENCE_STREAM,
            sequence=sequence,
            prev_digest=prev_digest,
            schema_version=schema_version,
        )
    )
    signed = sign_evidence(record)
    assert isinstance(signed, AttestationWindowRecord)
    return counter_sign_attestation(
        signed, issuer_key_id=ISSUER_KEY_ID, issuer_private_key=ISSUER_PRIVATE_KEY
    )


def signed_coverage_gap(
    *,
    record_id: str | None = None,
    sequence: int = 1,
    prev_digest: str | None = None,
    stream_id: str = EVIDENCE_STREAM,
    cause: str = "collector_unreachable",
) -> RecordEnvelope:
    return sign_evidence(
        validate_record(
            envelope(
                record_type="CoverageGap",
                body=coverage_gap_body(cause=cause),
                record_id=record_id or _record_id(2),
                stream_id=stream_id,
                sequence=sequence,
                prev_digest=prev_digest,
            )
        )
    )


def signed_population(
    *,
    record_id: str | None = None,
    sequence: int = 1,
    prev_digest: str | None = None,
) -> RecordEnvelope:
    return sign_issuer(
        validate_record(
            envelope(
                record_type="PopulationRecord",
                body=population_body(),
                record_id=record_id or _record_id(3),
                stream_id=ISSUER_STREAM,
                sequence=sequence,
                prev_digest=prev_digest,
            )
        )
    )


def signed_revocation(
    *,
    attestation_ref: str,
    effective_at: str,
    superseding_ref: str | None,
    record_id: str | None = None,
    signer: str = "issuer",
    reason: str = "discovered defect in computation",
) -> RecordEnvelope:
    record = validate_record(
        envelope(
            record_type="RevocationRecord",
            body=revocation_body(
                attestation_ref=attestation_ref,
                effective_at=effective_at,
                superseding_ref=superseding_ref,
                reason=reason,
            ),
            record_id=record_id or _record_id(4),
            stream_id="issuer:RevocationRecord",
        )
    )
    return sign_issuer(record) if signer == "issuer" else sign_evidence(record)


def bundle_bytes(records: Iterable[RecordEnvelope]) -> bytes:
    """The ES-034 container: canonical elements, ascending by canonical bytes."""

    elements = sorted(canonicalize(record) for record in records)
    return b"[" + b",".join(elements) + b"]"


def raw_bundle_bytes(elements: Sequence[Any]) -> bytes:
    """A container assembled from already-decoded JSON, preserving given order."""

    return b"[" + b",".join(canonicalize(element) for element in elements) + b"]"


def as_json(record: RecordEnvelope) -> dict[str, Any]:
    return record.model_dump(mode="json", exclude_unset=True)


def linked_evidence_stream() -> tuple[RecordEnvelope, AttestationWindowRecord]:
    """A CoverageGap at sequence 1 and an attestation at 2, correctly linked."""

    gap = signed_coverage_gap(record_id=_record_id(2), sequence=1, prev_digest=None)
    attestation = signed_attestation(
        record_id=_record_id(1), sequence=2, prev_digest=canonical_digest(gap)
    )
    return gap, attestation
