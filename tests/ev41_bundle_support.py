"""Deterministic signed bundle fixtures shared by EV-41 tests and vectors."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sdk_python.evidence.canonical import canonicalize
from sdk_python.evidence.schema import RecordEnvelope, validate_record
from sdk_python.evidence.signing import counter_sign_attestation, sign_record
from services.ingestion.receipts import RegisteredPublicKey

EVIDENCE_KEY_ID = "K1"
ISSUER_KEY_ID = "ISSUER1"
EVIDENCE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(0x00, 0x20)))
ISSUER_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(0x60, 0x80)))
WINDOW_START = "2026-08-01T00:00:00.000Z"
WINDOW_END = "2026-09-01T00:00:00.000Z"


def verification_keys() -> dict[str, RegisteredPublicKey]:
    return {
        EVIDENCE_KEY_ID: RegisteredPublicKey(
            namespace="evidence", public_key=EVIDENCE_KEY.public_key()
        ),
        ISSUER_KEY_ID: RegisteredPublicKey(namespace="issuer", public_key=ISSUER_KEY.public_key()),
    }


def _record_id(index: int) -> str:
    return f"01890f47-2f58-7cc0-98c4-{index:012x}"


def _envelope(
    *,
    index: int,
    record_type: str,
    body: dict[str, Any],
    stream_id: str,
    schema_version: str = "1.0.0",
) -> dict[str, Any]:
    return {
        "record_id": _record_id(index),
        "record_type": record_type,
        "schema_version": schema_version,
        "tenant_id": "tenant-1",
        "boundary_ref": "boundary-1",
        "stream_id": stream_id,
        "sequence": 1,
        "prev_digest": None,
        "source": {"collector": "ev41-vector", "version": "1.0.0"},
        "clocks": {"source_time": "2026-09-02T00:00:00.000Z"},
        "body": body,
        "signature": {},
    }


def _sign(raw: dict[str, Any], *, issuer: bool = False) -> RecordEnvelope:
    record = validate_record(raw)
    return sign_record(
        record,
        key_id=ISSUER_KEY_ID if issuer else EVIDENCE_KEY_ID,
        private_key=ISSUER_KEY if issuer else EVIDENCE_KEY,
    )


def _wire(record: RecordEnvelope) -> dict[str, Any]:
    return record.model_dump(mode="json", exclude_unset=True)


@dataclass(frozen=True, slots=True)
class BundleFixture:
    wire: bytes
    records: tuple[RecordEnvelope, ...]


def build_bundle(
    *,
    population_count: int = 4,
    matched: int = 1,
    out_of_scope: int = 1,
    ratio: str | None = "0.3333",
    denominator_class: str = "C1",
    coverage_level: str = "observed",
    capped_by_class: bool | None = False,
    pagination_complete: bool = True,
    result_cap_hit: bool = False,
    schema_version: str = "1.0.0",
    methodology_version: str = "1.0.0",
    qualified_at: str = "2026-07-01T00:00:00.000Z",
    validity_from: str = "2026-09-01T00:00:00.000Z",
    validity_until: str = "2026-12-01T00:00:00.000Z",
    assertions: list[dict[str, Any]] | None = None,
    gap_record: RecordEnvelope | None = None,
    announced_gaps: list[dict[str, Any]] | None = None,
    include_boundary: bool = True,
) -> BundleFixture:
    qualification = _sign(
        _envelope(
            index=401,
            record_type="QualificationRecord",
            stream_id="qualification-1",
            schema_version=schema_version,
            body={
                "action_family": "ticket.resolve",
                "destination_system": "support",
                "enumeration": {"capable": True, "api": "tickets.list"},
                "identity_isolation": {
                    "attribute": "service_account",
                    "vendor_settable": False,
                },
                "confirmation": {"capable": True, "api": "tickets.get"},
                "temporal": {
                    "authoritative_timestamp_source": "support",
                    "measured_settlement_lag_s": 0,
                },
                "retention_period": "P90D",
                "mutability": {"deletion_possible": False, "trace_available": True},
                "assigned_class": denominator_class,
                "class_evidence": {"trial": "qualification-1"},
                "trial": {"match_rate": "1.0000"},
                "qualified_at": qualified_at,
                "revalidation_cadence": "P90D",
            },
        )
    )
    boundary = _sign(
        _envelope(
            index=402,
            record_type="AssuranceBoundary",
            stream_id="boundary-1",
            schema_version=schema_version,
            body={
                "boundary_version": "1",
                "tenant": "tenant-1",
                "deployment": "production",
                "agent_identities": ["agent-1"],
                "action_families": ["ticket.resolve"],
                "destination_systems": ["support"],
                "enforcement_points": ["connector"],
                "policy_refs": ["policy-1"],
                "window_start": "2026-01-01T00:00:00.000Z",
                "window_end": "2027-01-01T00:00:00.000Z",
                "collection_modes": ["inline"],
                "fail_behaviour": {"ticket.resolve": "fail_closed"},
                "qualification_refs": [qualification.record_id],
            },
        )
    )
    population = _sign(
        _envelope(
            index=403,
            record_type="PopulationRecord",
            stream_id="population-1",
            schema_version=schema_version,
            body={
                "action_family": "ticket.resolve",
                "destination_system": "support",
                "window_start": WINDOW_START,
                "window_end": WINDOW_END,
                "enumeration_query": {"scope": "agent-1"},
                "record_identifiers": [f"ticket-{index}" for index in range(population_count)],
                "count": population_count,
                "pagination_complete": pagination_complete,
                "result_cap_hit": result_cap_hit,
                "retrieved_at": "2026-09-01T00:01:00.000Z",
                "authoritative_timestamps": {},
            },
        ),
        issuer=True,
    )
    counts = {
        "matched": matched,
        "unmatched_with_evidence": 0,
        "unmatched_without_evidence": population_count - matched - out_of_scope,
        "duplicate": 0,
        "ambiguous": 0,
        "out_of_scope": out_of_scope,
    }
    attestation_body: dict[str, Any] = {
        "boundary_ref": "boundary-1",
        "window_start": WINDOW_START,
        "window_end": WINDOW_END,
        "methodology_version": methodology_version,
        "denominator_class": denominator_class,
        "population_record_refs": [population.record_id],
        "coverage_level": coverage_level,
        "verification_status": "self_computed",
        "coverage_ratio": ratio,
        "counts": counts,
        "gaps": announced_gaps or [],
        "assertions": assertions or [],
        "exclusions": [],
        "relying_parties": [{"name": "buyer-1"}],
        "validity_from": validity_from,
        "validity_until": validity_until,
        "liability_ref": "terms-1",
        "issued_at": "2026-09-01T00:00:00.000Z",
        "issuer": {"name": "issuer-1"},
        "verifier_version": "1.0.0",
    }
    if capped_by_class is not None:
        attestation_body["capped_by_class"] = capped_by_class
    attestation = _sign(
        _envelope(
            index=404,
            record_type="AttestationWindow",
            stream_id="attestation-1",
            schema_version=schema_version,
            body=attestation_body,
        )
    )
    attestation = counter_sign_attestation(
        attestation, issuer_key_id=ISSUER_KEY_ID, issuer_private_key=ISSUER_KEY
    )
    records = [attestation, qualification, population]
    if include_boundary:
        records.append(boundary)
    if gap_record is not None:
        records.append(gap_record)
    records.sort(key=lambda record: canonicalize(_wire(record)))
    return BundleFixture(
        wire=canonicalize([_wire(record) for record in records]),
        records=tuple(records),
    )


def resign_attestation(fixture: BundleFixture, mutate: Any) -> BundleFixture:
    raw_records = [_wire(record) for record in fixture.records]
    for index, raw in enumerate(raw_records):
        if raw["record_type"] != "AttestationWindow":
            continue
        raw["signature"] = {}
        mutate(raw)
        signed = _sign(raw)
        raw_records[index] = _wire(
            counter_sign_attestation(
                signed, issuer_key_id=ISSUER_KEY_ID, issuer_private_key=ISSUER_KEY
            )
        )
        break
    raw_records.sort(key=canonicalize)
    return BundleFixture(
        wire=canonicalize(raw_records),
        records=tuple(validate_record(raw) for raw in raw_records),
    )


def revocation_record(
    *,
    effective_at: str,
    superseding_ref: str | None,
    attestation_ref: str = _record_id(404),
    schema_version: str = "1.0.0",
) -> bytes:
    record = _sign(
        _envelope(
            index=405,
            record_type="RevocationRecord",
            stream_id="revocation-1",
            schema_version=schema_version,
            body={
                "attestation_ref": attestation_ref,
                "reason": "computation defect",
                "issuer": {"name": "issuer-1"},
                "effective_at": effective_at,
                "superseding_ref": superseding_ref,
                "relying_party_notification_status": "sent",
            },
        ),
        issuer=True,
    )
    return canonicalize(_wire(record))


def coverage_gap_record() -> RecordEnvelope:
    return _sign(
        _envelope(
            index=406,
            record_type="CoverageGap",
            stream_id="gap-1",
            body={
                "gap_start": "2026-08-10T00:00:00.000Z",
                "gap_end": "2026-08-11T00:00:00.000Z",
                "affected_scope": {"action_families": ["ticket.resolve"]},
                "cause": "collector_unreachable",
                "detection_source": "collector",
                "exposure": "known",
                "actions_during_gap": None,
            },
        )
    )


def decode_bundle(fixture: BundleFixture) -> list[dict[str, Any]]:
    decoded = json.loads(fixture.wire)
    assert isinstance(decoded, list)
    return decoded
