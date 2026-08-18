"""Signed EV-18 lifecycle fixtures using the registered tenant keys."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sdk_python.evidence.schema import AttestationWindowRecord, validate_record
from sdk_python.evidence.signing import counter_sign_attestation, sign_record
from tests.ledger_support import RecordFactory


def signed_attestation(
    factory: RecordFactory,
    *,
    record_id: str,
    boundary_ref: str,
    sequence: int,
    window_start: datetime,
    window_end: datetime,
    validity_from: datetime | None = None,
    validity_until: datetime | None = None,
    relying_parties: tuple[str, ...] = ("buyer",),
) -> AttestationWindowRecord:
    issued_at = validity_from or datetime.now(UTC) - timedelta(minutes=1)
    valid_until = validity_until or issued_at + timedelta(days=30)
    record = validate_record(
        {
            "record_id": record_id,
            "record_type": "AttestationWindow",
            "schema_version": "1.0.0",
            "tenant_id": factory.tenant_id,
            "boundary_ref": boundary_ref,
            "stream_id": f"{factory.tenant_id}:attestations:1",
            "sequence": sequence,
            "prev_digest": None,
            "source": {"service": "attestation", "version": "0.1.0"},
            "clocks": {"source_time": issued_at.isoformat(timespec="milliseconds")},
            "body": {
                "boundary_ref": boundary_ref,
                "window_start": window_start.isoformat(timespec="milliseconds"),
                "window_end": window_end.isoformat(timespec="milliseconds"),
                "methodology_version": "0.1.0",
                "denominator_class": "C1",
                "population_record_refs": [],
                "coverage_level": "reconciled",
                "verification_status": "self_computed",
                "coverage_ratio": "1.0000",
                "capped_by_class": False,
                "counts": {"matched": 1},
                "gaps": [],
                "assertions": [],
                "exclusions": [],
                "relying_parties": [{"name": party} for party in relying_parties],
                "validity_from": issued_at.isoformat(timespec="milliseconds"),
                "validity_until": valid_until.isoformat(timespec="milliseconds"),
                "liability_ref": "terms:standard:1",
                "issued_at": issued_at.isoformat(timespec="milliseconds"),
                "issuer": {"name": "Evidence Control Plane"},
                "verifier_version": "0.1.0",
            },
            "signature": {},
        }
    )
    assert isinstance(record, AttestationWindowRecord)
    customer_signed = sign_record(
        record,
        key_id=factory.key_id,
        private_key=factory.private_key,
    )
    return counter_sign_attestation(
        customer_signed,
        issuer_key_id=factory.receipt_key_id,
        issuer_private_key=factory.receipt_private_key,
    )


__all__ = ["signed_attestation"]
