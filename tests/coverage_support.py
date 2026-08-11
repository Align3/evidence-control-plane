"""Typed value builders shared by EV-16 acceptance and unit tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sdk_python.evidence.schema import ExecutionReceiptRecord
from services.admin.qualification import DenominatorClass, Qualification
from services.computation.coverage import (
    ActionEvidence,
    CoverageBoundary,
    GapEvidence,
    TimeInterval,
)
from services.computation.reconciliation import (
    ReconciliationResult,
    ReconciliationStatus,
)
from services.ingestion.receipts import (
    RegisteredPublicKey,
    SignedIngestionReceipt,
    create_ingestion_receipt,
)
from tests.reconciliation_support import (
    confirmation,
    population,
)
from tests.reconciliation_support import receipt as execution_receipt


def at(hour: int, minute: int = 0) -> datetime:
    return datetime(2026, 8, 11, hour, minute, tzinfo=UTC)


def boundary() -> CoverageBoundary:
    return CoverageBoundary(
        boundary_ref="acme:boundary:1",
        window=TimeInterval(at(9), at(11)),
        clock_skew_threshold_ms=5_000,
    )


def qualification(denominator_class: DenominatorClass) -> Qualification:
    return Qualification(
        qualification_ref="q-1",
        tenant_id="acme",
        action_family="refund.issue",
        destination_system="payments",
        assigned_class=denominator_class,
        enumeration_capable=denominator_class.emits_ratio,
        confirmation_capable=True,
        identity_isolation_attribute="service_principal_id",
        identity_vendor_settable=False,
        authoritative_time_available=True,
        settlement_lag_s=300,
        source_retention_days=400,
        deletion_traceless_possible=False,
        qualified_at=at(8),
        recorded_at=at(8),
        revalidate_after=at(8) + timedelta(days=365),
    )


def reconciliation_results(
    statuses: list[ReconciliationStatus],
) -> tuple[ReconciliationResult, ...]:
    return tuple(
        ReconciliationResult(
            population_ref="01890f47-2f58-7cc0-98c4-000000000001",
            destination_record_id=f"destination-{index}",
            status=status,
            action_id=(
                f"action-{index}"
                if status is not ReconciliationStatus.UNMATCHED_WITHOUT_EVIDENCE
                else None
            ),
            confirmation_record_id=(
                f"01890f47-2f58-7cc0-98c4-{100 + index:012x}"
                if status is ReconciliationStatus.MATCHED
                else None
            ),
        )
        for index, status in enumerate(statuses)
    )


def coverage_population(
    size: int,
    *,
    result_cap_hit: bool = False,
    pagination_complete: bool = True,
):
    return population(
        [f"destination-{index}" for index in range(size)],
        action_family="refund.issue",
        destination_system="payments",
        result_cap_hit=result_cap_hit,
        pagination_complete=pagination_complete,
        window_start="2026-08-11T09:00:00.000Z",
        window_end="2026-08-11T11:00:00.000Z",
    )


def _timestamp(value: datetime) -> str:
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def action_evidence(
    statuses: list[ReconciliationStatus],
    *,
    occurred_at: datetime | None = None,
) -> tuple[ActionEvidence, ...]:
    instant = occurred_at or at(10)
    return tuple(
        ActionEvidence(
            destination_record_id=f"destination-{index}",
            confirmation=(
                confirmation(
                    f"action-{index}",
                    f"destination-{index}",
                    serial=100 + index,
                ).model_copy(
                    update={
                        "body": confirmation(
                            f"action-{index}",
                            f"destination-{index}",
                            serial=100 + index,
                        ).body.model_copy(
                            update={"authoritative_timestamp": _timestamp(instant)}
                        )
                    }
                )
                if status is ReconciliationStatus.MATCHED
                else None
            ),
        )
        for index, status in enumerate(statuses)
    )


def signed_ingestion_receipt(
    *,
    skew_ms: int,
    action_id: str = "clock-action",
    destination_record_id: str = "destination-0",
    source_time: datetime | None = None,
    serial: int = 10,
) -> tuple[
    SignedIngestionReceipt,
    ExecutionReceiptRecord,
    dict[str, RegisteredPublicKey],
]:
    """A real issuer proof bound to one customer record for ES-S-014."""
    observed_at = source_time or datetime(2026, 8, 11, 12, tzinfo=UTC)
    record = execution_receipt(action_id, destination_record_id, serial=serial)
    record = record.model_copy(
        update={
            "clocks": record.clocks.model_copy(
                update={"source_time": _timestamp(observed_at)}
            )
        }
    )
    private_key = Ed25519PrivateKey.generate()
    receipt = create_ingestion_receipt(
        record,
        ingest_time=observed_at + timedelta(milliseconds=skew_ms),
        issuer_key_id="issuer-clock-key",
        issuer_private_key=private_key,
    )
    return (
        receipt,
        record,
        {
            "issuer-clock-key": RegisteredPublicKey(
                namespace="issuer", public_key=private_key.public_key()
            )
        },
    )


def receipted_action_evidence(
    index: int,
    *,
    occurred_at: datetime,
    skew_ms: int = 0,
    affected_interval: TimeInterval | None = None,
) -> ActionEvidence:
    receipt, record, keys = signed_ingestion_receipt(
        skew_ms=skew_ms,
        action_id=f"action-{index}",
        destination_record_id=f"destination-{index}",
        source_time=occurred_at,
        serial=10 + index,
    )
    return ActionEvidence(
        destination_record_id=f"destination-{index}",
        ingestion_receipt=receipt,
        receipt_record=record,
        receipt_verification_keys=keys,
        affected_interval=affected_interval,
    )


def gap(
    start: datetime,
    end: datetime,
    *,
    cause: str = "denominator_unavailable",
    actions_during_gap: int | None = None,
) -> GapEvidence:
    return GapEvidence(
        interval=TimeInterval(start, end),
        cause=cause,
        affected_scope=("refund.issue",),
        detection_source="signed-gap-record",
        actions_during_gap=actions_during_gap,
        evidence_record_ref="01890f47-2f58-7cc0-98c4-000000000999",
    )
