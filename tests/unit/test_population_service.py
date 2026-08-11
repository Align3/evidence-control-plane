"""Negative-first tests for EV-14 population production."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import func, select

from sdk_python.evidence.schema import PopulationRecord
from services.computation import (
    ConnectorQualificationMismatchError,
    IssuerSigner,
    PopulationObservationTimingError,
    PopulationRequest,
    PopulationService,
    SettlementLagPendingError,
)
from services.computation.population import IssuerSignerError
from services.computation.tasks import (
    PopulationTaskRuntime,
    configure_population_tasks,
    population_task_payload,
    record_population_task,
    schedule_population_enumeration,
)
from services.connectors import (
    ConnectorCapabilities,
    ConnectorScope,
    DestinationConnector,
    EnumerationWindow,
    MockConnectorConfig,
    MockDestinationRecord,
    SilentTruncationError,
    create_mock_connector,
    require_window_enumerator,
)
from services.ingestion.receipts import parse_canonical_record_wire
from services.ledger import TenantEngines, population_partition, tenant_connection
from tests.ledger_support import TENANT_A, RecordFactory

LAG = timedelta(minutes=5)


class _CountingConnector:
    def __init__(self, inner: DestinationConnector) -> None:
        self.inner = inner
        self.enumeration_calls = 0

    def capabilities(self) -> ConnectorCapabilities:
        return self.inner.capabilities()

    def enumerate(self, scope: ConnectorScope, window: EnumerationWindow):  # type: ignore[no-untyped-def]
        self.enumeration_calls += 1
        return require_window_enumerator(self.inner).enumerate(scope, window)


def _now() -> datetime:
    current = datetime.now(UTC)
    return current.replace(microsecond=(current.microsecond // 1_000) * 1_000)


def _request(
    *, boundary_ref: str, now: datetime, early_by: timedelta = timedelta(0)
) -> PopulationRequest:
    end = now - LAG + early_by
    return PopulationRequest(
        tenant_id=TENANT_A,
        boundary_ref=boundary_ref,
        scope=ConnectorScope("payment.transfer", "ledger-sandbox"),
        window=EnumerationWindow(start=end - timedelta(hours=1), end=end),
    )


def _service(
    *,
    tenant_engines: TenantEngines,
    factory: RecordFactory,
    now: datetime,
    signer: IssuerSigner | None = None,
) -> PopulationService:
    configured = signer or IssuerSigner(
        factory.receipt_key_id, factory.receipt_private_key
    )
    return PopulationService(
        tenant_engines=tenant_engines,
        issuer_signers={TENANT_A: configured},
        clock=lambda: now,
    )


def _record(
    *, request: PopulationRequest, suffix: str = "1"
) -> MockDestinationRecord:
    return MockDestinationRecord(
        record_id=f"destination-{suffix}",
        action_id=f"action-{suffix}",
        action_family=request.scope.action_family,
        authoritative_timestamp=request.window.end - timedelta(minutes=1),
    )


def _connector(
    *,
    request: PopulationRequest,
    now: datetime,
    config: MockConnectorConfig | None = None,
    records: tuple[MockDestinationRecord, ...] = (),
) -> DestinationConnector:
    return create_mock_connector(
        config=config or MockConnectorConfig(settlement_lag=LAG),
        records=records,
        destination_system=request.scope.destination_system,
        retrieved_at=now,
    )


def _stored_count(engines: TenantEngines, request: PopulationRequest) -> int:
    table = population_partition(TENANT_A)
    with tenant_connection(engines, TENANT_A) as connection:
        return int(
            connection.execute(
                select(func.count())
                .select_from(table)
                .where(
                    table.c.window_start == request.window.start,
                    table.c.window_end == request.window.end,
                )
            ).scalar_one()
        )


def _stored_record(
    engines: TenantEngines, population_ref: str
) -> PopulationRecord:
    table = population_partition(TENANT_A)
    with tenant_connection(engines, TENANT_A) as connection:
        wire = connection.execute(
            select(table.c.received_wire_bytes).where(
                table.c.population_ref == population_ref
            )
        ).scalar_one()
    record, _ = parse_canonical_record_wire(bytes(wire))
    assert isinstance(record, PopulationRecord)
    return record


def test_early_run_never_calls_the_connector(
    tenant_engines: TenantEngines,
    record_factories: dict[str, RecordFactory],
    default_boundaries: dict[str, str],
) -> None:
    now = _now()
    request = _request(
        boundary_ref=default_boundaries[TENANT_A],
        now=now,
        early_by=timedelta(seconds=1),
    )
    connector = _CountingConnector(_connector(request=request, now=now))

    with pytest.raises(SettlementLagPendingError) as pending:
        _service(
            tenant_engines=tenant_engines,
            factory=record_factories[TENANT_A],
            now=now,
        ).record_enumeration(request, connector)

    assert pending.value.eligible_at == request.window.end + LAG
    assert connector.enumeration_calls == 0
    assert _stored_count(tenant_engines, request) == 0


def test_missing_issuer_custody_fails_before_enumeration(
    tenant_engines: TenantEngines,
    record_factories: dict[str, RecordFactory],
    default_boundaries: dict[str, str],
) -> None:
    now = _now()
    request = _request(boundary_ref=default_boundaries[TENANT_A], now=now)
    connector = _CountingConnector(_connector(request=request, now=now))
    factory = record_factories[TENANT_A]
    evidence_signer = IssuerSigner(factory.key_id, factory.private_key)

    with pytest.raises(IssuerSignerError, match="registered issuer"):
        _service(
            tenant_engines=tenant_engines,
            factory=factory,
            now=now,
            signer=evidence_signer,
        ).record_enumeration(request, connector)

    assert connector.enumeration_calls == 0


def test_substituted_issuer_key_material_fails_before_enumeration(
    tenant_engines: TenantEngines,
    record_factories: dict[str, RecordFactory],
    default_boundaries: dict[str, str],
) -> None:
    now = _now()
    request = _request(boundary_ref=default_boundaries[TENANT_A], now=now)
    connector = _CountingConnector(_connector(request=request, now=now))
    factory = record_factories[TENANT_A]
    substituted = IssuerSigner(
        factory.receipt_key_id, Ed25519PrivateKey.generate()
    )

    with pytest.raises(IssuerSignerError, match="does not match"):
        _service(
            tenant_engines=tenant_engines,
            factory=factory,
            now=now,
            signer=substituted,
        ).record_enumeration(request, connector)

    assert connector.enumeration_calls == 0


def test_connector_lag_must_match_the_signed_qualification(
    tenant_engines: TenantEngines,
    record_factories: dict[str, RecordFactory],
    default_boundaries: dict[str, str],
) -> None:
    now = _now()
    request = _request(boundary_ref=default_boundaries[TENANT_A], now=now)
    connector = _CountingConnector(
        _connector(
            request=request,
            now=now,
            config=MockConnectorConfig(settlement_lag=timedelta(0)),
        )
    )

    with pytest.raises(ConnectorQualificationMismatchError, match="does not match"):
        _service(
            tenant_engines=tenant_engines,
            factory=record_factories[TENANT_A],
            now=now,
        ).record_enumeration(request, connector)

    assert connector.enumeration_calls == 0


def test_silent_truncation_fails_loudly_without_manufacturing_evidence(
    tenant_engines: TenantEngines,
    record_factories: dict[str, RecordFactory],
    default_boundaries: dict[str, str],
) -> None:
    now = _now()
    request = _request(boundary_ref=default_boundaries[TENANT_A], now=now)
    records = (_record(request=request, suffix="1"), _record(request=request, suffix="2"))
    connector = _connector(
        request=request,
        now=now,
        config=MockConnectorConfig(settlement_lag=LAG, silent_truncate_to=1),
        records=records,
    )

    with pytest.raises(SilentTruncationError, match="silently truncated"):
        _service(
            tenant_engines=tenant_engines,
            factory=record_factories[TENANT_A],
            now=now,
        ).record_enumeration(request, connector)

    assert _stored_count(tenant_engines, request) == 0


@pytest.mark.parametrize(
    ("config", "alert", "cap_hit", "pagination_complete", "offset_seconds"),
    [
        (
            MockConnectorConfig(settlement_lag=LAG, result_cap_hit=True),
            "result_cap_hit",
            True,
            True,
            1,
        ),
        (
            MockConnectorConfig(settlement_lag=LAG, pagination_complete=False),
            "pagination_incomplete",
            False,
            False,
            2,
        ),
    ],
)
def test_each_explicit_truncation_signal_is_independently_persisted(
    config: MockConnectorConfig,
    alert: str,
    cap_hit: bool,
    pagination_complete: bool,
    offset_seconds: int,
    tenant_engines: TenantEngines,
    record_factories: dict[str, RecordFactory],
    default_boundaries: dict[str, str],
) -> None:
    now = _now()
    request = _request(
        boundary_ref=default_boundaries[TENANT_A],
        now=now,
        early_by=-timedelta(seconds=offset_seconds),
    )

    result = _service(
        tenant_engines=tenant_engines,
        factory=record_factories[TENANT_A],
        now=now,
    ).record_enumeration(
        request,
        _connector(request=request, now=now, config=config),
    )
    record = _stored_record(tenant_engines, result.population_ref)

    assert result.enumeration_alerts == (alert,)
    assert record.body.result_cap_hit is cap_hit
    assert record.body.pagination_complete is pagination_complete


def test_observed_lag_overrun_is_signed_stored_and_alerted(
    tenant_engines: TenantEngines,
    record_factories: dict[str, RecordFactory],
    default_boundaries: dict[str, str],
) -> None:
    now = _now()
    request = _request(boundary_ref=default_boundaries[TENANT_A], now=now)
    connector = _connector(
        request=request,
        now=now,
        config=MockConnectorConfig(
            settlement_lag=LAG,
            observed_settlement_lag=LAG + timedelta(seconds=1),
        ),
        records=(_record(request=request),),
    )

    result = _service(
        tenant_engines=tenant_engines,
        factory=record_factories[TENANT_A],
        now=now,
    ).record_enumeration(request, connector)

    assert result.enumeration_alerts == ("settlement_lag_exceeded",)
    extras = _stored_record(
        tenant_engines, result.population_ref
    ).body.model_extra or {}
    assert extras["observed_settlement_lag_ms"] == 301_000


def test_stale_pre_settlement_snapshot_is_refused(
    tenant_engines: TenantEngines,
    record_factories: dict[str, RecordFactory],
    default_boundaries: dict[str, str],
) -> None:
    now = _now()
    request = _request(boundary_ref=default_boundaries[TENANT_A], now=now)
    stale = now - timedelta(seconds=1)
    connector = _connector(request=request, now=stale)

    with pytest.raises(PopulationObservationTimingError, match="before settlement"):
        _service(
            tenant_engines=tenant_engines,
            factory=record_factories[TENANT_A],
            now=now,
        ).record_enumeration(request, connector)

    assert _stored_count(tenant_engines, request) == 0


def test_duplicates_remain_distinct_denominator_evidence(
    tenant_engines: TenantEngines,
    record_factories: dict[str, RecordFactory],
    default_boundaries: dict[str, str],
) -> None:
    now = _now()
    request = _request(boundary_ref=default_boundaries[TENANT_A], now=now)
    connector = _connector(
        request=request,
        now=now,
        config=MockConnectorConfig(settlement_lag=LAG, duplicate_records=True),
        records=(_record(request=request),),
    )

    result = _service(
        tenant_engines=tenant_engines,
        factory=record_factories[TENANT_A],
        now=now,
    ).record_enumeration(request, connector)
    record = _stored_record(tenant_engines, result.population_ref)

    assert result.enumeration_alerts == ()
    assert record.body.count == 2
    assert record.body.record_identifiers == ["destination-1", "destination-1"]


def test_reenumeration_appends_and_surfaces_disagreement_instead_of_refreshing(
    tenant_engines: TenantEngines,
    record_factories: dict[str, RecordFactory],
    default_boundaries: dict[str, str],
) -> None:
    now = _now()
    request = _request(boundary_ref=default_boundaries[TENANT_A], now=now)
    service = _service(
        tenant_engines=tenant_engines,
        factory=record_factories[TENANT_A],
        now=now,
    )
    first = service.record_enumeration(
        request,
        _connector(
            request=request,
            now=now,
            records=(_record(request=request, suffix="first"),),
        ),
    )
    second = service.record_enumeration(
        request,
        _connector(
            request=request,
            now=now,
            records=(_record(request=request, suffix="second"),),
        ),
    )

    assert first.population_ref != second.population_ref
    assert second.sequence == first.sequence + 1
    assert _stored_count(tenant_engines, request) == 2
    assert len(second.disagreements) == 1
    finding = second.disagreements[0]
    assert finding.previous_population_ref == first.population_ref
    assert finding.current_population_ref == second.population_ref
    assert "record_identifiers" in finding.differing_fields
    second_record = _stored_record(tenant_engines, second.population_ref)
    assert second_record.prev_digest == first.record_digest


def test_task_contract_keeps_keys_out_of_broker_and_acknowledges_late(
    default_boundaries: dict[str, str],
) -> None:
    now = _now()
    request = _request(boundary_ref=default_boundaries[TENANT_A], now=now)

    payload = population_task_payload(request=request, connector_id="mock")

    assert "key_id" not in payload
    assert "private_key" not in payload
    assert "connector" not in payload
    assert record_population_task.acks_late is True
    assert record_population_task.reject_on_worker_lost is True


def test_scheduler_uses_qualification_eligibility_as_celery_eta(
    monkeypatch: pytest.MonkeyPatch,
    tenant_engines: TenantEngines,
    record_factories: dict[str, RecordFactory],
    default_boundaries: dict[str, str],
) -> None:
    now = _now()
    request = _request(boundary_ref=default_boundaries[TENANT_A], now=now)
    service = _service(
        tenant_engines=tenant_engines,
        factory=record_factories[TENANT_A],
        now=now,
    )
    connector = _connector(request=request, now=now)
    captured: dict[str, object] = {}

    def fake_apply_async(*, args: list[object], eta: datetime) -> str:
        captured.update(args=args, eta=eta)
        return "scheduled"

    monkeypatch.setattr(record_population_task, "apply_async", fake_apply_async)
    configure_population_tasks(
        PopulationTaskRuntime(service=service, connectors={"mock": connector})
    )
    try:
        result = schedule_population_enumeration(request=request, connector_id="mock")
    finally:
        configure_population_tasks(None)

    assert result == "scheduled"
    assert captured["eta"] == request.window.end + LAG
    args = captured["args"]
    assert isinstance(args, list)
    assert args[0] == population_task_payload(request=request, connector_id="mock")
