"""Acceptance for EV-14's signed, durable truncation observation."""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pytest_bdd import given, scenario, then, when
from sqlalchemy import select

from sdk_python.evidence.schema import PopulationRecord
from services.computation import IssuerSigner, PopulationRequest, PopulationService
from services.computation.tasks import (
    PopulationTaskRuntime,
    configure_population_tasks,
    population_task_payload,
    record_population_task,
)
from services.connectors import (
    ConnectorScope,
    EnumerationWindow,
    MockConnectorConfig,
    create_mock_connector,
)
from services.ingestion.receipts import (
    RegisteredPublicKey,
    verify_canonical_evidence_record,
)
from services.ledger import TenantEngines, population_partition, tenant_connection
from tests.ledger_support import TENANT_A, RecordFactory

REPO = Path(__file__).resolve().parents[2]


@scenario(
    "evidence.feature",
    "ES-S-020 Truncation is durably recorded without becoming a denominator",
)
def test_es_s_020() -> None:
    """Bound by pytest-bdd."""


@pytest.fixture(autouse=True)
def _clear_population_task_runtime() -> None:
    configure_population_tasks(None)


@pytest.fixture(scope="module")
def population_go_verifier() -> Path:
    go = shutil.which("go")
    if go is None:
        pytest.skip("Go is required to independently verify PopulationRecord output")
    output = Path(tempfile.mkdtemp(prefix="es-s-020-go-")) / "verify"
    built = subprocess.run(  # noqa: S603
        [go, "build", "-buildvcs=false", "-o", str(output), "./cmd/verify"],
        cwd=REPO / "verifier-go",
        capture_output=True,
        text=True,
        check=False,
    )
    if built.returncode != 0:
        raise AssertionError(f"Go verifier build failed:\n{built.stdout}\n{built.stderr}")
    return output


@dataclass
class PopulationScenario:
    tenant_engines: TenantEngines
    factory: RecordFactory
    request: PopulationRequest
    task_result: dict[str, Any] | None = None
    wire: bytes | None = None


@given(
    "a connector observation with result_cap_hit true and pagination_complete false",
    target_fixture="population_scenario",
)
def _truncated_observation(
    tenant_engines: TenantEngines,
    record_factories: dict[str, RecordFactory],
    default_boundaries: dict[str, str],
) -> PopulationScenario:
    current = datetime.now(UTC)
    now = current.replace(microsecond=(current.microsecond // 1_000) * 1_000)
    lag = timedelta(minutes=5)
    window = EnumerationWindow(
        start=now - lag - timedelta(hours=1),
        end=now - lag,
    )
    request = PopulationRequest(
        tenant_id=TENANT_A,
        boundary_ref=default_boundaries[TENANT_A],
        scope=ConnectorScope("payment.transfer", "ledger-sandbox"),
        window=window,
    )
    factory = record_factories[TENANT_A]
    service = PopulationService(
        tenant_engines=tenant_engines,
        issuer_signers={
            TENANT_A: IssuerSigner(factory.receipt_key_id, factory.receipt_private_key)
        },
        clock=lambda: now,
    )
    connector = create_mock_connector(
        config=MockConnectorConfig(
            settlement_lag=lag,
            result_cap_hit=True,
            pagination_complete=False,
        ),
        destination_system="ledger-sandbox",
        retrieved_at=now,
    )
    configure_population_tasks(
        PopulationTaskRuntime(service=service, connectors={"qualified-mock": connector})
    )
    return PopulationScenario(
        tenant_engines=tenant_engines,
        factory=factory,
        request=request,
    )


@when("the population service records the enumeration")
def _record_enumeration(population_scenario: PopulationScenario) -> None:
    payload = population_task_payload(
        request=population_scenario.request,
        connector_id="qualified-mock",
    )
    eager_result = record_population_task.apply(args=[payload], throw=True)
    population_scenario.task_result = eager_result.get()


@then("the signed PopulationRecord preserves both truncation values")
def _preserves_flags(
    population_scenario: PopulationScenario,
    population_go_verifier: Path,
) -> None:
    result = population_scenario.task_result
    assert result is not None
    with tenant_connection(
        population_scenario.tenant_engines, TENANT_A
    ) as connection:
        wire = connection.execute(
            select(population_partition(TENANT_A).c.received_wire_bytes).where(
                population_partition(TENANT_A).c.population_ref
                == result["population_ref"]
            )
        ).scalar_one()
    population_scenario.wire = bytes(wire)
    registered = RegisteredPublicKey(
        namespace="issuer",
        public_key=population_scenario.factory.receipt_private_key.public_key(),
    )
    record = verify_canonical_evidence_record(
        population_scenario.wire,
        verification_keys={population_scenario.factory.receipt_key_id: registered},
    )
    assert isinstance(record, PopulationRecord)
    assert record.body.result_cap_hit is True
    assert record.body.pagination_complete is False
    assert set(result["enumeration_alerts"]) == {
        "result_cap_hit",
        "pagination_incomplete",
    }

    keyring = {
        population_scenario.factory.receipt_key_id: {
            "namespace": "issuer",
            "public_key": base64.urlsafe_b64encode(
                population_scenario.factory.receipt_private_key.public_key().public_bytes_raw()
            )
            .rstrip(b"=")
            .decode("ascii"),
        }
    }
    with tempfile.TemporaryDirectory(prefix="es-s-020-record-") as directory:
        root = Path(directory)
        record_path = root / "population.json"
        keyring_path = root / "keyring.json"
        record_path.write_bytes(population_scenario.wire)
        keyring_path.write_text(json.dumps(keyring), encoding="utf-8")
        verified = subprocess.run(  # noqa: S603
            [
                str(population_go_verifier),
                "-mode",
                "record",
                "-keyring",
                str(keyring_path),
                str(record_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    assert verified.returncode == 0, verified.stderr
    assert verified.stdout.startswith("VALID PopulationRecord")


@then("the record is durably appended before the task acknowledges it")
def _durable_before_acknowledgement(population_scenario: PopulationScenario) -> None:
    result = population_scenario.task_result
    assert result is not None
    assert record_population_task.acks_late is True
    assert record_population_task.reject_on_worker_lost is True
    # A fresh transaction after the eager task returned observes the row. The
    # task result therefore cannot precede the commit it acknowledges.
    with tenant_connection(
        population_scenario.tenant_engines, TENANT_A
    ) as connection:
        stored = connection.execute(
            select(population_partition(TENANT_A).c.population_ref).where(
                population_partition(TENANT_A).c.population_ref
                == result["population_ref"]
            )
        ).scalar_one()
    assert stored == result["population_ref"]
