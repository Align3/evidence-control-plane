"""IN-S-002 acceptance: offline gap emission on buffer exhaustion (IN-011).

The scenario's first Given is load-bearing and is honoured literally. The
transport points at a TCP port with nothing listening, so the connection is
refused by the kernel. A mock that returns an error quickly would prove only
that the client handles an error return; it would not prove that gap emission
survives the case this requirement exists for, which is our service being
genuinely absent.
"""

from __future__ import annotations

import json
import socket
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi import FastAPI
from pytest_bdd import given, scenario, then, when

from sdk_python.client import (
    ClientConfig,
    EvidenceClient,
    FamilyPolicy,
    HttpTransport,
    SigningIdentity,
)
from sdk_python.evidence.schema import parse_record
from services.ingestion.api import create_app
from services.ingestion.service import IngestionService, IssuerSigningKey
from services.ledger import TenantEngines
from tests.ledger_support import TENANT_A, RecordFactory
from tests.steps.asgi_support import asgi_post

BOUND = 3
FAMILY = "payment.transfer"


@scenario("infrastructure.feature", "IN-S-002 Offline gap emission on buffer exhaustion")
def test_in_s_002_offline_gap_emission() -> None:
    """Bound by pytest-bdd."""


@dataclass
class GapScenario:
    client: EvidenceClient
    app: FastAPI
    dead_port: int
    emitted: list[Any] = field(default_factory=list)
    dropped_at_gap: int | None = None


@pytest.fixture
def closed_port(free_tcp_port: int) -> int:
    """A port with nothing bound: connect() is refused, not merely slow."""

    probe = socket.socket()
    try:
        probe.settimeout(0.25)
        assert probe.connect_ex(("127.0.0.1", free_tcp_port)) != 0, (
            "the scenario requires a genuinely unreachable endpoint"
        )
    finally:
        probe.close()
    return free_tcp_port


@given("ingestion is unreachable", target_fixture="gap_scenario")
def _ingestion_unreachable(
    closed_port: int,
    tenant_engines: TenantEngines,
    record_factories: dict[str, RecordFactory],
) -> GapScenario:
    factory = record_factories[TENANT_A]
    service = IngestionService(
        tenant_engines=tenant_engines,
        issuer_signers={
            TENANT_A: IssuerSigningKey(
                key_id=factory.receipt_key_id,
                private_key=factory.receipt_private_key,
            )
        },
        clock=lambda: datetime.now(UTC) + timedelta(minutes=1),
    )
    client = EvidenceClient(
        config=ClientConfig(
            tenant_id=factory.tenant_id,
            boundary_ref="acme:default:1",
            collector_id=factory.collector_id,
            deployment="prod",
            buffer_bound=BOUND,
            families={
                FAMILY: FamilyPolicy.fail_open(
                    acknowledged_by="reviewer@example.invalid",
                    reason="EV-08 acceptance",
                )
            },
        ),
        identity=SigningIdentity(
            key_id=factory.key_id, private_key=factory.private_key
        ),
        transport=HttpTransport(f"http://127.0.0.1:{closed_port}/v1/evidence"),
    )
    return GapScenario(client=client, app=create_app(service), dead_port=closed_port)


@given("the SDK local buffer reaches its configured bound")
def _buffer_reaches_bound(gap_scenario: GapScenario) -> None:
    for index in range(BOUND):
        gap_scenario.emitted.append(
            gap_scenario.client.emit_execution_receipt(
                _receipt_body(index), action_family=FAMILY
            )
        )
    assert gap_scenario.client.buffered_count() == BOUND
    assert gap_scenario.client.gap_records() == []


@when("further actions occur")
def _further_actions(gap_scenario: GapScenario) -> None:
    gap_scenario.emitted.append(
        gap_scenario.client.emit_execution_receipt(
            _receipt_body(BOUND), action_family=FAMILY
        )
    )
    gap_scenario.dropped_at_gap = gap_scenario.client.dropped_count()


@then("a locally signed CoverageGap is emitted")
def _gap_is_locally_signed(gap_scenario: GapScenario) -> None:
    gaps = gap_scenario.client.gap_records()
    assert len(gaps) == 1
    gap = parse_record(json.loads(gaps[0].canonical_bytes))
    assert gap.record_type == "CoverageGap"
    assert gap.body.cause == "collector_unreachable"
    assert gap.signature["key_id"] == gap_scenario.client.key_id
    # IN-011: emitted before anything was discarded, not as a post-hoc note.
    assert gap_scenario.dropped_at_gap == 0


@then("it is accepted on reconnection with its original signature")
def _accepted_on_reconnection(gap_scenario: GapScenario) -> None:
    gaps = gap_scenario.client.gap_records()
    original = gaps[0].canonical_bytes
    original_signature = json.loads(original)["signature"]

    submitted = gap_scenario.client.flush(
        transport=_AsgiTransport(gap_scenario.app)
    )

    replayed = next(item for item in submitted if item.record_type == "CoverageGap")
    assert replayed.canonical_bytes == original, "flush re-signed or re-timestamped"
    assert json.loads(replayed.canonical_bytes)["signature"] == original_signature
    assert replayed.accepted


class _AsgiTransport:
    """Reconnected transport: the real ingestion app over ASGI."""

    def __init__(self, app: FastAPI) -> None:
        self._app = app

    def submit(self, canonical_bytes: bytes) -> None:
        response = asgi_post(self._app, "/v1/evidence", canonical_bytes)
        if response.status_code >= 400:
            raise AssertionError(
                f"ingestion refused a replayed record: {response.status_code} "
                f"{response.body!r}"
            )


def _receipt_body(index: int) -> dict[str, Any]:
    moment = datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return {
        "action_id": f"00000000-0000-4000-8000-{index:012d}",
        "dispatch_attempt": 1,
        "connector_identity": "acme-connector",
        "connector_version": "0.1.0",
        "destination_response_digest": "sha256:" + "22" * 32,
        "destination_record_ref": f"destination-{index}",
        "status": "accepted",
        "dispatched_at": moment,
        "responded_at": moment,
    }
