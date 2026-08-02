"""EV-07 acceptance steps through the HTTP surface and verifier primitives."""

from __future__ import annotations

import asyncio
import base64
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from pytest_bdd import given, scenario, then, when
from sqlalchemy import select

from sdk_python.evidence.canonical import canonical_digest
from sdk_python.evidence.chain import ChainVerificationResult, verify_stream
from sdk_python.evidence.schema import (
    IngestionReceipt,
    parse_record,
    serialize_record,
    validate_record,
)
from sdk_python.evidence.signing import sign_record
from services.ingestion.api import create_app
from services.ingestion.receipts import SignedIngestionReceipt, verify_ingestion_receipt
from services.ingestion.service import IngestionService, IssuerSigningKey
from services.ledger import (
    LedgerConfig,
    TenantEngines,
    digest_ref,
    evidence_partition,
    tenant_connection,
)
from tests.ledger_support import TENANT_A, RecordFactory


@scenario("architecture.feature", "AC-S-001 No queue in the write path")
def test_ac_s_001_no_queue_in_write_path() -> None:
    """Bound by pytest-bdd."""


@scenario("infrastructure.feature", "IN-S-001 No ack before durable commit")
def test_in_s_001_no_ack_before_durable_commit() -> None:
    """Bound by pytest-bdd."""


@scenario(
    "infrastructure.feature",
    "IN-S-003 Out-of-order reconnection reconciles by sequence",
)
def test_in_s_003_out_of_order_reconnection() -> None:
    """Bound by pytest-bdd."""


@scenario("security.feature", "SE-S-006 Unregistered collector rejected")
def test_se_s_006_unregistered_collector_rejected() -> None:
    """Bound by pytest-bdd."""


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _uuid7(number: int) -> str:
    base = UUID("01890f47-2f58-7cc0-98c4-dc0c0c070000").int
    return str(UUID(int=base + number))


def _encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


@dataclass
class IngestionHarness:
    app: FastAPI
    service: IngestionService
    tenant_engines: TenantEngines
    config: LedgerConfig
    factory: RecordFactory
    source_start: datetime

    def stream(
        self,
        *,
        stream_id: str,
        count: int,
        id_offset: int,
        collector_id: str | None = None,
        private_key: Ed25519PrivateKey | None = None,
        key_id: str | None = None,
    ) -> list[Any]:
        records: list[Any] = []
        previous_digest: str | None = None
        for sequence in range(1, count + 1):
            unsigned = validate_record(
                {
                    "record_id": _uuid7(id_offset + sequence),
                    "record_type": "AgentIdentity",
                    "schema_version": "1.0.0",
                    "tenant_id": TENANT_A,
                    "boundary_ref": "acme:default:1",
                    "stream_id": stream_id,
                    "sequence": sequence,
                    "prev_digest": previous_digest,
                    "source": {
                        "collector_id": collector_id or self.factory.collector_id,
                        "implementation": "sdk-python",
                        "version": "0.1.0",
                    },
                    "clocks": {
                        "source_time": _timestamp(
                            self.source_start + timedelta(seconds=sequence)
                        )
                    },
                    "body": {
                        "agent_id": f"agent-{stream_id}",
                        "deployment": "prod",
                        "runtime": "python-3.12",
                        "tenant_scope": TENANT_A,
                        "service_identity": "collector@example.invalid",
                        "model_versions": ["model-1"],
                        "tool_versions": ["tool-1"],
                        "credential_ref": "service_identity",
                    },
                    "signature": {},
                }
            )
            signed = sign_record(
                unsigned,
                key_id=key_id or self.factory.key_id,
                private_key=private_key or self.factory.private_key,
            )
            records.append(signed)
            previous_digest = canonical_digest(signed)
        return records

    def submit(self, record: Any) -> Any:
        response = asyncio.run(
            _asgi_post(self.app, "/v1/evidence", serialize_record(record))
        )
        return response


@dataclass(frozen=True)
class ASGIResponse:
    status_code: int
    body: bytes

    @property
    def text(self) -> str:
        return self.body.decode("utf-8")

    def json(self) -> Any:
        return json.loads(self.body)


async def _asgi_post(app: FastAPI, path: str, body: bytes) -> ASGIResponse:
    messages: list[dict[str, Any]] = []
    request_sent = False

    async def receive() -> dict[str, Any]:
        nonlocal request_sent
        if not request_sent:
            request_sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    await app(
        {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.5"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": path,
            "raw_path": path.encode("ascii"),
            "query_string": b"",
            "root_path": "",
            "headers": [(b"content-type", b"application/json")],
            "client": ("test", 123),
            "server": ("testserver", 80),
        },
        receive,
        send,
    )
    start = next(message for message in messages if message["type"] == "http.response.start")
    response_body = b"".join(
        message.get("body", b"")
        for message in messages
        if message["type"] == "http.response.body"
    )
    return ASGIResponse(status_code=start["status"], body=response_body)


@pytest.fixture
def ingestion_harness(
    ledger_config: LedgerConfig,
    tenant_engines: TenantEngines,
    record_factories: dict[str, RecordFactory],
) -> IngestionHarness:
    factory = record_factories[TENANT_A]
    source_start = datetime.now(UTC) + timedelta(seconds=1)
    service = IngestionService(
        tenant_engines=tenant_engines,
        issuer_signers={
            TENANT_A: IssuerSigningKey(
                key_id=factory.receipt_key_id,
                private_key=factory.receipt_private_key,
            )
        },
        clock=lambda: source_start + timedelta(minutes=2),
    )
    return IngestionHarness(
        app=create_app(service),
        service=service,
        tenant_engines=tenant_engines,
        config=ledger_config,
        factory=factory,
        source_start=source_start,
    )


def _stored_records(
    engines: TenantEngines,
    factory: RecordFactory,
    *,
    stream_id: str,
) -> list[Any]:
    partition = evidence_partition(TENANT_A)
    with tenant_connection(engines, TENANT_A) as connection:
        rows = connection.execute(
            select(partition).where(partition.c.stream_id == stream_id).order_by(
                partition.c.sequence
            )
        ).mappings().all()

    records: list[Any] = []
    for row in rows:
        envelope = json.loads(bytes(row["canonical_bytes"]))
        envelope["signature"] = {
            "alg": "ed25519",
            "key_id": row["key_id"],
            "sig": _encode_base64url(bytes(row["signature"])),
            "signed_digest": digest_ref(bytes(row["record_digest"])),
        }
        record = parse_record(envelope)
        receipt_bytes = bytes(row["receipt_canonical_bytes"])
        receipt = SignedIngestionReceipt(
            payload=IngestionReceipt.model_validate_json(receipt_bytes),
            canonical_bytes=receipt_bytes,
            key_id=row["receipt_key_id"],
            signature=bytes(row["receipt_signature"]),
        )
        verify_ingestion_receipt(
            receipt,
            record=record,
            issuer_public_keys={
                factory.receipt_key_id: factory.receipt_private_key.public_key()
            },
        )
        records.append(record)
    return records


def _verify_stored_stream(
    engines: TenantEngines,
    factory: RecordFactory,
    *,
    stream_id: str,
) -> ChainVerificationResult:
    return verify_stream(
        _stored_records(engines, factory, stream_id=stream_id),
        public_keys={factory.key_id: factory.private_key.public_key()},
    )


@given("a record submitted to ingestion", target_fixture="ingestion_context")
def record_submitted(ingestion_harness: IngestionHarness) -> dict[str, Any]:
    stream_id = "ev07-ac-001"
    return {
        "harness": ingestion_harness,
        "stream_id": stream_id,
        "record": ingestion_harness.stream(
            stream_id=stream_id, count=1, id_offset=100
        )[0],
    }


@when("ingestion acknowledges it")
def ingestion_acknowledges(ingestion_context: dict[str, Any]) -> None:
    ingestion_context["response"] = ingestion_context["harness"].submit(
        ingestion_context["record"]
    )


@then("the record is durably committed to the ledger")
def record_is_durably_committed(ingestion_context: dict[str, Any]) -> None:
    response = ingestion_context["response"]
    assert response.status_code == 201, response.text
    harness: IngestionHarness = ingestion_context["harness"]
    result = _verify_stored_stream(
        harness.tenant_engines,
        harness.factory,
        stream_id=ingestion_context["stream_id"],
    )
    assert result.end_sequence == 1


@then("no acknowledgment occurs before commit")
def no_ack_before_commit(ingestion_context: dict[str, Any]) -> None:
    response = ingestion_context["response"]
    assert response.status_code == 201
    assert response.json()["record_id"] == ingestion_context["record"].record_id


@given("ingestion receives a valid record", target_fixture="restart_context")
def ingestion_receives_valid_record(
    ingestion_harness: IngestionHarness,
) -> dict[str, Any]:
    stream_id = "ev07-in-001"
    return {
        "harness": ingestion_harness,
        "stream_id": stream_id,
        "record": ingestion_harness.stream(
            stream_id=stream_id, count=1, id_offset=200
        )[0],
    }


@when("the process is killed immediately after acknowledgment")
def process_killed_after_ack(restart_context: dict[str, Any]) -> None:
    harness: IngestionHarness = restart_context["harness"]
    response = harness.submit(restart_context["record"])
    assert response.status_code == 201, response.text
    harness.tenant_engines.dispose()
    restart_context["restarted_engines"] = TenantEngines(harness.config)


@then("the record is present after restart")
def record_present_after_restart(restart_context: dict[str, Any]) -> None:
    harness: IngestionHarness = restart_context["harness"]
    records = _stored_records(
        restart_context["restarted_engines"],
        harness.factory,
        stream_id=restart_context["stream_id"],
    )
    assert [record.record_id for record in records] == [
        restart_context["record"].record_id
    ]


@then("the chain verifies without a gap at that position")
def chain_verifies_after_restart(restart_context: dict[str, Any]) -> None:
    harness: IngestionHarness = restart_context["harness"]
    result = _verify_stored_stream(
        restart_context["restarted_engines"],
        harness.factory,
        stream_id=restart_context["stream_id"],
    )
    assert result.start_sequence == result.end_sequence == 1
    restart_context["restarted_engines"].dispose()


@given(
    "buffered records for sequences 10 through 20",
    target_fixture="reconnection_context",
)
def buffered_records(ingestion_harness: IngestionHarness) -> dict[str, Any]:
    stream_id = "ev07-in-003"
    records = ingestion_harness.stream(stream_id=stream_id, count=20, id_offset=300)
    for record in records[:9]:
        response = ingestion_harness.submit(record)
        assert response.status_code == 201, response.text
    return {
        "harness": ingestion_harness,
        "stream_id": stream_id,
        "buffered": records[9:],
    }


@when("they are submitted in arbitrary order after reconnection")
def submit_out_of_order(reconnection_context: dict[str, Any]) -> None:
    harness: IngestionHarness = reconnection_context["harness"]
    order = [5, 0, 10, 2, 8, 1, 9, 3, 7, 4, 6]
    responses = [
        harness.submit(reconnection_context["buffered"][index]) for index in order
    ]
    assert [response.status_code for response in responses] == [201] * 11


@then("the ledger reconstructs the chain by sequence")
def ledger_reconstructs_by_sequence(reconnection_context: dict[str, Any]) -> None:
    harness: IngestionHarness = reconnection_context["harness"]
    result = _verify_stored_stream(
        harness.tenant_engines,
        harness.factory,
        stream_id=reconnection_context["stream_id"],
    )
    reconnection_context["verification"] = result
    assert [record.sequence for record in result.records] == list(range(1, 21))


@then("no gap is reported")
def no_gap_reported(reconnection_context: dict[str, Any]) -> None:
    result: ChainVerificationResult = reconnection_context["verification"]
    assert result.start_sequence == 1
    assert result.end_sequence == 20


@given(
    "records signed by a collector identity not in the boundary",
    target_fixture="unregistered_context",
)
def unregistered_collector_record(
    ingestion_harness: IngestionHarness,
) -> dict[str, Any]:
    unregistered_key = Ed25519PrivateKey.generate()
    stream_id = "ev07-se-006"
    record = ingestion_harness.stream(
        stream_id=stream_id,
        count=1,
        id_offset=500,
        collector_id="unregistered-collector",
        private_key=unregistered_key,
        key_id="unregistered-key",
    )[0]
    return {
        "harness": ingestion_harness,
        "stream_id": stream_id,
        "record": record,
    }


@when("they are submitted to ingestion")
def unregistered_record_submitted(unregistered_context: dict[str, Any]) -> None:
    unregistered_context["response"] = unregistered_context["harness"].submit(
        unregistered_context["record"]
    )


@then("they are rejected")
def unregistered_record_rejected(unregistered_context: dict[str, Any]) -> None:
    response = unregistered_context["response"]
    assert response.status_code == 401
    assert "unregistered collector" in response.json()["detail"]


@then("they do not enter the ledger in any state")
def unregistered_record_absent(unregistered_context: dict[str, Any]) -> None:
    harness: IngestionHarness = unregistered_context["harness"]
    partition = evidence_partition(TENANT_A)
    with tenant_connection(harness.tenant_engines, TENANT_A) as connection:
        count = connection.execute(
            select(partition.c.record_id).where(
                partition.c.record_id == UUID(unregistered_context["record"].record_id)
            )
        ).all()
    assert count == []


def test_http_refuses_duplicate_envelope_members(
    ingestion_harness: IngestionHarness,
) -> None:
    response = asyncio.run(
        _asgi_post(
            ingestion_harness.app,
            "/v1/evidence",
            b'{"record_id":"first","record_id":"second"}',
        )
    )
    assert response.status_code == 422
    assert "duplicate JSON field" in response.json()["detail"]


def test_http_refuses_malformed_json(ingestion_harness: IngestionHarness) -> None:
    response = asyncio.run(
        _asgi_post(ingestion_harness.app, "/v1/evidence", b'{"record_id":')
    )
    assert response.status_code == 422
