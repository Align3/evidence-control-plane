"""Negative-first service tests beyond EV-07's thin acceptance scenarios."""

from __future__ import annotations

import ast
import inspect
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import Engine, select, text

from sdk_python.evidence.schema import serialize_record, validate_record
from sdk_python.evidence.signing import sign_record
from services.ingestion import api as ingestion_api
from services.ingestion import service as ingestion_module
from services.ingestion.receipts import NonCanonicalWireError
from services.ingestion.service import (
    ChainConflictError,
    CollectorAuthenticationError,
    ContentSubstitutionError,
    ForkIntegrityError,
    IngestionError,
    IngestionService,
    IssuerSigningKey,
    ReplayError,
)
from services.ledger import (
    TenantEngines,
    evidence_partition,
    integrity_event_partition,
    tenant_connection,
)
from tests.ledger_support import TENANT_A, RecordFactory


def _timestamp(value: datetime) -> str:
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _record(
    factory: RecordFactory,
    *,
    record_id: str,
    stream_id: str,
    sequence: int = 1,
    collector_id: str | None = None,
    version: str = "0.1.0",
    private_key: Ed25519PrivateKey | None = None,
    key_id: str | None = None,
    source_time: datetime | None = None,
) -> Any:
    source_time = source_time or datetime.now(UTC) + timedelta(seconds=1)
    unsigned = validate_record(
        {
            "record_id": record_id,
            "record_type": "AgentIdentity",
            "schema_version": "1.0.0",
            "tenant_id": TENANT_A,
            "boundary_ref": "acme:default:1",
            "stream_id": stream_id,
            "sequence": sequence,
            "prev_digest": None,
            "source": {
                "collector_id": collector_id or factory.collector_id,
                "implementation": "sdk-python",
                "version": version,
            },
            "clocks": {"source_time": _timestamp(source_time)},
            "body": {
                "agent_id": "agent-1",
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
    return sign_record(
        unsigned,
        key_id=key_id or factory.key_id,
        private_key=private_key or factory.private_key,
    )


@pytest.fixture
def ingestion_service(
    tenant_engines: TenantEngines,
    record_factories: dict[str, RecordFactory],
) -> IngestionService:
    factory = record_factories[TENANT_A]
    return IngestionService(
        tenant_engines=tenant_engines,
        issuer_signers={
            TENANT_A: IssuerSigningKey(
                key_id=factory.receipt_key_id,
                private_key=factory.receipt_private_key,
            )
        },
        clock=lambda: datetime.now(UTC) + timedelta(minutes=5),
    )


def _stored_record_ids(engines: TenantEngines, stream_id: str) -> list[str]:
    partition = evidence_partition(TENANT_A)
    with tenant_connection(engines, TENANT_A) as connection:
        return [
            str(row.record_id)
            for row in connection.execute(
                select(partition.c.record_id).where(partition.c.stream_id == stream_id)
            )
        ]


def _integrity_events(engines: TenantEngines, stream_id: str) -> list[Any]:
    partition = integrity_event_partition(TENANT_A)
    with tenant_connection(engines, TENANT_A) as connection:
        return list(
            connection.execute(
                select(partition).where(partition.c.stream_id == stream_id)
            ).mappings()
        )


def test_noncanonical_received_wire_is_refused_without_normalizing_or_storing(
    tenant_engines: TenantEngines,
    record_factories: dict[str, RecordFactory],
    ingestion_service: IngestionService,
) -> None:
    factory = record_factories[TENANT_A]
    record = _record(
        factory,
        record_id="01890f47-2f58-7cc0-98c4-dc0c0c076011",
        stream_id="ev07-noncanonical-wire",
    )
    noncanonical = json.dumps(
        record.model_dump(mode="json", exclude_unset=True),
        indent=2,
    ).encode()

    with pytest.raises(NonCanonicalWireError, match="not RFC 8785 canonical"):
        ingestion_service.ingest(noncanonical)
    assert _stored_record_ids(tenant_engines, record.stream_id) == []


def test_ingestion_stores_the_exact_received_canonical_wire(
    tenant_engines: TenantEngines,
    record_factories: dict[str, RecordFactory],
    ingestion_service: IngestionService,
) -> None:
    record = _record(
        record_factories[TENANT_A],
        record_id="01890f47-2f58-7cc0-98c4-dc0c0c076012",
        stream_id="ev07-exact-wire",
    )
    wire = serialize_record(record)
    ingestion_service.ingest(wire)

    partition = evidence_partition(TENANT_A)
    with tenant_connection(tenant_engines, TENANT_A) as connection:
        stored = connection.execute(
            select(partition.c.received_wire_bytes).where(
                partition.c.record_id == record.record_id
            )
        ).scalar_one()
    assert bytes(stored) == wire


def test_same_tenant_key_cannot_impersonate_another_registered_collector(
    owner_engine: Engine,
    tenant_engines: TenantEngines,
    record_factories: dict[str, RecordFactory],
    ingestion_service: IngestionService,
) -> None:
    factory = record_factories[TENANT_A]
    claimed_collector = "acme-collector-impersonated"
    with owner_engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO collectors (collector_id, tenant_id, implementation,"
                " version, mode, registered_at)"
                " VALUES (:cid, :tid, 'sdk-python', '0.1.0', 'checkpoint', now())"
            ),
            {"cid": claimed_collector, "tid": TENANT_A},
        )
    record = _record(
        factory,
        record_id="01890f47-2f58-7cc0-98c4-dc0c0c076001",
        stream_id="ev07-impersonation",
        collector_id=claimed_collector,
    )

    with pytest.raises(CollectorAuthenticationError, match="different collector"):
        ingestion_service.ingest(serialize_record(record))
    assert _stored_record_ids(tenant_engines, record.stream_id) == []


def test_invalid_customer_signature_never_enters_ledger(
    tenant_engines: TenantEngines,
    record_factories: dict[str, RecordFactory],
    ingestion_service: IngestionService,
) -> None:
    factory = record_factories[TENANT_A]
    record = _record(
        factory,
        record_id="01890f47-2f58-7cc0-98c4-dc0c0c076002",
        stream_id="ev07-invalid-signature",
        private_key=Ed25519PrivateKey.generate(),
    )

    with pytest.raises(CollectorAuthenticationError, match="signature verification"):
        ingestion_service.ingest(serialize_record(record))
    assert _stored_record_ids(tenant_engines, record.stream_id) == []


def test_registered_collector_version_mismatch_is_refused(
    tenant_engines: TenantEngines,
    record_factories: dict[str, RecordFactory],
    ingestion_service: IngestionService,
) -> None:
    factory = record_factories[TENANT_A]
    record = _record(
        factory,
        record_id="01890f47-2f58-7cc0-98c4-dc0c0c076003",
        stream_id="ev07-version-mismatch",
        version="9.9.9",
    )

    with pytest.raises(CollectorAuthenticationError, match="version"):
        ingestion_service.ingest(serialize_record(record))
    assert _stored_record_ids(tenant_engines, record.stream_id) == []


def test_revoked_collector_credential_is_refused(
    owner_engine: Engine,
    tenant_engines: TenantEngines,
    record_factories: dict[str, RecordFactory],
    ingestion_service: IngestionService,
) -> None:
    factory = record_factories[TENANT_A]
    private_key = Ed25519PrivateKey.generate()
    collector_id = "acme-collector-revoked"
    key_id = "acme-evidence-revoked-collector"
    with owner_engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO collectors (collector_id, tenant_id, implementation,"
                " version, mode, registered_at, revoked_at)"
                " VALUES (:cid, :tid, 'sdk-python', '0.1.0', 'checkpoint',"
                " now() - interval '1 day', now())"
            ),
            {"cid": collector_id, "tid": TENANT_A},
        )
        connection.execute(
            text(
                "INSERT INTO keys (key_id, tenant_id, collector_id, namespace,"
                " public_key, custody, valid_from)"
                " VALUES (:kid, :tid, :cid, 'evidence', :pk, 'client_held',"
                " now() - interval '1 day')"
            ),
            {
                "kid": key_id,
                "tid": TENANT_A,
                "cid": collector_id,
                "pk": private_key.public_key().public_bytes_raw(),
            },
        )
    record = _record(
        factory,
        record_id="01890f47-2f58-7cc0-98c4-dc0c0c076008",
        stream_id="ev07-revoked-collector",
        collector_id=collector_id,
        private_key=private_key,
        key_id=key_id,
    )

    with pytest.raises(CollectorAuthenticationError, match="revoked"):
        ingestion_service.ingest(serialize_record(record))
    assert _stored_record_ids(tenant_engines, record.stream_id) == []


def test_expired_evidence_key_is_refused(
    owner_engine: Engine,
    tenant_engines: TenantEngines,
    record_factories: dict[str, RecordFactory],
    ingestion_service: IngestionService,
) -> None:
    factory = record_factories[TENANT_A]
    private_key = Ed25519PrivateKey.generate()
    key_id = "acme-evidence-expired"
    with owner_engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO keys (key_id, tenant_id, collector_id, namespace,"
                " public_key, custody, valid_from, valid_until)"
                " VALUES (:kid, :tid, :cid, 'evidence', :pk, 'client_held',"
                " now() - interval '1 day', now())"
            ),
            {
                "kid": key_id,
                "tid": TENANT_A,
                "cid": factory.collector_id,
                "pk": private_key.public_key().public_bytes_raw(),
            },
        )
    record = _record(
        factory,
        record_id="01890f47-2f58-7cc0-98c4-dc0c0c076009",
        stream_id="ev07-expired-key",
        private_key=private_key,
        key_id=key_id,
    )

    with pytest.raises(CollectorAuthenticationError, match="expired"):
        ingestion_service.ingest(serialize_record(record))
    assert _stored_record_ids(tenant_engines, record.stream_id) == []


def test_noninitial_sequence_without_prev_digest_is_refused(
    tenant_engines: TenantEngines,
    record_factories: dict[str, RecordFactory],
    ingestion_service: IngestionService,
) -> None:
    factory = record_factories[TENANT_A]
    record = _record(
        factory,
        record_id="01890f47-2f58-7cc0-98c4-dc0c0c076010",
        stream_id="ev07-missing-prev-digest",
        sequence=2,
    )

    with pytest.raises(ChainConflictError, match="must name prev_digest"):
        ingestion_service.ingest(serialize_record(record))
    assert _stored_record_ids(tenant_engines, record.stream_id) == []


def test_evidence_namespace_key_cannot_be_configured_as_receipt_signer(
    tenant_engines: TenantEngines,
    record_factories: dict[str, RecordFactory],
) -> None:
    factory = record_factories[TENANT_A]
    service = IngestionService(
        tenant_engines=tenant_engines,
        issuer_signers={
            TENANT_A: IssuerSigningKey(
                key_id=factory.key_id,
                private_key=factory.private_key,
            )
        },
        clock=lambda: datetime.now(UTC) + timedelta(minutes=5),
    )
    record = _record(
        factory,
        record_id="01890f47-2f58-7cc0-98c4-dc0c0c076004",
        stream_id="ev07-wrong-receipt-namespace",
    )

    with pytest.raises(IngestionError, match="registered issuer key"):
        service.ingest(serialize_record(record))
    assert _stored_record_ids(tenant_engines, record.stream_id) == []


def test_configured_receipt_private_key_must_match_registry(
    tenant_engines: TenantEngines,
    record_factories: dict[str, RecordFactory],
) -> None:
    factory = record_factories[TENANT_A]
    service = IngestionService(
        tenant_engines=tenant_engines,
        issuer_signers={
            TENANT_A: IssuerSigningKey(
                key_id=factory.receipt_key_id,
                private_key=Ed25519PrivateKey.generate(),
            )
        },
        clock=lambda: datetime.now(UTC) + timedelta(minutes=5),
    )
    record = _record(
        factory,
        record_id="01890f47-2f58-7cc0-98c4-dc0c0c076005",
        stream_id="ev07-wrong-receipt-private-key",
    )

    with pytest.raises(IngestionError, match="does not match"):
        service.ingest(serialize_record(record))
    assert _stored_record_ids(tenant_engines, record.stream_id) == []


def test_second_record_at_an_occupied_stream_position_is_refused(
    tenant_engines: TenantEngines,
    record_factories: dict[str, RecordFactory],
    ingestion_service: IngestionService,
) -> None:
    factory = record_factories[TENANT_A]
    first = _record(
        factory,
        record_id="01890f47-2f58-7cc0-98c4-dc0c0c076006",
        stream_id="ev07-fork",
    )
    fork = _record(
        factory,
        record_id="01890f47-2f58-7cc0-98c4-dc0c0c076007",
        stream_id="ev07-fork",
    )
    ingestion_service.ingest(serialize_record(first))

    with pytest.raises(ForkIntegrityError, match="fatal stream fork") as caught:
        ingestion_service.ingest(serialize_record(fork))
    assert caught.value.error_code == "integrity.stream_fork"
    assert _stored_record_ids(tenant_engines, first.stream_id) == [first.record_id]
    events = _integrity_events(tenant_engines, first.stream_id)
    assert len(events) == 1
    assert events[0]["event_id"] == caught.value.event_id
    assert events[0]["event_type"] == "stream_fork"
    assert events[0]["surfaced_to_tenant_at"] is not None


def test_exact_replay_has_a_distinct_code_and_is_not_an_integrity_event(
    tenant_engines: TenantEngines,
    record_factories: dict[str, RecordFactory],
    ingestion_service: IngestionService,
) -> None:
    record = _record(
        record_factories[TENANT_A],
        record_id="01890f47-2f58-7cc0-98c4-dc0c0c076013",
        stream_id="ev07-replay",
    )
    wire = serialize_record(record)
    ingestion_service.ingest(wire)

    with pytest.raises(ReplayError, match="exact record replay") as caught:
        ingestion_service.ingest(wire)
    assert caught.value.error_code == "ingestion.replay"
    assert _integrity_events(tenant_engines, record.stream_id) == []


def test_content_substitution_has_a_distinct_code_and_tenant_event(
    tenant_engines: TenantEngines,
    record_factories: dict[str, RecordFactory],
    ingestion_service: IngestionService,
) -> None:
    factory = record_factories[TENANT_A]
    record_id = "01890f47-2f58-7cc0-98c4-dc0c0c076014"
    accepted = _record(factory, record_id=record_id, stream_id="ev07-original")
    substitute = _record(factory, record_id=record_id, stream_id="ev07-substitute")
    ingestion_service.ingest(serialize_record(accepted))

    with pytest.raises(
        ContentSubstitutionError, match="different content"
    ) as caught:
        ingestion_service.ingest(serialize_record(substitute))
    assert caught.value.error_code == "integrity.content_substitution"
    events = _integrity_events(tenant_engines, substitute.stream_id)
    assert len(events) == 1
    assert events[0]["event_id"] == caught.value.event_id
    assert events[0]["event_type"] == "content_substitution"


def test_write_path_has_no_broker_dependency() -> None:
    """AC-001/AC-010: importing ingestion cannot smuggle in an async queue."""
    imported: set[str] = set()
    for module in (ingestion_module, ingestion_api):
        tree = ast.parse(inspect.getsource(module))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".", 1)[0])
    assert imported.isdisjoint({"celery", "kombu", "redis"})


def test_ingestion_uses_ev27_namespaced_verification_entry_points() -> None:
    """F3: namespace policy has one implementation, not a parallel SQL copy."""

    source = inspect.getsource(ingestion_module)
    assert "verify_evidence_record_signature(" in source
    assert "verify_ingestion_receipt(" in source
    assert "verify_record_signature(" not in source
    assert "issuer_public_keys" not in source
    assert "def _evidence_key(" not in source
    assert "def _issuer_public_key(" not in source
