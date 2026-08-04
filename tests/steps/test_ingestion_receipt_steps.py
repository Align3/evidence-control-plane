"""ES-S-013 -- a collector cannot choose its own hosted clock skew."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pytest_bdd import given, scenario, then, when

from sdk_python.evidence.canonical import canonicalize
from sdk_python.evidence.schema import IngestionReceipt, validate_record
from sdk_python.evidence.signing import record_signing_bytes, sign_record
from services.ingestion.receipts import (
    ReceiptSignatureError,
    create_ingestion_receipt,
    verify_ingestion_receipt,
)


@scenario("evidence.feature", "ES-S-013 Collector cannot suppress measured skew")
def test_es_s_010_collector_cannot_suppress_measured_skew() -> None:
    """The hosted observation is authenticated by its actual observer."""


def _unsigned_record() -> Any:
    return validate_record(
        {
            "record_id": "01890f47-2f58-7cc0-98c4-dc0c0c07398f",
            "record_type": "AgentIdentity",
            "schema_version": "1.0.0",
            "tenant_id": "tenant-1",
            "boundary_ref": "boundary-1",
            "stream_id": "collector-1",
            "sequence": 1,
            "prev_digest": None,
            "source": {"collector_id": "collector-1", "version": "1.0.0"},
            "clocks": {"source_time": "2026-08-01T12:00:00.000Z"},
            "body": {
                "agent_id": "agent-1",
                "deployment": "prod",
                "runtime": "python-3.12",
                "tenant_scope": "tenant-1",
                "service_identity": "collector@example.invalid",
                "model_versions": ["model-1"],
                "tool_versions": ["tool-1"],
                "credential_ref": "service_identity",
            },
            "signature": {},
        }
    )


@given(
    "an issuer-signed ingestion receipt whose measured clock_skew_ms is non-zero",
    target_fixture="receipt_context",
)
def issuer_signed_receipt() -> dict[str, Any]:
    customer_key = Ed25519PrivateKey.generate()
    issuer_key = Ed25519PrivateKey.generate()
    record = sign_record(
        _unsigned_record(), key_id="customer-key", private_key=customer_key
    )
    customer_bytes = record_signing_bytes(record)
    receipt = create_ingestion_receipt(
        record,
        ingest_time=datetime(2026, 8, 1, 12, 0, 1, 250_000, tzinfo=UTC),
        issuer_key_id="issuer-key",
        issuer_private_key=issuer_key,
    )
    assert receipt.payload.clock_skew_ms == 1_250
    assert verify_ingestion_receipt(
        receipt,
        record=record,
        issuer_public_keys={"issuer-key": issuer_key.public_key()},
    ) == receipt.payload
    return {
        "record": record,
        "customer_bytes": customer_bytes,
        "issuer_key": issuer_key,
        "receipt": receipt,
    }


@when("clock_skew_ms is replaced with a collector-reported value of 0")
def replace_skew_with_collector_value(receipt_context: dict[str, Any]) -> None:
    receipt = receipt_context["receipt"]
    tampered_payload = IngestionReceipt(
        record_digest=receipt.payload.record_digest,
        ingest_time=receipt.payload.ingest_time,
        clock_skew_ms=0,
    )
    receipt_context["tampered"] = replace(
        receipt,
        canonical_bytes=canonicalize(tampered_payload),
    )


@then("receipt verification fails")
def receipt_verification_fails(receipt_context: dict[str, Any]) -> None:
    with pytest.raises(ReceiptSignatureError):
        verify_ingestion_receipt(
            receipt_context["tampered"],
            record=receipt_context["record"],
            issuer_public_keys={
                "issuer-key": receipt_context["issuer_key"].public_key()
            },
        )


@then("the customer-signed record bytes remain unchanged")
def customer_bytes_are_unchanged(receipt_context: dict[str, Any]) -> None:
    assert record_signing_bytes(receipt_context["record"]) == receipt_context[
        "customer_bytes"
    ]
