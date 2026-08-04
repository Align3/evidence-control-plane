"""Refusal and boundary tests for issuer-authored ingestion receipts."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from sdk_python.evidence.canonical import canonicalize
from sdk_python.evidence.schema import IngestionReceipt
from sdk_python.evidence.signing import sign_record
from services.ingestion.receipts import (
    ReceiptError,
    ReceiptSignatureError,
    create_ingestion_receipt,
    measure_clock_skew_ms,
    verify_ingestion_receipt,
)
from tests.steps.test_ingestion_receipt_steps import _unsigned_record


def _signed_record():
    key = Ed25519PrivateKey.generate()
    return sign_record(_unsigned_record(), key_id="customer", private_key=key)


def test_receipt_for_another_record_is_refused_even_with_a_valid_issuer_signature() -> None:
    issuer = Ed25519PrivateKey.generate()
    first = _signed_record()
    second = _signed_record().model_copy(
        update={"record_id": "01890f47-2f58-7cc0-98c4-dc0c0c073990"}, deep=True
    )
    receipt = create_ingestion_receipt(
        first,
        ingest_time=datetime(2026, 8, 1, 12, 0, 1, tzinfo=UTC),
        issuer_key_id="issuer",
        issuer_private_key=issuer,
    )

    with pytest.raises(ReceiptSignatureError, match="different customer record"):
        verify_ingestion_receipt(
            receipt,
            record=second,
            issuer_public_keys={"issuer": issuer.public_key()},
        )


def test_unknown_receipt_key_is_refused() -> None:
    issuer = Ed25519PrivateKey.generate()
    record = _signed_record()
    receipt = create_ingestion_receipt(
        record,
        ingest_time=datetime(2026, 8, 1, 12, 0, 1, tzinfo=UTC),
        issuer_key_id="issuer",
        issuer_private_key=issuer,
    )
    with pytest.raises(ReceiptSignatureError, match="unknown receipt signing key"):
        verify_ingestion_receipt(receipt, record=record, issuer_public_keys={})


def test_noncanonical_receipt_bytes_are_refused_before_use() -> None:
    issuer = Ed25519PrivateKey.generate()
    record = _signed_record()
    receipt = create_ingestion_receipt(
        record,
        ingest_time=datetime(2026, 8, 1, 12, 0, 1, tzinfo=UTC),
        issuer_key_id="issuer",
        issuer_private_key=issuer,
    )
    spaced = receipt.canonical_bytes.replace(b":", b": ", 1)
    resigned = replace(receipt, canonical_bytes=spaced, signature=issuer.sign(spaced))
    with pytest.raises(ReceiptSignatureError, match="not RFC 8785 canonical"):
        verify_ingestion_receipt(
            resigned,
            record=record,
            issuer_public_keys={"issuer": issuer.public_key()},
        )


def test_correctly_signed_but_miscomputed_skew_is_refused() -> None:
    issuer = Ed25519PrivateKey.generate()
    record = _signed_record()
    receipt = create_ingestion_receipt(
        record,
        ingest_time=datetime(2026, 8, 1, 12, 0, 1, tzinfo=UTC),
        issuer_key_id="issuer",
        issuer_private_key=issuer,
    )
    wrong_payload = receipt.payload.model_copy(update={"clock_skew_ms": 0})
    wrong_bytes = canonicalize(wrong_payload)
    wrongly_measured = replace(
        receipt,
        payload=wrong_payload,
        canonical_bytes=wrong_bytes,
        signature=issuer.sign(wrong_bytes),
    )

    with pytest.raises(ReceiptSignatureError, match="does not match"):
        verify_ingestion_receipt(
            wrongly_measured,
            record=record,
            issuer_public_keys={"issuer": issuer.public_key()},
        )


def test_receipt_payload_is_closed_and_forbids_floats() -> None:
    with pytest.raises(ValidationError, match="extra"):
        IngestionReceipt.model_validate(
            {
                "record_digest": "sha256:" + "0" * 64,
                "ingest_time": "2026-08-01T12:00:00.000Z",
                "clock_skew_ms": 0,
                "collector_skew_ms": 0,
            }
        )
    with pytest.raises(ValidationError, match="IEEE-754 floats"):
        IngestionReceipt.model_validate(
            {
                "record_digest": "sha256:" + "0" * 64,
                "ingest_time": "2026-08-01T12:00:00.000Z",
                "clock_skew_ms": 0.5,
            }
        )


def test_clock_skew_uses_instants_and_truncates_toward_zero() -> None:
    assert measure_clock_skew_ms(
        source_time="2026-08-01T13:00:00.000+01:00",
        ingest_time="2026-08-01T12:00:01.234Z",
    ) == 1_234
    assert measure_clock_skew_ms(
        source_time="2026-08-01T12:00:00.9999Z",
        ingest_time="2026-08-01T12:00:00.000Z",
    ) == -999


def test_naive_ingest_time_is_refused() -> None:
    with pytest.raises(ReceiptError, match="timezone-aware"):
        create_ingestion_receipt(
            _signed_record(),
            ingest_time=datetime(2026, 8, 1, 12, 0, 1),
            issuer_key_id="issuer",
            issuer_private_key=Ed25519PrivateKey.generate(),
        )


def test_receipt_payload_serializes_deterministically() -> None:
    payload = IngestionReceipt(
        record_digest="sha256:" + "0" * 64,
        ingest_time="2026-08-01T12:00:00.000Z",
        clock_skew_ms=0,
    )
    assert canonicalize(payload) == (
        b'{"clock_skew_ms":0,"ingest_time":"2026-08-01T12:00:00.000Z",'
        b'"record_digest":"sha256:' + b"0" * 64 + b'"}'
    )
