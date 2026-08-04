"""Shared helpers for the EV-06 ledger tests.

Kept out of `conftest.py` so unit and property tests can import the record
builder directly without going through a fixture.
"""

from __future__ import annotations

import base64
import hashlib
import subprocess
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sdk_python.evidence.canonical import canonicalize
from sdk_python.evidence.schema import IngestionReceipt

REPO = Path(__file__).resolve().parents[1]

TENANT_A = "acme"
TENANT_B = "globex"

INSUFFICIENT_PRIVILEGE = "42501"
UNIQUE_VIOLATION = "23505"
CHECK_VIOLATION = "23514"


def run_alembic(*args: str) -> None:
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "alembic", "-c", "migrations/alembic.ini", *args],
        cwd=REPO,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"alembic {' '.join(args)} failed:\n{result.stdout}\n{result.stderr}"
        )


class RecordFactory:
    """Builds signed evidence records for one tenant's stream.

    `canonical_bytes` here is the JCS-canonical record **excluding** the
    signature field -- exactly the bytes that were signed (ES-021). The
    ledger stores them verbatim and never re-serializes: canonicalization is
    the writer's job (ES-001), and a ledger that re-derived the bytes before
    hashing would be asserting agreement with its own canonicalizer rather
    than storing what the customer's key actually covered.

    `receipt_canonical_bytes` is separately canonicalized and signed by the
    hosted issuer. It is never derived from the customer envelope.
    """

    def __init__(
        self,
        tenant_id: str,
        collector_id: str,
        key_id: str,
        private_key: Ed25519PrivateKey,
        receipt_key_id: str,
        receipt_private_key: Ed25519PrivateKey,
    ) -> None:
        self.tenant_id = tenant_id
        self.collector_id = collector_id
        self.key_id = key_id
        self.private_key = private_key
        self.receipt_key_id = receipt_key_id
        self.receipt_private_key = receipt_private_key
        self.public_key = private_key.public_key().public_bytes_raw()
        self._sequence = 0
        self._prev_digest: bytes | None = None
        self.stream_id = f"{tenant_id}:stream:1"

    def next_record(
        self,
        *,
        record_type: str = "ExecutionReceipt",
        action_family: str | None = "payment.transfer",
        action_id: uuid.UUID | None = None,
        sequence: int | None = None,
    ) -> dict[str, Any]:
        if sequence is None:
            self._sequence += 1
            sequence = self._sequence
        record_id = uuid.uuid4()
        action_id = action_id or uuid.uuid4()
        source_time = datetime(2026, 7, 31, 12, 0, 0, tzinfo=UTC) + timedelta(
            seconds=sequence
        )
        body: dict[str, Any] = {
            "action_id": str(action_id),
            "destination_system": "ledger-sandbox",
            "amount": "10.00",
            "currency": "GBP",
        }
        if action_family is not None:
            body["action_family"] = action_family
        envelope = {
            "record_id": str(record_id),
            "record_type": record_type,
            "schema_version": "0.1.0",
            "tenant_id": self.tenant_id,
            "boundary_ref": f"{self.tenant_id}:default:1",
            "stream_id": self.stream_id,
            "sequence": sequence,
            "prev_digest": (
                None if self._prev_digest is None
                else "sha256:" + self._prev_digest.hex()
            ),
            "source": {
                "collector_id": self.collector_id,
                "implementation": "sdk-python",
                "version": "0.1.0",
            },
            "clocks": {
                "source_time": source_time.isoformat().replace("+00:00", "Z"),
                "authoritative_time": None,
            },
            "body": body,
        }
        canonical = canonicalize(envelope)
        digest = hashlib.sha256(canonical).digest()
        signature = self.private_key.sign(canonical)
        received_wire = {
            **envelope,
            "signature": {
                "alg": "ed25519",
                "key_id": self.key_id,
                "sig": base64.urlsafe_b64encode(signature)
                .rstrip(b"=")
                .decode("ascii"),
                "signed_digest": "sha256:" + digest.hex(),
            },
        }
        received_wire_digest = hashlib.sha256(canonicalize(received_wire)).digest()
        ingest_time = source_time + timedelta(milliseconds=4)
        receipt = IngestionReceipt(
            record_digest="sha256:" + received_wire_digest.hex(),
            ingest_time=ingest_time.isoformat(timespec="milliseconds").replace(
                "+00:00", "Z"
            ),
            clock_skew_ms=4,
        )
        receipt_bytes = canonicalize(receipt)
        prev_digest = self._prev_digest
        self._prev_digest = digest
        return {
            "record_id": record_id,
            "tenant_id": self.tenant_id,
            "record_type": record_type,
            "schema_version": "0.1.0",
            "boundary_ref": envelope["boundary_ref"],
            "stream_id": self.stream_id,
            "sequence": sequence,
            "prev_digest": prev_digest,
            "record_digest": digest,
            "collector_id": self.collector_id,
            "key_id": self.key_id,
            "signature": signature,
            "source_time": source_time,
            "ingest_time": ingest_time,
            "authoritative_time": None,
            "clock_skew_ms": 4,
            "canonical_bytes": canonical,
            "receipt_key_id": self.receipt_key_id,
            "receipt_signature": self.receipt_private_key.sign(receipt_bytes),
            "receipt_canonical_bytes": receipt_bytes,
            "body": body,
            "action_id": action_id,
            "action_family": action_family,
        }
