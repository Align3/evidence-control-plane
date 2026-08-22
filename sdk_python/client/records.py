"""Envelope construction and local signing.

Canonicalisation and Ed25519 come from `sdk_python.evidence`; this module only
assembles the ES-005 envelope around a caller-supplied body and hands it to
those. If anything here starts sorting keys or touching signature bytes, it is
duplicating EV-02/EV-03 and belongs there instead.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from sdk_python.client.buffer import BufferedRecord
from sdk_python.client.identity import SigningIdentity, SigningUnavailableError
from sdk_python.evidence.canonical import canonical_digest
from sdk_python.evidence.schema import serialize_record, validate_record
from sdk_python.evidence.signing import sign_record
from sdk_python.evidence.versions import require_published_schema_version

#: ES-035's published set is the only thing a conformant verifier will accept,
#: so it is read from the registry rather than restated here. Emitting under an
#: unpublished version produces records that are individually well-formed,
#: correctly signed, and refused by every verifier -- a failure that surfaces
#: only once someone tries to rely on them.
SCHEMA_VERSION = require_published_schema_version("1.0.0")
#: EV-07 checks this against the collector's registration row, so it names the
#: SDK as the rest of the repository already registers it. A separate identifier
#: for the client package would make every record this SDK emits fail collector
#: authentication against a collector registered by any other part of the system.
SDK_NAME = "sdk-python"
SDK_VERSION = "0.1.0"


def new_record_id(at: datetime) -> str:
    """UUIDv7 for a record created at `at`.

    Near-duplicate of `services.computation.population._uuid7`; both exist
    because `uuid.uuid7` postdates this runtime. Worth consolidating into
    `sdk_python.evidence` rather than growing a third copy.
    """

    unix_ms = int(at.timestamp() * 1_000)
    if not 0 <= unix_ms < 1 << 48:  # pragma: no cover - datetime's practical range
        raise ValueError("UUIDv7 timestamp is outside the 48-bit millisecond range")
    random = os.urandom(10)
    value = (
        unix_ms.to_bytes(6, "big")
        + bytes([0x70 | (random[0] & 0x0F), random[1]])
        + bytes([0x80 | (random[2] & 0x3F)])
        + random[3:10]
    )
    return str(uuid.UUID(bytes=value))


def rfc3339(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("SDK timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def build_envelope(
    *,
    record_type: str,
    body: Mapping[str, Any],
    tenant_id: str,
    boundary_ref: str,
    collector_id: str,
    deployment: str,
    stream_id: str,
    sequence: int,
    prev_digest: str | None,
    source_time: datetime,
    record_id: str | None = None,
) -> dict[str, Any]:
    return {
        "record_id": record_id or new_record_id(source_time),
        "record_type": record_type,
        "schema_version": SCHEMA_VERSION,
        "tenant_id": tenant_id,
        "boundary_ref": boundary_ref,
        "stream_id": stream_id,
        "sequence": sequence,
        "prev_digest": prev_digest,
        # `collector_id`, not `collector`: EV-07 authenticates the collector from
        # this member (`services/ingestion/service.py`), and a record naming it
        # anything else is refused at ingestion with a 401 no matter how well it
        # is signed. Some EV-02 schema fixtures still say `collector` because the
        # schema layer never reads it; the wire contract is what binds here.
        "source": {
            "collector_id": collector_id,
            "implementation": SDK_NAME,
            "version": SDK_VERSION,
            "deployment": deployment,
        },
        "clocks": {"source_time": rfc3339(source_time)},
        "body": dict(body),
        "signature": {},
    }


def sign_locally(
    envelope: Mapping[str, Any], identity: SigningIdentity
) -> tuple[BufferedRecord, str]:
    """Validate, sign, and serialize. Returns the buffered record and its digest.

    The returned digest is the ES-006a complete-record value, which is what the
    *next* record in this stream must carry as `prev_digest`. Returning it here
    keeps the chain arithmetic in one place instead of at every call site.
    """

    record = validate_record(envelope)
    try:
        signed = sign_record(
            record, key_id=identity.key_id, private_key=identity.private_key
        )
    except SigningUnavailableError:
        raise
    except Exception as exc:  # noqa: BLE001 - normalised; cause dropped deliberately
        # `from None`: a chained cause would put the private key into the
        # traceback's frame locals. See `identity.SigningUnavailableError`.
        raise SigningUnavailableError(
            f"local signing failed for {envelope.get('record_type')!r} "
            f"with key_id {identity.key_id!r}: {type(exc).__name__}"
        ) from None

    buffered = BufferedRecord(
        record_id=signed.record_id,
        record_type=signed.record_type,
        stream_id=signed.stream_id,
        sequence=signed.sequence,
        signed_at=signed.clocks.source_time,
        canonical_bytes=serialize_record(signed),
    )
    return buffered, canonical_digest(signed)
