"""Builders for signed boundary and qualification records (EV-12).

Kept beside `ledger_support.py` and separate from it: that module builds
evidence records for the ingestion path, this one builds the two
administrative record types, and the credentials and tables involved differ.

Every record here is genuinely signed with a real Ed25519 key, because
`record_boundary` and `record_qualification` verify before writing and a
fixture carrying a fake signature would only prove the verification was
skipped.

A note on `boundary_ref` in these envelopes
-------------------------------------------
`evidence-spec.md` §3 makes `boundary_ref` a required envelope field on every
record type, including these two. That is circular for both:

* an `AssuranceBoundary` cannot fall under a boundary version other than
  itself, so its `boundary_ref` is its own -- which `record_boundary` relies
  on and cross-checks against the signed body; and
* a `QualificationRecord` must exist *before* the boundary that cites it, so
  whatever it names cannot yet be recorded.

Neither table carries a foreign key on that field, so nothing here depends on
resolving it. The tension is real and is reported rather than papered over --
see the story's disclosure notes.
"""

from __future__ import annotations

import base64
import os
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sdk_python.evidence.canonical import canonicalize
from sdk_python.evidence.schema import AssuranceBoundaryRecord, QualificationRecord
from sdk_python.evidence.signing import record_signing_bytes, sign_record
from services.ingestion.receipts import SignedIngestionReceipt, create_ingestion_receipt

SCHEMA_VERSION = "0.1.0"


def uuid7() -> str:
    """A version-7 UUID. `uuid.uuid7` does not exist before Python 3.14."""
    unix_ms = int(time.time() * 1000)
    rand = os.urandom(10)
    value = (
        unix_ms.to_bytes(6, "big")
        + bytes([(0x70 | (rand[0] & 0x0F)), rand[1]])
        + bytes([(0x80 | (rand[2] & 0x3F))])
        + rand[3:10]
    )
    return str(uuid.UUID(bytes=value))


def rfc3339(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _envelope(
    *,
    record_type: str,
    tenant_id: str,
    boundary_ref: str,
    collector_id: str,
    source_time: datetime,
    body: dict[str, Any],
    sequence: int = 1,
) -> dict[str, Any]:
    return {
        "record_id": uuid7(),
        "record_type": record_type,
        "schema_version": SCHEMA_VERSION,
        "tenant_id": tenant_id,
        "boundary_ref": boundary_ref,
        "stream_id": f"{tenant_id}:admin:1",
        "sequence": sequence,
        "prev_digest": None,
        "source": {
            "collector_id": collector_id,
            "implementation": "admin-console",
            "version": "0.1.0",
        },
        # `authoritative_time` is optional *by presence*: omitted, not null,
        # so one record has one canonical form. These records relay no
        # destination timestamp, so it is absent.
        "clocks": {"source_time": rfc3339(source_time)},
        "body": body,
        "signature": {},
    }


def qualification_body(
    *,
    action_family: str,
    destination_system: str,
    assigned_class: str,
    qualified_at: datetime,
    enumeration_capable: bool = True,
    confirmation_capable: bool = True,
    identity_isolation_attribute: str | None = "service_principal_id",
    identity_vendor_settable: bool = False,
    authoritative_timestamp_source: str | None = "destination.created_at",
    settlement_lag_s: int = 300,
    retention_period: str = "P400D",
    deletion_possible: bool = False,
    trace_available: bool = True,
    revalidation_cadence: str = "P180D",
) -> dict[str, Any]:
    """A `QualificationRecord` body per `evidence-spec.md` §5.2.

    Defaults describe a well-isolated, enumerable, confirmable source -- the
    C1 case. Tests weaken one attribute at a time so that what a scenario
    exercises is visible in its own call rather than buried in the fixture.
    """
    return {
        "action_family": action_family,
        "destination_system": destination_system,
        "enumeration": {
            "capable": enumeration_capable,
            "api": "GET /v1/refunds",
            "scoping_params": ["account_id", "created_after", "created_before"],
            "ordering_guarantee": "created_at asc, id asc",
            "pagination": "cursor",
            "result_cap": 10000,
        },
        "identity_isolation": {
            "attribute": identity_isolation_attribute,
            "vendor_settable": identity_vendor_settable,
            "partial_notes": None,
        },
        "confirmation": {
            "capable": confirmation_capable,
            "api": "GET /v1/refunds/{id}",
            "permission_set": ["refunds:read"],
            "independent_of_enumeration": True,
        },
        "temporal": {
            "authoritative_timestamp_source": authoritative_timestamp_source,
            "measured_settlement_lag_s": settlement_lag_s,
        },
        "retention_period": retention_period,
        "mutability": {
            "deletion_possible": deletion_possible,
            "backdating_possible": False,
            "trace_available": trace_available,
        },
        "assigned_class": assigned_class,
        "class_evidence": "one week of production reconciliation, 100% matched",
        "trial": {
            "window": "2026-06-01/2026-06-08",
            "match_rate": "1.0",
            "unmatched_explanations": [],
        },
        "qualified_at": rfc3339(qualified_at),
        "revalidation_cadence": revalidation_cadence,
    }


def boundary_body(
    *,
    tenant_id: str,
    version: int,
    window_start: datetime,
    window_end: datetime,
    families: list[dict[str, str]],
    deployment: str = "production",
) -> dict[str, Any]:
    """An `AssuranceBoundary` body per `evidence-spec.md` §5.1.

    `families` entries are `{action_family, destination_system,
    qualification_ref}`; the top-level `destination_systems[]`,
    `qualification_refs[]` and `fail_behaviour` mappings are derived from them
    so a fixture cannot accidentally desynchronise the two halves of the
    declaration that `declared_families` checks agree.
    """
    return {
        "boundary_version": str(version),
        "tenant": tenant_id,
        "deployment": deployment,
        "agent_identities": [{"agent_id": f"{tenant_id}-agent-1"}],
        "action_families": list(families),
        "destination_systems": sorted(
            {family["destination_system"] for family in families}
        ),
        "enforcement_points": [],
        "policy_refs": ["policy:v1"],
        "window_start": rfc3339(window_start),
        "window_end": rfc3339(window_end),
        "collection_modes": ["checkpoint"],
        "fail_behaviour": {
            family["action_family"]: "fail_closed" for family in families
        },
        "qualification_refs": sorted(
            {family["qualification_ref"] for family in families}
        ),
    }


def signed_qualification(
    *,
    tenant_id: str,
    collector_id: str,
    key_id: str,
    private_key: Ed25519PrivateKey,
    boundary_ref: str,
    body: dict[str, Any],
    source_time: datetime | None = None,
) -> tuple[QualificationRecord, bytes, bytes]:
    """Return the record, the bytes its key covered, and the raw signature."""
    envelope = _envelope(
        record_type="QualificationRecord",
        tenant_id=tenant_id,
        boundary_ref=boundary_ref,
        collector_id=collector_id,
        source_time=source_time or datetime.now(tz=UTC),
        body=body,
    )
    return _sign(QualificationRecord, envelope, key_id=key_id, private_key=private_key)


def signed_boundary(
    *,
    tenant_id: str,
    collector_id: str,
    key_id: str,
    private_key: Ed25519PrivateKey,
    name: str,
    version: int,
    body: dict[str, Any],
    source_time: datetime | None = None,
) -> tuple[AssuranceBoundaryRecord, bytes, bytes]:
    envelope = _envelope(
        record_type="AssuranceBoundary",
        tenant_id=tenant_id,
        boundary_ref=f"{tenant_id}:{name}:{version}",
        collector_id=collector_id,
        source_time=source_time or datetime.now(tz=UTC),
        body=body,
    )
    return _sign(
        AssuranceBoundaryRecord, envelope, key_id=key_id, private_key=private_key
    )


def _sign(
    model: type[Any],
    envelope: dict[str, Any],
    *,
    key_id: str,
    private_key: Ed25519PrivateKey,
) -> tuple[Any, bytes, bytes]:
    unsigned = model.model_validate({**envelope, "signature": {}})
    signed = sign_record(unsigned, key_id=key_id, private_key=private_key)
    canonical = record_signing_bytes(signed)
    # The raw 64-byte proof stored in the tables' `signature` column, decoded
    # from the record rather than produced by signing a second time: a
    # re-signing helper that drifted from `sign_record` would give the column
    # and the record different proofs while every test still passed.
    encoded = str(signed.signature["sig"])
    signature = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    return signed, canonical, signature


def canonical_body_bytes(body: dict[str, Any]) -> bytes:
    return canonicalize(body)


def constitutive_receipt(
    record: AssuranceBoundaryRecord | QualificationRecord,
    *,
    issuer_key_id: str,
    issuer_private_key: Ed25519PrivateKey,
    recorded_at: datetime,
) -> SignedIngestionReceipt:
    """Create the real ES-032 issuer receipt used by administrative writes."""

    return create_ingestion_receipt(
        record,
        ingest_time=recorded_at,
        issuer_key_id=issuer_key_id,
        issuer_private_key=issuer_private_key,
    )


@dataclass(frozen=True)
class AdminActor:
    """One tenant's administrative signing identity, plus write helpers.

    Wraps the two `services.admin` entry points so a test states the fact it
    is exercising -- this class, this date, this family -- without restating
    the record-construction boilerplate each time. The helpers call the real
    functions, so a test that writes through them is exercising signature
    verification and ES-009 validation too.
    """

    tenant_id: str
    collector_id: str
    key_id: str
    private_key: Ed25519PrivateKey
    issuer_key_id: str
    issuer_private_key: Ed25519PrivateKey

    @property
    def public_keys(self) -> dict[str, Any]:
        return {self.key_id: self.private_key.public_key()}

    def write_qualification(
        self,
        connection: Any,
        *,
        action_family: str,
        destination_system: str,
        assigned_class: str,
        qualified_at: datetime,
        recorded_at: datetime | None = None,
        **body_kwargs: Any,
    ) -> str:
        from services.admin import record_qualification

        observed_at = recorded_at or datetime.now(tz=UTC)
        record, canonical, signature = signed_qualification(
            tenant_id=self.tenant_id,
            collector_id=self.collector_id,
            key_id=self.key_id,
            private_key=self.private_key,
            boundary_ref=f"{self.tenant_id}:default:1",
            body=qualification_body(
                action_family=action_family,
                destination_system=destination_system,
                assigned_class=assigned_class,
                qualified_at=qualified_at,
                **body_kwargs,
            ),
            source_time=observed_at,
        )
        return record_qualification(
            connection,
            record=record,
            canonical_bytes=canonical,
            signature=signature,
            receipt=constitutive_receipt(
                record,
                issuer_key_id=self.issuer_key_id,
                issuer_private_key=self.issuer_private_key,
                recorded_at=observed_at,
            ),
        )

    def write_boundary(
        self,
        connection: Any,
        *,
        name: str,
        version: int,
        window_start: datetime,
        window_end: datetime,
        families: list[dict[str, str]],
        recorded_at: datetime,
    ) -> str:
        from services.admin import record_boundary

        record, canonical, signature = signed_boundary(
            tenant_id=self.tenant_id,
            collector_id=self.collector_id,
            key_id=self.key_id,
            private_key=self.private_key,
            name=name,
            version=version,
            body=boundary_body(
                tenant_id=self.tenant_id,
                version=version,
                window_start=window_start,
                window_end=window_end,
                families=families,
            ),
            source_time=recorded_at,
        )
        return record_boundary(
            connection,
            record=record,
            canonical_bytes=canonical,
            signature=signature,
            receipt=constitutive_receipt(
                record,
                issuer_key_id=self.issuer_key_id,
                issuer_private_key=self.issuer_private_key,
                recorded_at=recorded_at,
            ),
        )


__all__ = [
    "SCHEMA_VERSION",
    "AdminActor",
    "boundary_body",
    "canonical_body_bytes",
    "constitutive_receipt",
    "qualification_body",
    "rfc3339",
    "signed_boundary",
    "signed_qualification",
    "uuid7",
]
