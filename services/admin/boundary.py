"""Assurance boundaries: versioned, immutable, signed.

Owns `evidence-spec.md` §5.1 and ES-009, `coverage-methodology.md` CM-003, and
`threat-model.md` TM-002. Supplies -- but does not discharge -- the
interval-coverage half of AR-027; see `interval_coverage` below.

Append-only application path
----------------------------
There is no update function in this module. Migration 0012 attaches triggers
to `boundaries` that raise on `UPDATE`, `DELETE`, and `TRUNCATE` while those
triggers remain enabled. A change through the supported path is
`record_boundary` again with the next version number.

That is defense in depth, not owner-proof retention. The live migration
credential is a PostgreSQL superuser and can disable or drop a trigger before
mutating the table. TM-002 therefore remains dependent on an external,
independently controlled history; this story does not claim that a database
owner cannot erase or rewrite its own database.

`data-model.md` §2.4 lists a `superseded_by` column. It is not built, and
cannot be: writing it means updating the row being superseded, which is the
one operation an immutable table exists to refuse. Supersession is derived
from the version ordering instead -- see `boundary_versions` -- and §2.4
amendment 1 records the change.
"""

from __future__ import annotations

import hmac
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import Connection, select
from sqlalchemy.engine import RowMapping

from sdk_python.evidence.canonical import canonicalize
from sdk_python.evidence.schema import AssuranceBoundaryRecord, IngestionReceipt
from sdk_python.evidence.signing import (
    InvalidSignatureError,
    SignatureError,
    record_signature_bytes,
    verify_record_signature_bytes,
)
from services.ingestion.receipts import (
    SignedIngestionReceipt,
    parse_timestamp,
    verify_ingestion_receipt,
)

from .schema import boundaries, boundary_action_families
from .trust import registered_evidence_keyring, registered_receipt_keyring

#: Keys required on every `action_families[]` entry. `evidence-spec.md` §5.1
#: names the list and ES-009 names `qualification_ref`; the entry shape itself
#: is unspecified, so it is pinned here. `action_family` rather than `name`
#: deliberately: it is the key `QualificationRecord` already uses for the same
#: concept, and one spelling across two record types is one fewer place for a
#: boundary and its qualification to mean different things by the same word.
ACTION_FAMILY_KEYS = frozenset({"action_family", "destination_system", "qualification_ref"})

FAIL_BEHAVIOURS = frozenset({"fail_closed", "fail_open"})


class BoundaryError(ValueError):
    """Base class for malformed or unrecordable assurance boundaries."""


class UnqualifiedActionFamilyError(BoundaryError):
    """ES-009: a declared family carries no `qualification_ref`.

    "A boundary declaring a family without qualification is invalid" -- so the
    boundary is refused entirely rather than recorded with the family dropped.
    Dropping it would silently narrow the declared scope, which is the
    gerrymandering TM-002 exists to make visible.
    """


class BoundaryRefMismatchError(BoundaryError):
    """The envelope's `boundary_ref` disagrees with the signed body."""


class UnattestedRecordingTimeError(BoundaryError):
    """A boundary interval cannot be derived from an unsigned hosted time."""


@dataclass(frozen=True, slots=True)
class DeclaredFamily:
    """One `action_families[]` entry, after ES-009 validation."""

    action_family: str
    destination_system: str
    qualification_ref: str
    fail_behaviour: str


@dataclass(frozen=True, slots=True)
class BoundaryVersion:
    """One row of `boundaries`, with its declared families."""

    boundary_ref: str
    tenant_id: str
    name: str
    version: int
    window_start: datetime
    window_end: datetime
    recorded_at: datetime
    families: tuple[DeclaredFamily, ...]
    recording_time_attested: bool = True

    @property
    def declared_families(self) -> frozenset[str]:
        return frozenset(family.action_family for family in self.families)


@dataclass(frozen=True, slots=True)
class EffectiveInterval:
    """AR-027's effective interval for one boundary version.

    Begins at the later of the declared `window_start` and the hosted
    observation of when the version was recorded, so a boundary written after
    the fact cannot be backdated into force. Ends at the earlier of the
    declared `window_end` and the effective start of the next version.

    `start > end` is representable and means the version was never in force at
    all -- recorded after its own window closed, or superseded before it
    opened. That is a real state and is reported as an empty interval rather
    than normalised away, because the difference between "in force for a
    shorter period than declared" and "never in force" matters to the party
    deciding whether to rely on it.
    """

    start: datetime
    end: datetime

    @property
    def is_empty(self) -> bool:
        return self.end <= self.start

    def encloses(self, *, window_start: datetime, window_end: datetime) -> bool:
        """Whether this interval covers `[window_start, window_end]` in full."""
        if self.is_empty:
            return False
        return self.start <= window_start and window_end <= self.end


@dataclass(frozen=True, slots=True)
class IntervalCoverage:
    """The result AR-027 needs, and nothing more.

    `covered` answers the condition A-02 is subject to. `uncovered` carries
    the bounds AR-027 says must be reported when the answer is no.

    This deliberately stops short of the assertion. Emitting or withholding
    A-02 is assertion selection, which is EV-17's, as is AR-027's prohibition
    on restating A-02 more narrowly over the part that *was* covered. There is
    accordingly no field here naming the covered sub-interval: the shape a
    narrower restatement would be built from is one this type declines to
    hand over.
    """

    boundary_ref: str
    effective: EffectiveInterval | None
    window_start: datetime
    window_end: datetime
    uncovered: tuple[tuple[datetime, datetime], ...]

    @property
    def covered(self) -> bool:
        return not self.uncovered


def _require_mapping(value: object, *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise BoundaryError(f"{label} must be a JSON object")
    return value


def _require_text(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise BoundaryError(f"{label} must be a non-empty string")
    return value


def parse_boundary_ref(boundary_ref: str) -> tuple[str, str, int]:
    """Decompose `{tenant}:{name}:{version}` (`data-model.md` §2.4).

    The database enforces the same composition as a CHECK, so a ref that
    parses here and a row that exists there cannot disagree.
    """
    parts = boundary_ref.split(":")
    if len(parts) != 3:
        raise BoundaryError(
            f"boundary_ref must be '{{tenant}}:{{name}}:{{version}}', got "
            f"{boundary_ref!r}"
        )
    tenant, name, version = parts
    if not version.isdigit():
        raise BoundaryError(f"boundary_ref version must be an integer, got {version!r}")
    return tenant, name, int(version)


def declared_families(record: AssuranceBoundaryRecord) -> tuple[DeclaredFamily, ...]:
    """Validate and extract `action_families[]`. Enforces ES-009 and CM-003.

    Every failure below refuses the whole boundary. There is no partial
    acceptance: a boundary is a scope declaration, and one recorded with a
    family quietly removed declares a different scope from the one that was
    signed.
    """
    body = record.body
    entries = body.action_families
    if not entries:
        raise BoundaryError("a boundary must declare at least one action family")

    fail_behaviour = _require_mapping(
        body.fail_behaviour, label="fail_behaviour"
    )
    destination_systems = body.destination_systems
    declared_refs = set(body.qualification_refs)

    families: list[DeclaredFamily] = []
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        mapping = _require_mapping(entry, label=f"action_families[{index}]")
        missing = ACTION_FAMILY_KEYS - set(mapping)
        if "qualification_ref" in missing:
            raise UnqualifiedActionFamilyError(
                f"action_families[{index}] carries no qualification_ref; ES-009 "
                f"makes a boundary declaring an unqualified family invalid"
            )
        if missing:
            raise BoundaryError(
                f"action_families[{index}] is missing {sorted(missing)}"
            )

        family = _require_text(
            mapping["action_family"], label=f"action_families[{index}].action_family"
        )
        destination = _require_text(
            mapping["destination_system"],
            label=f"action_families[{index}].destination_system",
        )
        qualification_ref = _require_text(
            mapping["qualification_ref"],
            label=f"action_families[{index}].qualification_ref",
        )
        if family in seen:
            raise BoundaryError(f"action family {family!r} is declared twice")
        seen.add(family)

        # CM-003: the boundary declares the denominator source per family. A
        # destination absent from `destination_systems[]` would be a source
        # named in one half of the declaration and not the other.
        if destination not in destination_systems:
            raise BoundaryError(
                f"action_families[{index}] names destination system "
                f"{destination!r}, which is absent from destination_systems[]"
            )
        if qualification_ref not in declared_refs:
            raise BoundaryError(
                f"action_families[{index}] cites qualification "
                f"{qualification_ref!r}, which is absent from qualification_refs[]"
            )

        behaviour = _require_text(
            fail_behaviour.get(family), label=f"fail_behaviour[{family!r}]"
        )
        if behaviour not in FAIL_BEHAVIOURS:
            raise BoundaryError(
                f"fail_behaviour[{family!r}] must be one of "
                f"{sorted(FAIL_BEHAVIOURS)}, got {behaviour!r}"
            )
        families.append(
            DeclaredFamily(
                action_family=family,
                destination_system=destination,
                qualification_ref=qualification_ref,
                fail_behaviour=behaviour,
            )
        )

    # The reverse direction. A ref listed at the top level but attached to no
    # family is a qualification the boundary appears to rest on and does not.
    orphaned = declared_refs - {family.qualification_ref for family in families}
    if orphaned:
        raise BoundaryError(
            f"qualification_refs[] lists {sorted(orphaned)}, which no declared "
            f"action family cites"
        )
    return tuple(families)


def record_boundary(
    connection: Connection,
    *,
    record: AssuranceBoundaryRecord,
    canonical_bytes: bytes,
    signature: bytes,
    receipt: SignedIngestionReceipt,
) -> str:
    """Store a signed `AssuranceBoundary` version. Returns its `boundary_ref`.

    `recorded_at` is derived only from the verified issuer receipt. AR-027
    floors the effective interval at it precisely so that a boundary recorded
    late cannot claim to have been in force early; accepting a caller-supplied
    timestamp would defeat that rule.

    There is no `update_boundary`. A change is a new version.
    """
    public_keys = registered_evidence_keyring(
        connection, tenant_id=record.tenant_id, signature=record.signature
    )
    verify_record_signature_bytes(
        record, signing_bytes=canonical_bytes, public_keys=public_keys
    )
    embedded_signature = record_signature_bytes(record)
    if not hmac.compare_digest(signature, embedded_signature):
        raise InvalidSignatureError(
            "detached signature does not match the supplied record"
        )
    receipt_payload = verify_ingestion_receipt(
        receipt,
        record=record,
        verification_keys=registered_receipt_keyring(
            connection,
            tenant_id=record.tenant_id,
            key_id=receipt.key_id,
        ),
    )
    families = declared_families(record)

    tenant, name, version = parse_boundary_ref(record.boundary_ref)
    if tenant != record.tenant_id:
        raise BoundaryRefMismatchError(
            f"boundary_ref names tenant {tenant!r} but the envelope declares "
            f"{record.tenant_id!r}"
        )
    if record.body.tenant != record.tenant_id:
        raise BoundaryRefMismatchError(
            f"body.tenant is {record.body.tenant!r} but the envelope "
            f"declares {record.tenant_id!r}"
        )
    if record.body.boundary_version != str(version):
        raise BoundaryRefMismatchError(
            f"body.boundary_version is "
            f"{record.body.boundary_version!r} but boundary_ref "
            f"names version {version}"
        )

    window_start = _parse_timestamp(record.body.window_start)
    window_end = _parse_timestamp(record.body.window_end)

    connection.execute(
        boundaries.insert(),
        {
            "boundary_ref": record.boundary_ref,
            "tenant_id": record.tenant_id,
            "name": name,
            "version": version,
            "canonical_bytes": canonical_bytes,
            "body": json.loads(
                json.dumps(record.body.model_dump(mode="json", exclude_unset=True))
            ),
            "key_id": str(record.signature["key_id"]),
            "key_namespace": "evidence",
            "signature": signature,
            "window_start": window_start,
            "window_end": window_end,
            "recorded_at": parse_timestamp(receipt_payload.ingest_time),
            "receipt_key_id": receipt.key_id,
            "receipt_key_namespace": "issuer",
            "receipt_signature": receipt.signature,
            "receipt_canonical_bytes": receipt.canonical_bytes,
            "received_wire_bytes": canonicalize(record),
        },
    )
    # One statement per family, in the same transaction. The composite foreign
    # key means an unqualified or mis-qualified family aborts the boundary
    # insert too, so a boundary and its family rows are never half-recorded.
    connection.execute(
        boundary_action_families.insert(),
        [
            {
                "tenant_id": record.tenant_id,
                "boundary_ref": record.boundary_ref,
                "action_family": family.action_family,
                "qualification_ref": family.qualification_ref,
                "destination_system": family.destination_system,
                "fail_behaviour": family.fail_behaviour,
            }
            for family in families
        ],
    )
    return record.boundary_ref


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _recording_time_is_attested(
    connection: Connection, row: RowMapping
) -> bool:
    """Re-verify the stored ES-032 receipt before AR-027 uses its time."""

    required = (
        "receipt_key_id",
        "receipt_key_namespace",
        "receipt_signature",
        "receipt_canonical_bytes",
        "received_wire_bytes",
    )
    if any(row[field] is None for field in required):
        return False
    try:
        received_wire = bytes(row["received_wire_bytes"])
        record = AssuranceBoundaryRecord.model_validate_json(received_wire)
        receipt_bytes = bytes(row["receipt_canonical_bytes"])
        receipt = SignedIngestionReceipt(
            payload=IngestionReceipt.model_validate_json(receipt_bytes),
            canonical_bytes=receipt_bytes,
            key_id=str(row["receipt_key_id"]),
            signature=bytes(row["receipt_signature"]),
        )
        payload = verify_ingestion_receipt(
            receipt,
            record=record,
            verification_keys=registered_receipt_keyring(
                connection,
                tenant_id=str(row["tenant_id"]),
                key_id=receipt.key_id,
            ),
            received_wire_bytes=received_wire,
        )
    except (TypeError, ValueError, SignatureError):
        return False
    recorded_at = row["recorded_at"]
    return isinstance(recorded_at, datetime) and (
        parse_timestamp(payload.ingest_time) == recorded_at
    )


def boundary_versions(
    connection: Connection, *, tenant_id: str, name: str
) -> tuple[BoundaryVersion, ...]:
    """Every version of one boundary, ascending.

    The ordering is the supersession history: version *n* is superseded by
    *n+1* if the tuple has one. TM-002 requires that history be visible, and a
    list of immutable rows is a stronger form of visible than a mutable
    pointer would be -- there is no state in which the pointer is stale.
    """
    rows = connection.execute(
        select(boundaries)
        .where(boundaries.c.tenant_id == tenant_id, boundaries.c.name == name)
        .order_by(boundaries.c.version)
    ).mappings().all()
    if not rows:
        return ()

    family_rows = connection.execute(
        select(boundary_action_families).where(
            boundary_action_families.c.tenant_id == tenant_id,
            boundary_action_families.c.boundary_ref.in_(
                [row["boundary_ref"] for row in rows]
            ),
        )
    ).mappings()
    by_ref: dict[str, list[DeclaredFamily]] = {}
    for row in family_rows:
        by_ref.setdefault(row["boundary_ref"], []).append(
            DeclaredFamily(
                action_family=row["action_family"],
                destination_system=row["destination_system"],
                qualification_ref=row["qualification_ref"],
                fail_behaviour=row["fail_behaviour"],
            )
        )

    return tuple(
        BoundaryVersion(
            boundary_ref=row["boundary_ref"],
            tenant_id=row["tenant_id"],
            name=row["name"],
            version=row["version"],
            window_start=row["window_start"],
            window_end=row["window_end"],
            recorded_at=row["recorded_at"],
            families=tuple(
                sorted(
                    by_ref.get(row["boundary_ref"], []),
                    key=lambda family: family.action_family,
                )
            ),
            recording_time_attested=_recording_time_is_attested(connection, row),
        )
        for row in rows
    )


def effective_interval(
    version: BoundaryVersion, *, successor: BoundaryVersion | None = None
) -> EffectiveInterval:
    """AR-027's effective interval for one version.

    Pure, so the rule can be exercised without a database and reproduced by
    the verifier from the same inputs.
    """
    if not version.recording_time_attested:
        raise UnattestedRecordingTimeError(
            f"{version.boundary_ref!r} has no issuer-attested recording time"
        )
    if successor is not None and not successor.recording_time_attested:
        raise UnattestedRecordingTimeError(
            f"successor {successor.boundary_ref!r} has no issuer-attested recording time"
        )
    start = max(version.window_start, version.recorded_at)
    end = version.window_end
    if successor is not None:
        successor_start = max(successor.window_start, successor.recorded_at)
        end = min(end, successor_start)
    return EffectiveInterval(start=start, end=end)


def interval_coverage(
    versions: Sequence[BoundaryVersion],
    *,
    boundary_ref: str,
    window_start: datetime,
    window_end: datetime,
) -> IntervalCoverage:
    """Whether one boundary version was in force for the whole window (AR-027).

    `versions` is the full history from `boundary_versions`; the successor is
    located within it, because the version's interval end depends on when the
    next version took effect.

    **This is the check, not the assertion.** AR-027 is a condition on
    issuance, and issuance is EV-17's. What this returns is the fact EV-17
    needs -- whether the referenced version enclosed the window, and if not,
    the bounds of what it did not enclose. Deciding to withhold A-02, and
    refusing to emit a narrower restatement in its place, are decisions about
    the assertion catalogue and are made where assertions are selected.

    Note also that a *later* version does not extend the referenced version's
    interval, and this function offers no way to ask whether the union of
    versions covered the window. AR-027 forbids that reading explicitly: the
    attestation must reference one version that was in force throughout.
    """
    ordered = sorted(versions, key=lambda item: item.version)
    index = next(
        (i for i, item in enumerate(ordered) if item.boundary_ref == boundary_ref), None
    )
    if index is None:
        raise BoundaryError(
            f"{boundary_ref!r} is not among the supplied versions "
            f"{[item.boundary_ref for item in ordered]}"
        )
    successor = ordered[index + 1] if index + 1 < len(ordered) else None
    try:
        effective = effective_interval(ordered[index], successor=successor)
    except UnattestedRecordingTimeError:
        # ES-032: a stored hosted timestamp has no standing without the
        # issuer receipt that authenticates it.  Return an explicitly
        # unresolved interval and withhold the whole requested window rather
        # than feeding the unattested value into AR-027 arithmetic.
        return IntervalCoverage(
            boundary_ref=boundary_ref,
            effective=None,
            window_start=window_start,
            window_end=window_end,
            uncovered=((window_start, window_end),),
        )

    uncovered: list[tuple[datetime, datetime]] = []
    if effective.is_empty:
        # Never in force. The whole window is uncovered, reported as one
        # interval rather than as two around an empty middle.
        uncovered.append((window_start, window_end))
    else:
        if window_start < effective.start:
            uncovered.append((window_start, min(effective.start, window_end)))
        if window_end > effective.end:
            uncovered.append((max(effective.end, window_start), window_end))

    return IntervalCoverage(
        boundary_ref=boundary_ref,
        effective=effective,
        window_start=window_start,
        window_end=window_end,
        uncovered=tuple(uncovered),
    )


__all__ = [
    "ACTION_FAMILY_KEYS",
    "FAIL_BEHAVIOURS",
    "BoundaryError",
    "BoundaryRefMismatchError",
    "BoundaryVersion",
    "DeclaredFamily",
    "EffectiveInterval",
    "IntervalCoverage",
    "UnqualifiedActionFamilyError",
    "UnattestedRecordingTimeError",
    "boundary_versions",
    "declared_families",
    "effective_interval",
    "interval_coverage",
    "parse_boundary_ref",
    "record_boundary",
]
