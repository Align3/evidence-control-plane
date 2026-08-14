"""Qualification records and the class in force for a window.

Owns `evidence-spec.md` ES-010, `coverage-methodology.md` CM-003/CM-004, and
`threat-model.md` TM-013 -- one rule stated four times:

    A denominator class may be downgraded mid-window. It may never be
    upgraded retroactively. A stronger class requires a new
    `QualificationRecord` with a later `qualified_at`, and applies only to
    windows **beginning after** that date.

Three guards, deliberately
--------------------------
The rule is enforced in three independent places, and none of them is
sufficient alone:

1. **At write time, by the database.** Migration 0012 attaches a `BEFORE
   INSERT` trigger refusing a stronger record backdated behind an existing
   weaker one. This is defense in depth for ordinary DML, not an owner-proof
   control: PostgreSQL superusers and relation owners can disable triggers.
2. **At read time, here.** `class_in_force` resolves the governing class from
   the history for a given window, and `assert_class_claimable` refuses a
   claim the history does not support.
3. **At verification time, by the Go verifier** (TM-013, TM-S-005). Not built
   by this story -- `verifier-go/` is EV-05's and EV-19's. See
   `QUALIFICATION_POSTDATES_WINDOW` below for the contract this story fixes
   for it.

Three guards because a single one is a single place to get it wrong, and
because a relying party has no reason to trust guards 1 and 2 -- both run on
our infrastructure, under our credentials. Only guard 3 is reproducible by
someone who does not trust us, which is why TM-013 says "verifier enforces
this independently" and why the verifier's failure is the one the acceptance
scenario asserts.

What is not here
----------------
Applying the class to a coverage computation. `admissible_level` and
`emits_ratio` below are the static `coverage-methodology.md` §6 lattice --
the class-admissible half of CM-008's `min(evidence-supported,
class-admissible)`. Taking that minimum, and everything about the numerator,
belongs to the coverage engine (EV-16), which should consume these rather
than restate the table.
"""

from __future__ import annotations

import hmac
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from sqlalchemy import Connection, select

from sdk_python.evidence.canonical import canonicalize
from sdk_python.evidence.schema import QualificationRecord
from sdk_python.evidence.signing import (
    InvalidSignatureError,
    record_signature_bytes,
    verify_record_signature_bytes,
)
from services.ingestion.receipts import (
    SignedIngestionReceipt,
    parse_timestamp,
    verify_ingestion_receipt,
)

from .schema import qualification_records
from .trust import registered_evidence_keyring, registered_receipt_keyring

#: The verifier failure string TM-S-005 asserts. Fixed here as a constant so
#: the Python resolver, the conformance fixtures this story emits, and EV-19's
#: Go implementation are quoting one source rather than three spellings that
#: happen to agree today.
QUALIFICATION_POSTDATES_WINDOW = "qualification postdates window"


class QualificationError(ValueError):
    """Base class for qualification-record and class-resolution failures."""


class QualificationPostdatesWindowError(QualificationError):
    """A class is claimed whose only support was qualified during or after the window.

    TM-013 / CM-004: the qualification date must precede the window's start.
    """


class ClassNotQualifiedError(QualificationError):
    """A class is claimed that no record in the history assigns."""


class UnqualifiedWindowError(QualificationError):
    """No qualification record was in force when the window began.

    CM-003: an attestation cannot be issued for a family whose denominator
    class is undeclared. An absent record is that case, not a default.
    """


class CoverageLevel(StrEnum):
    """`coverage-methodology.md` §5, ordered weakest-first by declaration."""

    OBSERVED = "observed"
    INTERCEPTED = "intercepted"
    ENFORCED = "enforced"
    RECONCILED = "reconciled"


class DenominatorClass(StrEnum):
    """`coverage-methodology.md` §3, declared strongest-first.

    The declaration order matches the `denominator_class` Postgres enum, so
    the ordering used by the write-time trigger and the ordering used here are
    the same ordering rather than two that agree by inspection.
    """

    C1 = "c1"
    C2 = "c2"
    C3 = "c3"
    C4 = "c4"
    C5 = "c5"

    @property
    def rank(self) -> int:
        """Position in the strength order; lower is stronger."""
        return _CLASS_ORDER.index(self)

    def is_stronger_than(self, other: DenominatorClass) -> bool:
        return self.rank < other.rank

    @property
    def admissible_level(self) -> CoverageLevel:
        """Highest coverage level this class admits (`coverage-methodology.md` §6).

        The class-admissible half of CM-008. The evidence-supported half, and
        the minimum of the two, are the coverage engine's (EV-16).
        """
        return _ADMISSIBLE_LEVEL[self]

    @property
    def emits_ratio(self) -> bool:
        """CM-009: a ratio at C1, C2, C3 only.

        At C4 and C5 `coverage_ratio` is explicitly null (ES-017) -- not zero,
        not omitted. This property says whether the number may exist at all;
        rendering the null is EV-16's and EV-17's.
        """
        return self in _RATIO_CLASSES


_CLASS_ORDER: tuple[DenominatorClass, ...] = (
    DenominatorClass.C1,
    DenominatorClass.C2,
    DenominatorClass.C3,
    DenominatorClass.C4,
    DenominatorClass.C5,
)

_ADMISSIBLE_LEVEL: Mapping[DenominatorClass, CoverageLevel] = {
    DenominatorClass.C1: CoverageLevel.RECONCILED,
    DenominatorClass.C2: CoverageLevel.RECONCILED,
    DenominatorClass.C3: CoverageLevel.ENFORCED,
    DenominatorClass.C4: CoverageLevel.OBSERVED,
    DenominatorClass.C5: CoverageLevel.OBSERVED,
}

_RATIO_CLASSES = frozenset(
    {DenominatorClass.C1, DenominatorClass.C2, DenominatorClass.C3}
)


def weakest(classes: Iterable[DenominatorClass]) -> DenominatorClass:
    """The weakest of `classes`. Raises on an empty iterable."""
    ordered = sorted(classes, key=lambda item: item.rank)
    if not ordered:
        raise ValueError("no denominator classes to compare")
    return ordered[-1]


@dataclass(frozen=True, slots=True)
class Qualification:
    """One row of `qualification_records`, projected.

    `enumeration_capable` and `confirmation_capable` are separate fields and
    neither implies the other (AC-008, CM-010). A record carrying confirmation
    without enumeration is valid and useful -- it supports per-action
    reconciliation -- and it supports no window-level coverage claim. The
    second half of that is not enforced by this dataclass: it is a property of
    the class the record may hold, which migration 0012 constrains
    (`ck_qualification_records_ratio_class_enumerates`) and which the coverage
    engine enforces again at window level.
    """

    qualification_ref: str
    tenant_id: str
    action_family: str
    destination_system: str
    assigned_class: DenominatorClass
    enumeration_capable: bool
    confirmation_capable: bool
    identity_isolation_attribute: str | None
    identity_vendor_settable: bool
    authoritative_time_available: bool
    settlement_lag_s: int
    source_retention_days: int
    deletion_traceless_possible: bool
    qualified_at: datetime
    recorded_at: datetime
    revalidate_after: datetime

    @property
    def supports_window_coverage_claim(self) -> bool:
        """AC-008, stated positively at record level.

        Confirmation alone never reaches a ratio-emitting class, so a
        confirmation-only record answers `False` here however capable its
        confirmation API is.
        """
        return self.enumeration_capable and self.assigned_class.emits_ratio


def _require_object(value: object, *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise QualificationError(f"{label} must be a JSON object")
    return value


def _require_bool(value: object, *, label: str) -> bool:
    if not isinstance(value, bool):
        raise QualificationError(f"{label} must be a boolean")
    return value


def _require_int(value: object, *, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise QualificationError(f"{label} must be an integer")
    return value


def _optional_text(value: object, *, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise QualificationError(f"{label} must be a non-empty string or null")
    return value


def projection(record: QualificationRecord) -> dict[str, Any]:
    """Derive the indexed columns from the signed body (DM-005).

    Every value here is read out of the body that was signed. Nothing is
    supplied by the caller alongside it, so a projection column cannot say
    something the signature does not cover.
    """
    body = record.body
    enumeration = _require_object(body.enumeration, label="enumeration")
    confirmation = _require_object(body.confirmation, label="confirmation")
    isolation = _require_object(
        body.identity_isolation, label="identity_isolation"
    )
    temporal = _require_object(body.temporal, label="temporal")
    mutability = _require_object(body.mutability, label="mutability")

    return {
        "action_family": body.action_family,
        "destination_system": body.destination_system,
        "assigned_class": DenominatorClass(str(body.assigned_class).lower()),
        "enumeration_capable": _require_bool(
            enumeration.get("capable"), label="enumeration.capable"
        ),
        "confirmation_capable": _require_bool(
            confirmation.get("capable"), label="confirmation.capable"
        ),
        "identity_isolation_attribute": _optional_text(
            isolation.get("attribute"), label="identity_isolation.attribute"
        ),
        "identity_vendor_settable": _require_bool(
            isolation.get("vendor_settable"), label="identity_isolation.vendor_settable"
        ),
        # CM §7 step 4. Absent means the destination provides no authoritative
        # timestamp, which ES-020 then makes govern nothing.
        "authoritative_time_available": _optional_text(
            temporal.get("authoritative_timestamp_source"),
            label="temporal.authoritative_timestamp_source",
        )
        is not None,
        "settlement_lag_s": _require_int(
            temporal.get("measured_settlement_lag_s"),
            label="temporal.measured_settlement_lag_s",
        ),
        "source_retention_days": _day_duration(
            body.retention_period, label="retention_period"
        ),
        # TM-005 asks whether an administrator can delete a record without
        # trace. Deletion that leaves a trace is a different, weaker fact, so
        # both halves are read and combined rather than either alone.
        "deletion_traceless_possible": _require_bool(
            mutability.get("deletion_possible"), label="mutability.deletion_possible"
        )
        and not _require_bool(
            mutability.get("trace_available"), label="mutability.trace_available"
        ),
    }


def _day_duration(value: object, *, label: str) -> int:
    """Parse an ISO-8601 whole-day duration (`P90D`) as a day count.

    Deliberately narrow. A general duration parser would silently accept
    `P1Y`, whose day count depends on which year, and the retention question
    CM §7 step 5 asks -- "is the source retained at least as long as
    attestation validity?" -- is a comparison that must not rest on a guess.
    """
    if not isinstance(value, str) or not value.startswith("P") or not value.endswith("D"):
        raise QualificationError(
            f"{label} must be an ISO-8601 day duration such as 'P90D', got {value!r}"
        )
    try:
        days = int(value[1:-1])
    except ValueError as exc:
        raise QualificationError(
            f"{label} must be an ISO-8601 day duration such as 'P90D', got {value!r}"
        ) from exc
    if days <= 0:
        raise QualificationError(f"{label} must be a positive number of days")
    return days


def record_qualification(
    connection: Connection,
    *,
    record: QualificationRecord,
    canonical_bytes: bytes,
    signature: bytes,
    receipt: SignedIngestionReceipt,
) -> str:
    """Store a signed `QualificationRecord`. Returns its `qualification_ref`.

    The signature is verified against `canonical_bytes` -- the exact bytes the
    customer key covered -- before anything is written. Storing an
    unverifiable qualification record would mean the class a whole window's
    claims rest on was asserted by nobody in particular.

    Retroactive upgrade is refused by the database, not here (migration 0012).
    This function does not pre-check it: a check here that the trigger also
    performs invites the check here being "improved" later into the only one.
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
    columns = projection(record)
    qualification_ref = record.record_id
    connection.execute(
        qualification_records.insert(),
        {
            "qualification_ref": qualification_ref,
            "tenant_id": record.tenant_id,
            **columns,
            "assigned_class": columns["assigned_class"].value,
            "canonical_bytes": canonical_bytes,
            "body": json.loads(
                json.dumps(record.body.model_dump(mode="json", exclude_unset=True))
            ),
            "key_id": str(record.signature["key_id"]),
            "key_namespace": "evidence",
            "signature": signature,
            "qualified_at": _parse_timestamp(record.body.qualified_at),
            "recorded_at": parse_timestamp(receipt_payload.ingest_time),
            "receipt_key_id": receipt.key_id,
            "receipt_key_namespace": "issuer",
            "receipt_signature": receipt.signature,
            "receipt_canonical_bytes": receipt.canonical_bytes,
            "received_wire_bytes": canonicalize(record),
            "revalidate_after": _revalidate_after(record),
        },
    )
    return qualification_ref


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _revalidate_after(record: QualificationRecord) -> datetime:
    """`qualified_at` plus the declared revalidation cadence (CM-004).

    Derived rather than supplied: a caller-provided revalidation date could
    disagree with the cadence the signed body declares, and the column is what
    a staleness sweep would read.
    """
    qualified_at = _parse_timestamp(record.body.qualified_at)
    cadence = _day_duration(
        record.body.revalidation_cadence, label="revalidation_cadence"
    )
    return qualified_at + timedelta(days=cadence)


def qualification_history(
    connection: Connection,
    *,
    tenant_id: str,
    action_family: str,
    destination_system: str,
) -> tuple[Qualification, ...]:
    """Every qualification for one triple, oldest `qualified_at` first."""
    rows = connection.execute(
        select(qualification_records)
        .where(
            qualification_records.c.tenant_id == tenant_id,
            qualification_records.c.action_family == action_family,
            qualification_records.c.destination_system == destination_system,
        )
        .order_by(
            qualification_records.c.qualified_at,
            qualification_records.c.recorded_at,
        )
    ).mappings()
    return tuple(
        Qualification(
            qualification_ref=row["qualification_ref"],
            tenant_id=row["tenant_id"],
            action_family=row["action_family"],
            destination_system=row["destination_system"],
            assigned_class=DenominatorClass(row["assigned_class"]),
            enumeration_capable=row["enumeration_capable"],
            confirmation_capable=row["confirmation_capable"],
            identity_isolation_attribute=row["identity_isolation_attribute"],
            identity_vendor_settable=row["identity_vendor_settable"],
            authoritative_time_available=row["authoritative_time_available"],
            settlement_lag_s=row["settlement_lag_s"],
            source_retention_days=row["source_retention_days"],
            deletion_traceless_possible=row["deletion_traceless_possible"],
            qualified_at=row["qualified_at"],
            recorded_at=row["recorded_at"],
            revalidate_after=row["revalidate_after"],
        )
        for row in rows
    )


def governing_qualification(
    history: Sequence[Qualification], *, window_start: datetime
) -> Qualification:
    """The record whose class a window beginning at `window_start` inherits.

    CM-004 says a class "applies only to windows beginning after that date",
    so the comparison is strict: a record qualified at exactly `window_start`
    does not govern that window. A window that begins at the same instant a
    qualification was recorded did not begin *after* it, and reading the
    boundary case the generous way is how a retroactive upgrade gets in one
    microsecond at a time.
    """
    earlier = [
        item
        for item in _without_backdated_upgrades(history)
        if item.qualified_at < window_start
    ]
    if not earlier:
        raise UnqualifiedWindowError(
            f"no qualification record was in force at {window_start.isoformat()}; "
            f"CM-003 forbids attesting a family whose denominator class is "
            f"undeclared"
        )
    return max(earlier, key=lambda item: item.qualified_at)


def class_in_force(
    history: Sequence[Qualification],
    *,
    window_start: datetime,
    window_end: datetime,
) -> DenominatorClass:
    """The denominator class governing `[window_start, window_end)`.

    Two rules, in this order:

    * The window inherits the class of the last record qualified strictly
      before it began (CM-004). A record qualified during the window carries
      no class *up* to it, however strong.
    * A record qualified during the window that assigns a **weaker** class
      applies (CM-004: "a class may be downgraded mid-window"), and caps the
      whole window rather than part of it. Splitting the window at the
      downgrade would let the earlier sub-interval keep the stronger claim,
      which is a claim about a period whose denominator source has since been
      shown to be worse than believed.

    Taking the weakest of the candidates does both at once: a mid-window
    record stronger than the baseline loses the comparison and is ignored,
    which is exactly the treatment CM-004 requires of it.
    """
    if window_end <= window_start:
        raise QualificationError(
            f"window_end {window_end.isoformat()} does not follow window_start "
            f"{window_start.isoformat()}"
        )
    eligible = _without_backdated_upgrades(history)
    baseline = governing_qualification(eligible, window_start=window_start)
    mid_window = [
        item.assigned_class
        for item in eligible
        if window_start <= item.qualified_at < window_end
    ]
    return weakest([baseline.assigned_class, *mid_window])


def _without_backdated_upgrades(
    history: Sequence[Qualification],
) -> tuple[Qualification, ...]:
    """Exclude stronger records inserted behind an already-recorded weaker one.

    ``qualified_at`` is customer-signed effective time; ``recorded_at`` is the
    hosted observation order.  Both are required to distinguish a legitimate
    C1-then-C4 downgrade from a C4 followed by a newly inserted C1 dated behind
    it.  The write trigger refuses the latter, while this read guard remains
    conservative if such a row arrives through restore or disabled triggers.
    """

    return tuple(
        candidate
        for candidate in history
        if not any(
            candidate.assigned_class.is_stronger_than(other.assigned_class)
            and other.qualified_at >= candidate.qualified_at
            and other.recorded_at < candidate.recorded_at
            for other in history
            if other is not candidate
        )
    )


def assert_class_claimable(
    history: Sequence[Qualification],
    *,
    claimed: DenominatorClass,
    window_start: datetime,
    window_end: datetime,
) -> None:
    """Raise unless `claimed` is supported for the window. TM-013, CM-004.

    Claiming *less* than the history supports is permitted: an attestation
    understating its denominator class overclaims nothing. Claiming more is
    refused, and the two ways of claiming more are distinguished, because they
    are different facts about the world:

    * `QualificationPostdatesWindowError` -- the class was qualified, but not until
      during or after the window. This is TM-013's retroactive upgrade, and
      the message carries `QUALIFICATION_POSTDATES_WINDOW` verbatim.
    * `ClassNotQualifiedError` -- no record assigns that class at all, or the class
      in force is weaker because of a downgrade rather than a date.
    """
    in_force = class_in_force(
        history, window_start=window_start, window_end=window_end
    )
    if not claimed.is_stronger_than(in_force):
        return

    supporting = [
        item
        for item in _without_backdated_upgrades(history)
        if not claimed.is_stronger_than(item.assigned_class)
    ]
    if supporting and all(item.qualified_at >= window_start for item in supporting):
        earliest = min(supporting, key=lambda item: item.qualified_at)
        raise QualificationPostdatesWindowError(
            f"{QUALIFICATION_POSTDATES_WINDOW}: {claimed.value.upper()} was "
            f"qualified at {earliest.qualified_at.isoformat()} by "
            f"{earliest.qualification_ref}, which is not before the window "
            f"beginning {window_start.isoformat()}; the window is governed by "
            f"{in_force.value.upper()}"
        )
    raise ClassNotQualifiedError(
        f"{claimed.value.upper()} is not supported for the window beginning "
        f"{window_start.isoformat()}; the class in force is "
        f"{in_force.value.upper()}"
    )


__all__ = [
    "QUALIFICATION_POSTDATES_WINDOW",
    "ClassNotQualifiedError",
    "CoverageLevel",
    "DenominatorClass",
    "Qualification",
    "QualificationError",
    "QualificationPostdatesWindowError",
    "UnqualifiedWindowError",
    "assert_class_claimable",
    "class_in_force",
    "governing_qualification",
    "projection",
    "qualification_history",
    "record_qualification",
    "weakest",
]
