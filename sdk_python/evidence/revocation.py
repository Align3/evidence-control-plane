"""The revocation protocol (AR-029, AR-030, AR-031).

Three separable questions, answered in this order and no other:

1. *Did we establish anything?*  AR-029.  Only a 404 or an authenticated 200
   naming the attestation we asked about is an answer; everything else leaves
   the verifier having failed to ask, which is ``unchecked`` — never ``valid``,
   because a suppressed response would then un-revoke, and never ``revoked``,
   because an unauthenticated one would then revoke.
2. *Is it in effect yet?*  AR-031.  A published revocation with a strictly
   later ``effective_at`` has not taken effect, and the attestation is
   ``valid`` — with the pending revocation surfaced, because withholding it
   would drop the fact a relying party deciding today most needs.
3. *Which state is it?*  AR-030.  ``superseding_ref`` carries the distinction
   and ``reason`` does not: a named reference reports ``superseded``, an
   explicit ``null`` reports ``revoked``, and an *absent* member is a
   non-conformant record that is rejected rather than read as either.

The transport is injected rather than performed here.  The verifier runs
offline by design (threat-model §5), and a module that opened sockets could not
be exercised against the boundary cases AR-031 pins.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast
from urllib.parse import quote

from sdk_python.evidence.chain import RegisteredPublicKey
from sdk_python.evidence.instants import Instant, TimestampError, parse_instant
from sdk_python.evidence.schema import (
    AttestationWindowRecord,
    EnvelopeValidationError,
    RevocationRecord,
)
from sdk_python.evidence.versions import require_published_schema_version

NOT_FOUND: int = 404
OK: int = 200


class RevocationStatus(StrEnum):
    """The four answers a relying party may be given."""

    VALID = "valid"
    REVOKED = "revoked"
    SUPERSEDED = "superseded"
    UNCHECKED = "unchecked"


@dataclass(frozen=True, slots=True)
class RevocationResponse:
    """What the issuer endpoint answered, as bytes and a status code."""

    status_code: int
    body: bytes | None = None


class RevocationTransport(Protocol):
    """Fetches one revocation URL.  Any failure may be raised, not swallowed."""

    def __call__(self, url: str) -> RevocationResponse: ...


@dataclass(frozen=True, slots=True)
class RevocationOutcome:
    """A revocation verdict about a named instant.

    ``evaluated_at`` is not decoration.  AR-031 makes a verification an
    assertion *about an instant*, so an outcome that did not carry the instant
    it was computed at could not be reconstructed or disputed later.
    """

    status: RevocationStatus
    evaluated_at: Instant
    detail: str
    record: RevocationRecord | None = None
    superseding_ref: str | None = None
    effective_at: Instant | None = None
    pending_status: RevocationStatus | None = None

    @property
    def is_pending(self) -> bool:
        """A published revocation whose ``effective_at`` has not yet arrived."""

        return self.pending_status is not None


def revocation_url(endpoint: str, attestation: AttestationWindowRecord) -> str:
    """Build the AR-029 request URL for an attestation."""

    return f"{endpoint.rstrip('/')}/revocations/{quote(attestation.record_id, safe='')}"


def _unchecked(evaluated_at: Instant, detail: str) -> RevocationOutcome:
    return RevocationOutcome(
        status=RevocationStatus.UNCHECKED, evaluated_at=evaluated_at, detail=detail
    )


def _authenticate(
    response: RevocationResponse,
    *,
    attestation: AttestationWindowRecord,
    verification_keys: Mapping[str, RegisteredPublicKey],
) -> RevocationRecord:
    """Return the authenticated record, or raise: a failure establishes nothing."""

    from services.ingestion.receipts import RegisteredPublicKey as ServiceKey
    from services.ingestion.receipts import verify_canonical_evidence_record

    if response.body is None:
        raise EnvelopeValidationError("200 response carried no body")

    record = verify_canonical_evidence_record(
        response.body,
        verification_keys=cast(Mapping[str, ServiceKey], verification_keys),
    )
    if not isinstance(record, RevocationRecord):
        raise EnvelopeValidationError(
            f"200 response carried a {record.record_type}, not a RevocationRecord"
        )
    require_published_schema_version(record.schema_version)
    # ES-033 already required the issuer namespace for this record type inside
    # the call above; re-stating it here would be a second, weaker check.
    if record.body.attestation_ref != attestation.record_id:
        raise EnvelopeValidationError(
            "RevocationRecord names attestation "
            f"{record.body.attestation_ref!r}, not the one asked about"
        )
    return record


def classify_revocation(
    record: RevocationRecord, *, evaluated_at: Instant
) -> RevocationOutcome:
    """Apply AR-031 then AR-030 to an already-authenticated record."""

    try:
        effective_at = parse_instant(record.body.effective_at)
    except TimestampError as exc:
        # An instant we cannot compare is not an instant we may act on.
        return _unchecked(
            evaluated_at, f"RevocationRecord effective_at is unusable: {exc}"
        )

    # AR-030. Absence never reaches here: RevocationRecordBody makes the member
    # required, so a record omitting it fails validation during authentication
    # and is refused under AR-029 rather than read as either state.
    superseding_ref = record.body.superseding_ref
    in_effect_status = (
        RevocationStatus.SUPERSEDED
        if superseding_ref is not None
        else RevocationStatus.REVOKED
    )

    # AR-031, and the boundary is exact: equality is *in effect*. Only a
    # strictly later effective_at leaves the attestation valid.
    if effective_at > evaluated_at:
        return RevocationOutcome(
            status=RevocationStatus.VALID,
            evaluated_at=evaluated_at,
            detail=(
                "a revocation is published but takes effect at "
                f"{record.body.effective_at}, later than the evaluation instant"
            ),
            record=record,
            superseding_ref=superseding_ref,
            effective_at=effective_at,
            pending_status=in_effect_status,
        )

    return RevocationOutcome(
        status=in_effect_status,
        evaluated_at=evaluated_at,
        detail=(
            "superseded by " + repr(superseding_ref)
            if superseding_ref is not None
            else "revoked: " + record.body.reason
        ),
        record=record,
        superseding_ref=superseding_ref,
        effective_at=effective_at,
    )


def check_revocation(
    attestation: AttestationWindowRecord,
    *,
    endpoint: str,
    transport: RevocationTransport,
    verification_keys: Mapping[str, RegisteredPublicKey],
    evaluated_at: Instant | str,
) -> RevocationOutcome:
    """Ask the issuer endpoint about an attestation and classify the answer."""

    instant = (
        evaluated_at if isinstance(evaluated_at, Instant) else parse_instant(evaluated_at)
    )
    url = revocation_url(endpoint, attestation)

    try:
        response = transport(url)
    except Exception as exc:  # noqa: BLE001 - any transport failure is "could not ask"
        return _unchecked(instant, f"revocation endpoint could not be reached: {exc}")

    if response.status_code == NOT_FOUND:
        return RevocationOutcome(
            status=RevocationStatus.VALID,
            evaluated_at=instant,
            detail="the issuer published no revocation for this attestation",
        )

    if response.status_code != OK:
        return _unchecked(
            instant,
            f"revocation endpoint answered {response.status_code}; nothing was "
            "established, and an unrecognised answer must not read as a clean "
            "bill of health",
        )

    try:
        record = _authenticate(
            response,
            attestation=attestation,
            verification_keys=verification_keys,
        )
    except Exception as exc:  # noqa: BLE001 - AR-029: any failure establishes nothing
        return _unchecked(
            instant, f"revocation response could not be authenticated: {exc}"
        )

    return classify_revocation(record, evaluated_at=instant)
