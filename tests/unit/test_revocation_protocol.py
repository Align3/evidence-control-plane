"""AR-029/030/031: the revocation protocol, its discriminator, and its boundary.

Negative-first per AG-007.  The withholding case — ``unchecked`` — is written
before any verdict, because AR-029's whole point is that "I could not ask" must
not be reported as "nothing was published".
"""

from __future__ import annotations

import json

import pytest

from sdk_python.evidence.canonical import canonicalize
from sdk_python.evidence.instants import Instant, TimestampError, parse_instant
from sdk_python.evidence.revocation import (
    RevocationResponse,
    RevocationStatus,
    check_revocation,
    classify_revocation,
    revocation_url,
)
from sdk_python.evidence.schema import RevocationRecord
from tests.bundle_support import (
    signed_attestation,
    signed_coverage_gap,
    signed_revocation,
    verification_keys,
)

ENDPOINT = "https://issuer.example.invalid/api"
NOW = "2026-08-01T12:00:00.000Z"


def _responder(response: RevocationResponse):
    def transport(url: str) -> RevocationResponse:
        assert url.endswith("/revocations/" + ATTESTATION.record_id)
        return response

    return transport


ATTESTATION = signed_attestation()


def _check(response: RevocationResponse, *, evaluated_at: str = NOW):
    return check_revocation(
        ATTESTATION,
        endpoint=ENDPOINT,
        transport=_responder(response),
        verification_keys=verification_keys(),
        evaluated_at=evaluated_at,
    )


def _signed_revocation_bytes(
    *, effective_at: str = NOW, superseding_ref: str | None = None, **kwargs
) -> bytes:
    return canonicalize(
        signed_revocation(
            attestation_ref=ATTESTATION.record_id,
            effective_at=effective_at,
            superseding_ref=superseding_ref,
            **kwargs,
        )
    )


# --------------------------------------------------------------------------
# AR-029: what counts as having asked
# --------------------------------------------------------------------------


def test_the_request_url_is_the_attestation_record_id() -> None:
    assert revocation_url(ENDPOINT, ATTESTATION) == (
        f"{ENDPOINT}/revocations/{ATTESTATION.record_id}"
    )
    assert revocation_url(ENDPOINT + "/", ATTESTATION) == revocation_url(
        ENDPOINT, ATTESTATION
    )


@pytest.mark.parametrize("status_code", [301, 400, 401, 403, 429, 500, 502, 503])
def test_any_other_response_establishes_nothing(status_code: int) -> None:
    """AR-S-009: not valid, and not revoked."""

    outcome = _check(RevocationResponse(status_code, b"whatever"))
    assert outcome.status is RevocationStatus.UNCHECKED
    assert outcome.status is not RevocationStatus.VALID
    assert outcome.status is not RevocationStatus.REVOKED


def test_an_unreachable_endpoint_is_unchecked_not_valid() -> None:
    def transport(url: str) -> RevocationResponse:
        raise OSError("captive portal")

    outcome = check_revocation(
        ATTESTATION,
        endpoint=ENDPOINT,
        transport=transport,
        verification_keys=verification_keys(),
        evaluated_at=NOW,
    )
    assert outcome.status is RevocationStatus.UNCHECKED


def test_a_404_is_an_answer_and_reports_valid() -> None:
    outcome = _check(RevocationResponse(404))
    assert outcome.status is RevocationStatus.VALID
    assert outcome.record is None


def test_a_200_with_no_body_establishes_nothing() -> None:
    assert _check(RevocationResponse(200)).status is RevocationStatus.UNCHECKED


def test_a_200_carrying_an_unsigned_record_establishes_nothing() -> None:
    """An unauthenticated answer would let anyone revoke."""

    record = json.loads(_signed_revocation_bytes())
    record["body"]["reason"] = "substituted after signing"
    outcome = _check(RevocationResponse(200, canonicalize(record)))
    assert outcome.status is RevocationStatus.UNCHECKED


def test_a_200_signed_by_an_evidence_key_establishes_nothing() -> None:
    """ES-033 makes RevocationRecord issuer-primary; a customer cannot revoke."""

    body = _signed_revocation_bytes(signer="evidence")
    assert _check(RevocationResponse(200, body)).status is RevocationStatus.UNCHECKED


def test_a_200_naming_a_different_attestation_establishes_nothing() -> None:
    body = canonicalize(
        signed_revocation(
            attestation_ref="01890f47-2f58-7cc0-98c4-000000000099",
            effective_at=NOW,
            superseding_ref=None,
        )
    )
    assert _check(RevocationResponse(200, body)).status is RevocationStatus.UNCHECKED


def test_a_200_carrying_a_different_record_type_establishes_nothing() -> None:
    body = canonicalize(signed_coverage_gap())
    assert _check(RevocationResponse(200, body)).status is RevocationStatus.UNCHECKED


@pytest.mark.parametrize("schema_version", ["2.0.0", "9.9.9"])
def test_a_revocation_with_an_unpublished_schema_establishes_nothing(
    schema_version: str,
) -> None:
    body = _signed_revocation_bytes(schema_version=schema_version)
    assert _check(RevocationResponse(200, body)).status is RevocationStatus.UNCHECKED


def test_a_non_canonical_200_body_establishes_nothing() -> None:
    body = json.dumps(json.loads(_signed_revocation_bytes()), indent=2).encode()
    assert _check(RevocationResponse(200, body)).status is RevocationStatus.UNCHECKED


def test_an_absent_superseding_ref_is_rejected_rather_than_read_as_either() -> None:
    """AR-030: ES-002b makes the member required and nullable.

    Absence is not a third spelling of ``null``.  A record omitting it is
    non-conformant, and reading it as ``revoked`` would let a producer's
    omission decide a relying party's verdict.
    """

    record = json.loads(_signed_revocation_bytes())
    del record["body"]["superseding_ref"]
    outcome = _check(RevocationResponse(200, canonicalize(record)))
    assert outcome.status is RevocationStatus.UNCHECKED
    assert outcome.status is not RevocationStatus.REVOKED
    assert outcome.status is not RevocationStatus.SUPERSEDED


# --------------------------------------------------------------------------
# AR-030: superseding_ref, and not reason, carries the distinction
# --------------------------------------------------------------------------


def test_a_named_superseding_ref_reports_superseded() -> None:
    body = _signed_revocation_bytes(superseding_ref="attestation-2")
    outcome = _check(RevocationResponse(200, body))
    assert outcome.status is RevocationStatus.SUPERSEDED
    assert outcome.superseding_ref == "attestation-2"


def test_an_otherwise_identical_record_with_null_superseding_ref_reports_revoked() -> None:
    """AR-S-010's second clause, held against the first on one changed member."""

    superseded = json.loads(_signed_revocation_bytes(superseding_ref="attestation-2"))
    revoked = json.loads(_signed_revocation_bytes(superseding_ref=None))
    differences = {
        key
        for key in superseded["body"]
        if superseded["body"][key] != revoked["body"][key]
    }
    assert differences == {"superseding_ref"}

    assert (
        _check(RevocationResponse(200, canonicalize(superseded))).status
        is RevocationStatus.SUPERSEDED
    )
    assert (
        _check(RevocationResponse(200, canonicalize(revoked))).status
        is RevocationStatus.REVOKED
    )


def test_reason_does_not_carry_the_distinction() -> None:
    """The discriminator is the reference, not the prose beside it."""

    signed = canonicalize(
        signed_revocation(
            attestation_ref=ATTESTATION.record_id,
            effective_at=NOW,
            superseding_ref=None,
            reason="superseded by a later attestation",
        )
    )
    # A record whose *reason* says supersession but whose superseding_ref is
    # null is a revocation, because AR-030 assigns the distinction to the ref.
    assert _check(RevocationResponse(200, signed)).status is RevocationStatus.REVOKED


# --------------------------------------------------------------------------
# AR-031: the effective-date boundary
# --------------------------------------------------------------------------


def _classified(effective_at: str, evaluated_at: str, superseding_ref=None):
    record = signed_revocation(
        attestation_ref=ATTESTATION.record_id,
        effective_at=effective_at,
        superseding_ref=superseding_ref,
    )
    assert isinstance(record, RevocationRecord)
    return classify_revocation(record, evaluated_at=parse_instant(evaluated_at))


def test_a_strictly_later_effective_at_leaves_the_attestation_valid() -> None:
    outcome = _classified("2026-08-01T12:00:00.001Z", NOW)
    assert outcome.status is RevocationStatus.VALID
    assert outcome.pending_status is RevocationStatus.REVOKED
    assert outcome.is_pending
    assert outcome.effective_at == parse_instant("2026-08-01T12:00:00.001Z")
    assert outcome.evaluated_at == parse_instant(NOW)


def test_an_identical_effective_at_is_in_effect() -> None:
    """The boundary is exact: equality revokes.

    Pinned rather than inferred from "later than".  Between reporting an
    attestation revoked slightly early and trusting it slightly too long, only
    the first is a safe failure for a relying party.
    """

    outcome = _classified(NOW, NOW)
    assert outcome.status is RevocationStatus.REVOKED
    assert outcome.pending_status is None


def test_one_microsecond_either_side_of_the_boundary() -> None:
    before = "2026-08-01T11:59:59.999999Z"
    exact = "2026-08-01T12:00:00.000000Z"
    after = "2026-08-01T12:00:00.000001Z"

    assert _classified(before, exact).status is RevocationStatus.REVOKED
    assert _classified(exact, exact).status is RevocationStatus.REVOKED
    assert _classified(after, exact).status is RevocationStatus.VALID


def test_a_pending_revocation_is_surfaced_rather_than_discarded() -> None:
    """AR-S-011: reporting valid while silently dropping it would withhold the
    one fact a relying party deciding today most needs."""

    outcome = _classified("2026-09-01T00:00:00.000Z", NOW, superseding_ref="att-2")
    assert outcome.status is RevocationStatus.VALID
    assert outcome.record is not None
    assert outcome.effective_at is not None
    assert outcome.effective_at.text == "2026-09-01T00:00:00.000Z"
    assert outcome.pending_status is RevocationStatus.SUPERSEDED
    assert outcome.evaluated_at.text == NOW


def test_the_evaluation_instant_appears_in_every_outcome() -> None:
    """AR-031: a verification is an assertion about an instant."""

    outcomes = [
        _check(RevocationResponse(404)),
        _check(RevocationResponse(500)),
        _check(RevocationResponse(200, _signed_revocation_bytes())),
    ]
    assert all(outcome.evaluated_at == parse_instant(NOW) for outcome in outcomes)


def test_a_past_decision_can_be_reconstructed_by_supplying_the_instant() -> None:
    body = _signed_revocation_bytes(effective_at="2026-08-01T12:00:00.000Z")
    assert (
        _check(RevocationResponse(200, body), evaluated_at="2026-07-01T00:00:00.000Z").status
        is RevocationStatus.VALID
    )
    assert (
        _check(RevocationResponse(200, body), evaluated_at="2026-09-01T00:00:00.000Z").status
        is RevocationStatus.REVOKED
    )


# --------------------------------------------------------------------------
# The comparison is on instants, never on strings
# --------------------------------------------------------------------------


def test_two_spellings_of_one_instant_compare_equal() -> None:
    """A lexical comparison ranks these apart; AR-031 forbids that."""

    zulu = parse_instant("2026-10-01T10:00:00.000Z")
    offset = parse_instant("2026-10-01T11:00:00.000+01:00")
    assert zulu.text != offset.text
    assert zulu.same_instant_as(offset)
    assert zulu.epoch_nanoseconds == offset.epoch_nanoseconds
    assert not zulu < offset
    assert not offset < zulu


def test_an_offset_spelling_is_classified_by_instant_not_by_text() -> None:
    # Lexically "2026-08-01T13:00:00.000+01:00" > "2026-08-01T12:00:00.000Z",
    # which would wrongly report valid. As instants they are equal.
    outcome = _classified("2026-08-01T13:00:00.000+01:00", NOW)
    assert outcome.status is RevocationStatus.REVOKED


def test_a_negative_offset_is_ordered_correctly() -> None:
    # 07:00-05:00 is 12:00Z: equal, therefore in effect.
    assert _classified("2026-08-01T07:00:00.000-05:00", NOW).status is (
        RevocationStatus.REVOKED
    )
    # 06:59:59.999-05:00 is one millisecond earlier: also in effect.
    assert _classified("2026-08-01T06:59:59.999-05:00", NOW).status is (
        RevocationStatus.REVOKED
    )
    # 07:00:00.001-05:00 is one millisecond later: not yet.
    assert _classified("2026-08-01T07:00:00.001-05:00", NOW).status is (
        RevocationStatus.VALID
    )


def test_an_uncomparable_precision_is_refused_rather_than_truncated() -> None:
    with pytest.raises(TimestampError, match="nanosecond"):
        parse_instant("2026-08-01T12:00:00.0000000001Z")


def test_an_unvalidated_leap_second_is_refused_rather_than_normalized() -> None:
    with pytest.raises(TimestampError, match="leap-second"):
        parse_instant("2026-08-01T12:00:60.000Z")


def test_a_timestamp_without_an_offset_is_refused() -> None:
    with pytest.raises(TimestampError, match="explicit offset"):
        parse_instant("2026-08-01T12:00:00.000")


def test_instants_are_not_ordered_by_their_text() -> None:
    later_text_earlier_instant = parse_instant("2026-08-01T13:00:00.000+02:00")
    earlier_text_later_instant = parse_instant("2026-08-01T12:00:00.000Z")
    assert later_text_earlier_instant.text > earlier_text_later_instant.text
    assert later_text_earlier_instant < earlier_text_later_instant


def test_instant_equality_ignores_spelling_for_ordering_operators() -> None:
    assert Instant(0, "a") <= Instant(0, "z")
    assert Instant(0, "z") >= Instant(0, "a")
    assert not Instant(0, "a") < Instant(0, "z")
