"""Sequence, digest-link, fork, and key-continuity tests for EV-03."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sdk_python.evidence.canonical import canonical_digest
from sdk_python.evidence.chain import (
    ChainVerificationError,
    DigestLinkError,
    KeyContinuityError,
    SequenceGapError,
    StreamForkError,
    create_key_continuity,
    verify_stream,
    verify_streams,
)
from sdk_python.evidence.schema import validate_record
from sdk_python.evidence.signing import sign_record

TS = "2026-07-31T12:00:00.000+01:00"


def _record(sequence: int, *, prev_digest: str | None = None):
    suffix = f"{sequence:012x}"
    return validate_record(
        {
            "record_id": f"01890f47-2f58-7cc0-98c4-{suffix}",
            "record_type": "AgentIdentity",
            "schema_version": "1.0.0",
            "tenant_id": "tenant-1",
            "boundary_ref": "boundary-1",
            "stream_id": "collector-1",
            "sequence": sequence,
            "prev_digest": prev_digest,
            "source": {"collector": "sdk-python"},
            "clocks": {"source_time": TS, "ingest_time": TS, "clock_skew_ms": 0},
            "body": {
                "agent_id": f"agent-{sequence}",
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


def _signed_chain(length: int):
    key = Ed25519PrivateKey.generate()
    records = []
    previous_digest = None
    for sequence in range(1, length + 1):
        signed = sign_record(
            _record(sequence, prev_digest=previous_digest), key_id="K1", private_key=key
        )
        records.append(signed)
        previous_digest = canonical_digest(signed)
    return key, records


def test_out_of_order_complete_stream_is_reconstructed_and_verified() -> None:
    key, records = _signed_chain(3)

    result = verify_stream(
        [records[2], records[0], records[1]], public_keys={"K1": key.public_key()}
    )

    assert result.start_sequence == 1
    assert result.end_sequence == 3
    assert result.last_digest == canonical_digest(records[-1])


def test_multiple_streams_are_verified_without_cross_stream_sequence_order() -> None:
    key = Ed25519PrivateKey.generate()
    first = sign_record(_record(1), key_id="K1", private_key=key)
    other_unsigned = _record(1).model_copy(
        update={
            "record_id": "01890f47-2f58-7cc0-98c4-dc0c0c073990",
            "stream_id": "collector-2",
        },
        deep=True,
    )
    other = sign_record(other_unsigned, key_id="K1", private_key=key)

    results = verify_streams([other, first], public_keys={"K1": key.public_key()})

    assert set(results) == {"collector-1", "collector-2"}
    assert all(result.end_sequence == 1 for result in results.values())


def test_sequence_gap_terminates_at_last_valid_record() -> None:
    key, records = _signed_chain(1)
    third = sign_record(
        _record(3, prev_digest=canonical_digest(records[0])), key_id="K1", private_key=key
    )

    with pytest.raises(SequenceGapError) as caught:
        verify_stream([records[0], third], public_keys={"K1": key.public_key()})

    assert caught.value.break_sequence == 3
    assert caught.value.valid_through_sequence == 1
    assert caught.value.coverage_gap_body["cause"] == "sequence_break"


def test_unanchored_mid_stream_input_is_not_reported_as_verified() -> None:
    key = Ed25519PrivateKey.generate()
    second = sign_record(_record(2), key_id="K1", private_key=key)

    with pytest.raises(SequenceGapError, match="without a verified anchor"):
        verify_stream([second], public_keys={"K1": key.public_key()})


def test_unauthenticated_conflict_cannot_poison_a_stream_as_a_fork() -> None:
    key = Ed25519PrivateKey.generate()
    first = sign_record(_record(1), key_id="K1", private_key=key)
    conflicting = sign_record(_record(1), key_id="K1", private_key=key)
    broken_signature = dict(conflicting.signature)
    broken_signature["sig"] = "A" * 86
    conflicting = conflicting.model_copy(update={"signature": broken_signature}, deep=True)

    with pytest.raises(ChainVerificationError) as caught:
        verify_stream([first, conflicting], public_keys={"K1": key.public_key()})

    assert not isinstance(caught.value, StreamForkError)


def test_wrong_prev_digest_is_a_chain_break() -> None:
    key, records = _signed_chain(1)
    second = sign_record(
        _record(2, prev_digest="sha256:" + "0" * 64), key_id="K1", private_key=key
    )

    with pytest.raises(DigestLinkError, match="prev_digest"):
        verify_stream([records[0], second], public_keys={"K1": key.public_key()})


def test_valid_key_continuity_allows_rotation() -> None:
    k1, records = _signed_chain(1)
    k2 = Ed25519PrivateKey.generate()
    continuity = create_key_continuity(
        predecessor_key_id="K1",
        predecessor_private_key=k1,
        new_key_id="K2",
        new_public_key=k2.public_key(),
    )
    second = sign_record(
        _record(2, prev_digest=canonical_digest(records[0])),
        key_id="K2",
        private_key=k2,
        key_continuity=continuity,
    )

    result = verify_stream(
        [records[0], second],
        public_keys={"K1": k1.public_key(), "K2": k2.public_key()},
    )

    assert result.end_sequence == 2
    assert result.last_key_id == "K2"


def test_continuity_for_a_different_new_key_is_refused() -> None:
    k1, records = _signed_chain(1)
    k2 = Ed25519PrivateKey.generate()
    substituted = Ed25519PrivateKey.generate()
    continuity = create_key_continuity(
        predecessor_key_id="K1",
        predecessor_private_key=k1,
        new_key_id="K2",
        new_public_key=substituted.public_key(),
    )
    second = sign_record(
        _record(2, prev_digest=canonical_digest(records[0])),
        key_id="K2",
        private_key=k2,
        key_continuity=continuity,
    )

    with pytest.raises(KeyContinuityError, match="new public key"):
        verify_stream(
            [records[0], second],
            public_keys={"K1": k1.public_key(), "K2": k2.public_key()},
        )
