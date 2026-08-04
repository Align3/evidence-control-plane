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


def _record(
    sequence: int,
    *,
    prev_digest: str | None = None,
    tenant_id: str = "tenant-1",
    stream_id: str = "collector-1",
):
    suffix = f"{sequence:012x}"
    return validate_record(
        {
            "record_id": f"01890f47-2f58-7cc0-98c4-{suffix}",
            "record_type": "AgentIdentity",
            "schema_version": "1.0.0",
            "tenant_id": tenant_id,
            "boundary_ref": "boundary-1",
            "stream_id": stream_id,
            "sequence": sequence,
            "prev_digest": prev_digest,
            "source": {"collector": "sdk-python"},
            "clocks": {"source_time": TS},
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


def test_prev_digest_commits_the_previous_signature_member() -> None:
    original_key, records = _signed_chain(1)
    second = sign_record(
        _record(2, prev_digest=canonical_digest(records[0])),
        key_id="K1",
        private_key=original_key,
    )
    replacement_key = Ed25519PrivateKey.generate()
    unsigned_first = records[0].model_copy(update={"signature": {}}, deep=True)
    resigned_first = sign_record(
        unsigned_first, key_id="KX", private_key=replacement_key
    )

    with pytest.raises(DigestLinkError, match="prev_digest mismatch"):
        verify_stream(
            [resigned_first, second],
            public_keys={"KX": replacement_key.public_key(), "K1": original_key.public_key()},
        )


def test_valid_key_continuity_allows_rotation() -> None:
    k1, records = _signed_chain(1)
    k2 = Ed25519PrivateKey.generate()
    continuity = create_key_continuity(
        predecessor_key_id="K1",
        predecessor_private_key=k1,
        new_key_id="K2",
        new_public_key=k2.public_key(),
        tenant_id="tenant-1",
        stream_id="collector-1",
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
        tenant_id="tenant-1",
        stream_id="collector-1",
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


@pytest.mark.parametrize(
    ("target_tenant", "target_stream", "message"),
    [
        ("tenant-2", "collector-1", "tenant_id does not match"),
        ("tenant-1", "collector-2", "stream_id does not match"),
    ],
)
def test_continuity_proof_cannot_be_replayed_across_context(
    target_tenant: str, target_stream: str, message: str
) -> None:
    k1 = Ed25519PrivateKey.generate()
    k2 = Ed25519PrivateKey.generate()
    first = sign_record(
        _record(1, tenant_id=target_tenant, stream_id=target_stream),
        key_id="K1",
        private_key=k1,
    )
    continuity = create_key_continuity(
        predecessor_key_id="K1",
        predecessor_private_key=k1,
        new_key_id="K2",
        new_public_key=k2.public_key(),
        tenant_id="tenant-1",
        stream_id="collector-1",
    )
    second = sign_record(
        _record(
            2,
            prev_digest=canonical_digest(first),
            tenant_id=target_tenant,
            stream_id=target_stream,
        ),
        key_id="K2",
        private_key=k2,
    )
    replayed_signature = dict(second.signature)
    replayed_signature["key_continuity"] = continuity
    replayed = second.model_copy(
        update={"signature": replayed_signature}, deep=True
    )

    with pytest.raises(ChainVerificationError, match=message):
        verify_stream(
            [first, replayed],
            public_keys={"K1": k1.public_key(), "K2": k2.public_key()},
        )


def test_continuity_context_is_covered_by_the_predecessor_signature() -> None:
    k1 = Ed25519PrivateKey.generate()
    k2 = Ed25519PrivateKey.generate()
    first = sign_record(
        _record(1, tenant_id="tenant-2"), key_id="K1", private_key=k1
    )
    continuity = create_key_continuity(
        predecessor_key_id="K1",
        predecessor_private_key=k1,
        new_key_id="K2",
        new_public_key=k2.public_key(),
        tenant_id="tenant-1",
        stream_id="collector-1",
    )
    forged_continuity = dict(continuity)
    forged_continuity["tenant_id"] = "tenant-2"
    second = sign_record(
        _record(
            2,
            prev_digest=canonical_digest(first),
            tenant_id="tenant-2",
        ),
        key_id="K2",
        private_key=k2,
        key_continuity=forged_continuity,
    )

    # The assertion and envelope agree on tenant-2, so only cryptographic
    # coverage of the tenant binding can reject this forgery.
    assert second.signature["key_continuity"]["tenant_id"] == second.tenant_id
    with pytest.raises(KeyContinuityError, match="signed by the predecessor"):
        verify_stream(
            [first, second],
            public_keys={"K1": k1.public_key(), "K2": k2.public_key()},
        )


def test_continuity_assertion_with_unknown_member_is_refused() -> None:
    k1, records = _signed_chain(1)
    k2 = Ed25519PrivateKey.generate()
    continuity = create_key_continuity(
        predecessor_key_id="K1",
        predecessor_private_key=k1,
        new_key_id="K2",
        new_public_key=k2.public_key(),
        tenant_id="tenant-1",
        stream_id="collector-1",
    )
    continuity["junk"] = "not authenticated"
    second = sign_record(
        _record(2, prev_digest=canonical_digest(records[0])),
        key_id="K2",
        private_key=k2,
    )
    replayed_signature = dict(second.signature)
    replayed_signature["key_continuity"] = continuity
    replayed = second.model_copy(update={"signature": replayed_signature}, deep=True)

    with pytest.raises(ChainVerificationError, match="unknown.*member"):
        verify_stream(
            [records[0], replayed],
            public_keys={"K1": k1.public_key(), "K2": k2.public_key()},
        )


def test_continuity_assertion_is_refused_on_first_record() -> None:
    predecessor = Ed25519PrivateKey.generate()
    current = Ed25519PrivateKey.generate()
    continuity = create_key_continuity(
        predecessor_key_id="K0",
        predecessor_private_key=predecessor,
        new_key_id="K1",
        new_public_key=current.public_key(),
        tenant_id="tenant-1",
        stream_id="collector-1",
    )
    first = sign_record(
        _record(1),
        key_id="K1",
        private_key=current,
        key_continuity=continuity,
    )

    with pytest.raises(KeyContinuityError, match="forbidden on the first"):
        verify_stream(
            [first],
            public_keys={"K0": predecessor.public_key(), "K1": current.public_key()},
        )


def test_continuity_assertion_is_refused_without_key_rotation() -> None:
    predecessor = Ed25519PrivateKey.generate()
    current = Ed25519PrivateKey.generate()
    continuity = create_key_continuity(
        predecessor_key_id="K0",
        predecessor_private_key=predecessor,
        new_key_id="K1",
        new_public_key=current.public_key(),
        tenant_id="tenant-1",
        stream_id="collector-1",
    )
    first = sign_record(_record(1), key_id="K1", private_key=current)
    second = sign_record(
        _record(2, prev_digest=canonical_digest(first)),
        key_id="K1",
        private_key=current,
        key_continuity=continuity,
    )

    with pytest.raises(KeyContinuityError, match="without a key rotation"):
        verify_stream(
            [first, second],
            public_keys={"K0": predecessor.public_key(), "K1": current.public_key()},
        )
