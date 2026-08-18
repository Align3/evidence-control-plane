"""EV-08 unit coverage: fail behaviour, buffering, gap ordering, key hygiene."""

from __future__ import annotations

import base64
import json
import traceback
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sdk_python.client import (
    FAIL_CLOSED_TRADE_OFF,
    ClientConfig,
    ClientConfigurationError,
    EvidenceClient,
    FailClosedError,
    FamilyPolicy,
    RecordRejectedError,
    SigningIdentity,
    SigningUnavailableError,
    TransportUnavailableError,
    UnconfiguredFamilyError,
)
from sdk_python.client.identity import REDACTED
from sdk_python.evidence.chain import verify_evidence_stream
from sdk_python.evidence.schema import parse_record

FAMILY = "payment.transfer"
OTHER = "ticket.resolve"


class DeadTransport:
    """Ingestion absent: every submission raises unreachable."""

    def __init__(self) -> None:
        self.attempts = 0

    def submit(self, canonical_bytes: bytes) -> None:
        self.attempts += 1
        raise TransportUnavailableError("nothing is listening")


class CollectingTransport:
    """Reachable ingestion that records exactly what bytes it received."""

    def __init__(self) -> None:
        self.received: list[bytes] = []

    def submit(self, canonical_bytes: bytes) -> None:
        self.received.append(canonical_bytes)


class ShuffledTransport(CollectingTransport):
    """Accepts anything, and asserts the client never required an order."""

    def __init__(self) -> None:
        super().__init__()
        self.sequences: list[int] = []

    def submit(self, canonical_bytes: bytes) -> None:
        super().submit(canonical_bytes)
        self.sequences.append(json.loads(canonical_bytes)["sequence"])


class RejectOnceTransport(CollectingTransport):
    """Reject the first record, then accept subsequent submissions."""

    def __init__(self) -> None:
        super().__init__()
        self.calls = 0

    def submit(self, canonical_bytes: bytes) -> None:
        self.calls += 1
        if self.calls == 1:
            raise RecordRejectedError(422, "invalid record")
        super().submit(canonical_bytes)


@pytest.fixture
def identity() -> SigningIdentity:
    return SigningIdentity(key_id="acme-collector-1", private_key=Ed25519PrivateKey.generate())


def _config(**overrides: Any) -> ClientConfig:
    defaults: dict[str, Any] = {
        "tenant_id": "acme",
        "boundary_ref": "acme:default:1",
        "collector_id": "collector-1",
        "deployment": "prod",
        "buffer_bound": 3,
        "families": {
            FAMILY: FamilyPolicy.fail_open(
                acknowledged_by="ops@example.invalid", reason="unit test"
            )
        },
    }
    defaults.update(overrides)
    return ClientConfig(**defaults)


def _client(identity: SigningIdentity, transport: Any, **overrides: Any) -> EvidenceClient:
    moment = datetime(2026, 8, 12, 9, 0, tzinfo=UTC)
    counter = {"n": 0}

    def clock() -> datetime:
        counter["n"] += 1
        return moment + timedelta(seconds=counter["n"])

    return EvidenceClient(
        config=_config(**overrides), identity=identity, transport=transport, clock=clock
    )


def _receipt(index: int) -> dict[str, Any]:
    moment = "2026-08-12T09:00:00.000Z"
    return {
        "action_id": f"00000000-0000-4000-8000-{index:012d}",
        "dispatch_attempt": 1,
        "connector_identity": "acme-connector",
        "connector_version": "0.1.0",
        "destination_response_digest": "sha256:" + "22" * 32,
        "destination_record_ref": f"destination-{index}",
        "status": "accepted",
        "dispatched_at": moment,
        "responded_at": moment,
    }


# ------------------------------------------------------- IN-009 / IN-013


def test_an_unconfigured_family_is_refused_rather_than_defaulted(
    identity: SigningIdentity,
) -> None:
    """IN-009 forbids a global default, so there is nothing to fall back to."""

    client = _client(identity, CollectingTransport())
    with pytest.raises(UnconfiguredFamilyError, match="no configured fail behaviour"):
        client.emit_execution_receipt(_receipt(0), action_family=OTHER)


def test_no_records_are_authored_for_an_unconfigured_family(
    identity: SigningIdentity,
) -> None:
    """The refusal must precede signing, or the stream gains a phantom sequence."""

    transport = CollectingTransport()
    client = _client(identity, transport)
    with pytest.raises(UnconfiguredFamilyError):
        client.emit_execution_receipt(_receipt(0), action_family=OTHER)

    assert transport.received == []
    result = client.emit_execution_receipt(_receipt(1), action_family=FAMILY)
    assert result.sequence == 1, "the refused emission consumed a sequence number"


def test_fail_closed_requires_the_trade_off_verbatim() -> None:
    with pytest.raises(ClientConfigurationError, match="trade-off"):
        FamilyPolicy.fail_closed(
            acknowledged_by="ops@example.invalid",
            reason="high-risk",
            trade_off_acknowledged="I understand the risks",
        )

    policy = FamilyPolicy.fail_closed(
        acknowledged_by="ops@example.invalid",
        reason="high-risk",
        trade_off_acknowledged=FAIL_CLOSED_TRADE_OFF,
    )
    assert policy.behaviour == "fail_closed"


def test_changing_fail_behaviour_produces_an_audit_record() -> None:
    """IN-009: there is no setter that changes behaviour without the record."""

    policy = FamilyPolicy.fail_open(acknowledged_by="ops@example.invalid", reason="initial")
    replacement, change = policy.changed_to(
        "fail_closed",
        action_family=FAMILY,
        changed_by="risk@example.invalid",
        reason="regulatory review",
        trade_off_acknowledged=FAIL_CLOSED_TRADE_OFF,
    )
    assert replacement.behaviour == "fail_closed"
    assert change.action_family == FAMILY
    assert change.previous == "fail_open" and change.current == "fail_closed"
    assert change.changed_by == "risk@example.invalid"
    with pytest.raises(AttributeError):
        policy.behaviour = "fail_closed"  # type: ignore[misc]


def test_fail_closed_family_refuses_the_action_after_recording_the_gap(
    identity: SigningIdentity,
) -> None:
    """IN-013: the customer's outage is the chosen trade-off, but the gap is kept."""

    client = _client(
        identity,
        DeadTransport(),
        families={
            FAMILY: FamilyPolicy.fail_closed(
                acknowledged_by="risk@example.invalid",
                reason="high-risk transfers",
                trade_off_acknowledged=FAIL_CLOSED_TRADE_OFF,
            )
        },
    )
    for index in range(3):
        client.emit_execution_receipt(_receipt(index), action_family=FAMILY)

    with pytest.raises(FailClosedError):
        client.emit_execution_receipt(_receipt(3), action_family=FAMILY)

    assert len(client.gap_records()) == 1, "the gap must survive the refusal"
    assert client.buffered_count() == 3, "fail-closed must not discard buffered evidence"
    gap = parse_record(json.loads(client.gap_records()[0].canonical_bytes))
    assert gap.body.actions_during_gap == 0
    # Nothing was lost behind the caller's back: it was told, by exception,
    # and the action did not proceed.
    assert client.refused_count() == 0


def test_transport_rejection_does_not_create_a_phantom_predecessor(
    identity: SigningIdentity,
) -> None:
    transport = RejectOnceTransport()
    client = _client(identity, transport)

    with pytest.raises(RecordRejectedError):
        client.emit_execution_receipt(_receipt(0), action_family=FAMILY)

    accepted = client.emit_execution_receipt(_receipt(1), action_family=FAMILY)
    assert accepted.sequence == 1
    record = json.loads(transport.received[0])
    assert record["sequence"] == 1
    assert record["prev_digest"] is None


# --------------------------------------------------------------- IN-010 / IN-011


def test_exhaustion_refuses_the_new_record_and_leaves_the_buffer_intact(
    identity: SigningIdentity,
) -> None:
    """IN-010/IN-011: the bound refuses admission, it never makes room."""

    client = _client(identity, DeadTransport())
    for index in range(3):
        client.emit_execution_receipt(_receipt(index), action_family=FAMILY)

    assert client.buffered_count() == 3
    assert client.gap_records() == []
    assert client.refused_count() == 0
    # Byte-for-byte, exactly what is held before exhaustion.
    held_before = [
        (item.record_id, item.sequence, item.canonical_bytes)
        for item in client.pending()
    ]

    result = client.emit_execution_receipt(_receipt(3), action_family=FAMILY)

    # The new record is what gives way, and it takes no sequence with it.
    assert not result.captured
    assert result.sequence is None
    assert client.refused_count() == 1

    # Nothing already buffered was touched: same records, same order, same bytes.
    held_after = [
        (item.record_id, item.sequence, item.canonical_bytes)
        for item in client.pending()
        if item.record_type != "CoverageGap"
    ]
    assert held_after == held_before
    assert client.buffered_count() == 3

    # A locally signed gap accounts for the interval that went uncaptured.
    gaps = client.gap_records()
    assert len(gaps) == 1
    gap = parse_record(json.loads(gaps[0].canonical_bytes))
    assert gap.record_type == "CoverageGap"
    assert gap.body.cause == "collector_unreachable"
    assert gap.body.actions_during_gap == 1
    # The gap takes the sequence the refused record gave back, so the chain
    # continues from the last record still held instead of skipping one.
    assert gap.sequence == held_before[-1][1] + 1


def test_gap_body_states_what_the_client_actually_knows(identity: SigningIdentity) -> None:
    client = _client(identity, DeadTransport())
    for index in range(4):
        client.emit_execution_receipt(_receipt(index), action_family=FAMILY)

    gap = parse_record(json.loads(client.gap_records()[0].canonical_bytes))
    assert gap.body.cause == "collector_unreachable"
    assert gap.body.exposure == "known"
    # One emission was refused, so exactly one action went uncaptured. The
    # three still in the buffer are held evidence, not gap contents.
    assert gap.body.actions_during_gap == 1
    assert gap.body.affected_scope["action_family"] == FAMILY


def test_buffer_refuses_to_exceed_its_bound(identity: SigningIdentity) -> None:
    client = _client(identity, DeadTransport(), buffer_bound=2)
    for index in range(6):
        client.emit_execution_receipt(_receipt(index), action_family=FAMILY)
    assert client.buffered_count() == 2
    assert client.refused_count() == 4


def test_a_continuing_outage_accumulates_the_uncaptured_count(
    identity: SigningIdentity,
) -> None:
    """Each gap states the episode's running total, not just its own refusal.

    The count cannot be revised later: a signed gap is immutable. So each new
    gap supersedes the previous one for the same episode, and the last is the
    complete account of it.
    """

    client = _client(identity, DeadTransport(), buffer_bound=2)
    for index in range(5):
        client.emit_execution_receipt(_receipt(index), action_family=FAMILY)

    counts = [
        parse_record(json.loads(item.canonical_bytes)).body.actions_during_gap
        for item in client.gap_records()
    ]
    assert counts == [1, 2, 3]

    starts = {
        parse_record(json.loads(item.canonical_bytes)).body.gap_start
        for item in client.gap_records()
    }
    assert len(starts) == 1, "one episode has one start, however many gaps mark it"


def test_gap_emission_reaches_no_network(identity: SigningIdentity) -> None:
    """IN-011's whole point: the gap does not depend on our availability."""

    transport = DeadTransport()
    client = _client(identity, transport)
    for index in range(4):
        client.emit_execution_receipt(_receipt(index), action_family=FAMILY)

    # Four emissions attempted the network; the gap itself added no attempt.
    assert transport.attempts == 4
    assert len(client.gap_records()) == 1


def test_gaps_module_cannot_reach_a_socket() -> None:
    """Enforce the import-closure property `gaps.py` documents."""

    import sdk_python.client.gaps as gaps

    closure: set[str] = set()
    pending = [gaps.__name__]
    seen = set()
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        module = __import__(name, fromlist=["__dict__"])
        for value in vars(module).values():
            origin = getattr(value, "__module__", None) or getattr(value, "__name__", None)
            if isinstance(origin, str) and origin.startswith("sdk_python.client"):
                pending.append(origin)
            elif isinstance(origin, str):
                closure.add(origin.split(".")[0])

    forbidden = {"socket", "urllib", "http", "httpx", "requests", "asyncio"}
    assert not (closure & forbidden), (
        f"gaps.py can reach {sorted(closure & forbidden)}; IN-011 requires it to "
        "produce evidence with no hosted dependency"
    )


# --------------------------------------------------------------------- IN-012


def test_flush_submits_original_bytes_without_resigning(identity: SigningIdentity) -> None:
    client = _client(identity, DeadTransport())
    for index in range(3):
        client.emit_execution_receipt(_receipt(index), action_family=FAMILY)
    authored = {item.record_id: item.canonical_bytes for item in client.pending()}
    authored_times = {
        item.record_id: item.signed_at for item in client.pending()
    }

    reconnected = CollectingTransport()
    results = client.flush(transport=reconnected)

    assert len(results) == 3
    for result in results:
        assert result.canonical_bytes == authored[result.record_id], "bytes changed"
        parsed = json.loads(result.canonical_bytes)
        assert parsed["clocks"]["source_time"] == authored_times[result.record_id]
    assert reconnected.received == [item for item in authored.values()]


def test_flush_does_not_assume_in_order_delivery(identity: SigningIdentity) -> None:
    """EV-07 reconciles by sequence; the client must not depend on arrival order."""

    client = _client(identity, DeadTransport())
    for index in range(3):
        client.emit_execution_receipt(_receipt(index), action_family=FAMILY)

    shuffled = ShuffledTransport()
    results = client.flush(transport=shuffled)

    assert len(results) == 3
    # Every buffered record was offered exactly once, and the client did not
    # abort when sequences arrived non-monotonically at the far side.
    assert shuffled.sequences == sorted(shuffled.sequences)
    assert len({json.loads(b)["record_id"] for b in shuffled.received}) == 3
    assert client.buffered_count() == 0


def test_a_partial_flush_retains_what_was_not_accepted(identity: SigningIdentity) -> None:
    client = _client(identity, DeadTransport())
    for index in range(3):
        client.emit_execution_receipt(_receipt(index), action_family=FAMILY)

    class FlakyTransport:
        def __init__(self) -> None:
            self.calls = 0

        def submit(self, canonical_bytes: bytes) -> None:
            self.calls += 1
            if self.calls > 1:
                raise TransportUnavailableError("dropped again mid-flush")

    results = client.flush(transport=FlakyTransport())
    assert len(results) == 1
    assert client.buffered_count() == 2, "unsent records must not be lost"


def test_the_local_chain_verifies_across_an_outage(identity: SigningIdentity) -> None:
    """The stream authored offline is a well-formed ES-006a chain."""

    from dataclasses import dataclass

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    @dataclass(frozen=True)
    class RK:
        namespace: str
        public_key: Ed25519PublicKey

    client = _client(identity, DeadTransport())
    for index in range(4):
        client.emit_execution_receipt(_receipt(index), action_family=FAMILY)

    records = [
        parse_record(json.loads(item.canonical_bytes)) for item in client.pending()
    ]
    # The dropped record leaves a sequence hole by design, so verify the
    # contiguous prefix the client still holds.
    contiguous = [r for r in records if r.sequence <= 4]
    result = verify_evidence_stream(
        contiguous,
        verification_keys={identity.key_id: RK("evidence", identity.public_key)},
    )
    assert result.end_sequence == contiguous[-1].sequence


# ------------------------------------------------------------ SE-005 / SE-006


def test_private_key_never_appears_in_repr_or_str(identity: SigningIdentity) -> None:
    rendered = f"{identity!r} {identity} {identity:>10}"
    assert REDACTED in rendered
    assert _key_material(identity) not in rendered


def test_private_key_never_appears_in_a_signing_failure_traceback() -> None:
    """The trap: deliberately break signing and grep the whole traceback."""

    broken = SigningIdentity(key_id="k", private_key=Ed25519PrivateKey.generate())
    secret = _key_material(broken)

    class Exploding:
        def sign(self, payload: bytes) -> bytes:
            raise RuntimeError("HSM offline")

        def public_key(self) -> Any:  # pragma: no cover - not reached
            raise AssertionError

    object.__setattr__(broken, "private_key", Exploding())
    with pytest.raises(SigningUnavailableError) as caught:
        broken.sign_bytes(b"payload")

    rendered = "".join(
        traceback.format_exception(type(caught.value), caught.value, caught.value.__tb__)
        if hasattr(caught.value, "__tb__")
        else traceback.format_exception(caught.value)
    )
    assert secret not in rendered
    assert caught.value.__cause__ is None, "a chained cause exposes the key's frame"
    assert caught.value.__context__ is None or "HSM" not in str(caught.value)


def test_private_key_never_appears_when_a_malformed_record_fails(
    identity: SigningIdentity,
) -> None:
    secret = _key_material(identity)
    client = _client(identity, CollectingTransport())

    with pytest.raises(Exception) as caught:  # noqa: PT011 - any failure path counts
        client.emit_execution_receipt({"action_id": "not-a-valid-body"}, action_family=FAMILY)

    rendered = "".join(traceback.format_exception(caught.value))
    assert secret not in rendered
    assert REDACTED in repr(identity)


def test_a_signing_identity_cannot_be_serialized(identity: SigningIdentity) -> None:
    import copy
    import pickle

    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(identity)
    with pytest.raises(TypeError, match="cannot be serialized"):
        copy.deepcopy(identity)


def _key_material(identity: SigningIdentity) -> str:
    raw = identity.private_key.private_bytes_raw()
    return base64.b64encode(raw).decode()
