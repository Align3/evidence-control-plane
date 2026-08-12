"""The public emission API (IN-009 through IN-013, SE-005, SE-006)."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sdk_python.client.buffer import BoundedBuffer, BufferedRecord
from sdk_python.client.config import ClientConfig, FamilyPolicy
from sdk_python.client.gaps import build_coverage_gap
from sdk_python.client.identity import SigningIdentity
from sdk_python.client.records import build_envelope, sign_locally
from sdk_python.client.transport import (
    RecordRejectedError,
    Transport,
    TransportUnavailableError,
)

#: ES-033 assigns these to the customer's evidence key. The client holds an
#: evidence key (SE-006) and therefore emits exactly this set; PopulationRecord,
#: ExternalConfirmation, and RevocationRecord are issuer-origin and are produced
#: by hosted services, not here.
CUSTOMER_RECORD_TYPES = (
    "AssuranceBoundary",
    "QualificationRecord",
    "AgentIdentity",
    "ActionProposal",
    "AuthorityDecision",
    "HumanReview",
    "ExecutionReceipt",
    "FinalityRecord",
    "OutcomeRecord",
    "CoverageGap",
)


class FailClosedError(RuntimeError):
    """IN-013: the family is fail-closed and evidence could not be recorded."""


@dataclass(frozen=True, slots=True)
class EmissionResult:
    """What happened to one emitted record."""

    record_id: str
    record_type: str
    sequence: int
    submitted: bool
    buffered: bool

    @property
    def accepted(self) -> bool:
        return self.submitted


@dataclass(frozen=True, slots=True)
class FlushResult:
    """One record's fate during a flush, carrying the bytes actually sent."""

    record_id: str
    record_type: str
    sequence: int
    canonical_bytes: bytes
    accepted: bool


class EvidenceClient:
    """Emit signed evidence, buffering locally when ingestion is absent.

    One client instance owns one stream. Sequence and `prev_digest` are assigned
    locally and monotonically, so the chain stays well-formed across an outage:
    the records were authored in that order whether or not anyone could receive
    them at the time.
    """

    def __init__(
        self,
        *,
        config: ClientConfig,
        identity: SigningIdentity,
        transport: Transport,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._config = config
        self._identity = identity
        self._transport = transport
        self._clock = clock or (lambda: datetime.now(UTC))
        self._buffer = BoundedBuffer(config.buffer_bound)
        self._gaps: list[BufferedRecord] = []
        self._sequence = 0
        self._prev_digest: str | None = None
        self._stream_id = f"{config.tenant_id}:{config.collector_id}:1"
        self._unreachable_since: datetime | None = None

    @property
    def key_id(self) -> str:
        return self._identity.key_id

    @property
    def stream_id(self) -> str:
        return self._stream_id

    def buffered_count(self) -> int:
        return len(self._buffer)

    def dropped_count(self) -> int:
        return self._buffer.dropped

    def gap_records(self) -> list[BufferedRecord]:
        return list(self._gaps)

    def pending(self) -> list[BufferedRecord]:
        """Everything awaiting submission, gaps included, in authored order."""

        return sorted(
            [*self._buffer, *self._gaps], key=lambda item: item.sequence
        )

    # ---------------------------------------------------------------- emission

    def emit(
        self, record_type: str, body: Mapping[str, Any], *, action_family: str
    ) -> EmissionResult:
        """Sign locally, then submit or buffer. Never silently discards."""

        if record_type not in CUSTOMER_RECORD_TYPES:
            raise ValueError(
                f"{record_type!r} is not a customer-origin record type; ES-033 "
                "assigns it to the issuer and it cannot be signed with this key"
            )
        # Resolve the policy first: an unconfigured family is a configuration
        # error and must surface before a record is authored, not after.
        policy = self._config.policy_for(action_family)
        buffered, digest = self._author(record_type, body)
        return self._deliver(buffered, digest, policy=policy, action_family=action_family)

    def _author(
        self, record_type: str, body: Mapping[str, Any]
    ) -> tuple[BufferedRecord, str]:
        self._sequence += 1
        envelope = build_envelope(
            record_type=record_type,
            body=body,
            tenant_id=self._config.tenant_id,
            boundary_ref=self._config.boundary_ref,
            collector_id=self._config.collector_id,
            deployment=self._config.deployment,
            stream_id=self._stream_id,
            sequence=self._sequence,
            prev_digest=self._prev_digest,
            source_time=self._clock(),
        )
        buffered, digest = sign_locally(envelope, self._identity)
        self._prev_digest = digest
        return buffered, digest

    def _deliver(
        self,
        buffered: BufferedRecord,
        digest: str,
        *,
        policy: FamilyPolicy,
        action_family: str,
    ) -> EmissionResult:
        try:
            self._transport.submit(buffered.canonical_bytes)
        except TransportUnavailableError:
            self._note_unreachable()
            return self._buffer_or_gap(
                buffered, policy=policy, action_family=action_family
            )
        except RecordRejectedError:
            # Seen and refused: buffering would retry something already judged.
            raise
        self._unreachable_since = None
        return EmissionResult(
            record_id=buffered.record_id,
            record_type=buffered.record_type,
            sequence=buffered.sequence,
            submitted=True,
            buffered=False,
        )

    def _buffer_or_gap(
        self, buffered: BufferedRecord, *, policy: FamilyPolicy, action_family: str
    ) -> EmissionResult:
        if not self._buffer.is_full():
            self._buffer.append(buffered)
            return EmissionResult(
                record_id=buffered.record_id,
                record_type=buffered.record_type,
                sequence=buffered.sequence,
                submitted=False,
                buffered=True,
            )

        # IN-011: the bound is reached. Mark the gap *before* anything is
        # discarded, so the evidence that records were lost is authored while
        # the records still exist.
        self._emit_gap(
            cause="collector_unreachable",
            action_family=action_family,
            actions_during_gap=len(self._buffer) + 1,
        )

        if policy.behaviour == "fail_closed":
            # IN-013: the gap is recorded, then the action is refused. The
            # customer chose this trade-off explicitly at configuration time.
            raise FailClosedError(
                f"action family {action_family!r} is fail_closed and evidence "
                "could not be recorded; a CoverageGap has been signed locally"
            )

        self._buffer.discard_oldest()
        self._buffer.append(buffered)
        return EmissionResult(
            record_id=buffered.record_id,
            record_type=buffered.record_type,
            sequence=buffered.sequence,
            submitted=False,
            buffered=True,
        )

    def _emit_gap(
        self, *, cause: str, action_family: str, actions_during_gap: int | None
    ) -> BufferedRecord:
        now = self._clock()
        self._sequence += 1
        gap, digest = build_coverage_gap(
            identity=self._identity,
            tenant_id=self._config.tenant_id,
            boundary_ref=self._config.boundary_ref,
            collector_id=self._config.collector_id,
            deployment=self._config.deployment,
            stream_id=self._stream_id,
            sequence=self._sequence,
            prev_digest=self._prev_digest,
            gap_start=self._unreachable_since or now,
            gap_end=now,
            affected_scope={
                "action_family": action_family,
                "collector": self._config.collector_id,
                "stream_id": self._stream_id,
            },
            cause=cause,  # type: ignore[arg-type]
            # The client counted these itself, so "known" is honest here.
            exposure="known" if actions_during_gap is not None else "unknown",
            actions_during_gap=actions_during_gap,
        )
        self._prev_digest = digest
        self._gaps.append(gap)
        return gap

    def _note_unreachable(self) -> None:
        if self._unreachable_since is None:
            self._unreachable_since = self._clock()

    # ------------------------------------------------------------------- flush

    def flush(self, *, transport: Transport | None = None) -> list[FlushResult]:
        """Submit buffered records and gap markers with original signatures.

        Ordered by sequence for readability only. EV-07 reconciles by sequence,
        not receipt order (IN-012), so this method must not depend on arrival
        order and does not stop at the first success or failure boundary.
        """

        target = transport or self._transport
        outstanding = self.pending()
        results: list[FlushResult] = []
        unsent: list[BufferedRecord] = []

        for item in outstanding:
            try:
                # The stored bytes go out verbatim: no re-signing, no
                # re-timestamping. What was authored during the outage is what
                # the ledger receives.
                target.submit(item.canonical_bytes)
            except TransportUnavailableError:
                unsent.append(item)
                continue
            results.append(
                FlushResult(
                    record_id=item.record_id,
                    record_type=item.record_type,
                    sequence=item.sequence,
                    canonical_bytes=item.canonical_bytes,
                    accepted=True,
                )
            )

        sent_ids = {result.record_id for result in results}
        self._buffer.drain()
        self._buffer.restore([item for item in unsent if item.record_type != "CoverageGap"])
        self._gaps = [
            gap for gap in self._gaps if gap.record_id not in sent_ids
        ]
        if not unsent:
            self._unreachable_since = None
        return results

    # ------------------------------------------------- typed emission helpers

    def emit_agent_identity(
        self, body: Mapping[str, Any], *, action_family: str
    ) -> EmissionResult:
        return self.emit("AgentIdentity", body, action_family=action_family)

    def emit_action_proposal(
        self, body: Mapping[str, Any], *, action_family: str
    ) -> EmissionResult:
        return self.emit("ActionProposal", body, action_family=action_family)

    def emit_authority_decision(
        self, body: Mapping[str, Any], *, action_family: str
    ) -> EmissionResult:
        return self.emit("AuthorityDecision", body, action_family=action_family)

    def emit_human_review(
        self, body: Mapping[str, Any], *, action_family: str
    ) -> EmissionResult:
        return self.emit("HumanReview", body, action_family=action_family)

    def emit_execution_receipt(
        self, body: Mapping[str, Any], *, action_family: str
    ) -> EmissionResult:
        return self.emit("ExecutionReceipt", body, action_family=action_family)

    def emit_finality_record(
        self, body: Mapping[str, Any], *, action_family: str
    ) -> EmissionResult:
        return self.emit("FinalityRecord", body, action_family=action_family)

    def emit_outcome_record(
        self, body: Mapping[str, Any], *, action_family: str
    ) -> EmissionResult:
        return self.emit("OutcomeRecord", body, action_family=action_family)

    def emit_assurance_boundary(
        self, body: Mapping[str, Any], *, action_family: str
    ) -> EmissionResult:
        return self.emit("AssuranceBoundary", body, action_family=action_family)

    def emit_qualification_record(
        self, body: Mapping[str, Any], *, action_family: str
    ) -> EmissionResult:
        return self.emit("QualificationRecord", body, action_family=action_family)
