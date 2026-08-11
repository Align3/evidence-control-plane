"""Configurable signed mock destination connector for EV-13 onward."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from secrets import randbits
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from sdk_python.evidence.canonical import canonical_digest, canonicalize
from sdk_python.evidence.schema import (
    ClocksModel,
    ExternalConfirmationBody,
    ExternalConfirmationRecord,
    JsonObject,
    PopulationRecord,
    PopulationRecordBody,
)
from sdk_python.evidence.signing import sign_record
from services.connectors.base import (
    ActionReference,
    AttributionSurface,
    ConnectorCapabilities,
    ConnectorCapabilityError,
    ConnectorScope,
    DestinationConnector,
    EnumerationWindow,
    ReconciliationStatus,
)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("mock timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _uuid7(value: datetime) -> str:
    """Create a collision-resistant UUIDv7 identifier for mock evidence."""

    milliseconds = int(value.timestamp() * 1_000) & ((1 << 48) - 1)
    tail = randbits(80)
    raw = (milliseconds << 80) | tail
    raw &= ~(0xF << 76)
    raw |= 0x7 << 76
    raw &= ~(0x3 << 62)
    raw |= 0x2 << 62
    return str(UUID(int=raw))


@dataclass(frozen=True, slots=True)
class MockDestinationRecord:
    record_id: str
    action_id: str
    action_family: str
    authoritative_timestamp: datetime
    actor_attribute: str | None = "mock-agent"
    payload: JsonObject | None = None
    reconciliation_status: ReconciliationStatus = "matched"

    def __post_init__(self) -> None:
        if not self.record_id or not self.action_id or not self.action_family:
            raise ValueError("mock records require record, action, and family identifiers")
        if (
            self.authoritative_timestamp.tzinfo is None
            or self.authoritative_timestamp.utcoffset() is None
        ):
            raise ValueError("mock record authoritative_timestamp must be timezone-aware")


@dataclass(frozen=True, slots=True)
class MockConnectorConfig:
    enumeration: bool = True
    confirmation: bool = True
    authoritative_time: bool = True
    settlement_lag: timedelta = timedelta(0)
    attribution_surface: AttributionSurface | None = None
    silent_truncate_to: int | None = None
    result_cap_hit: bool = False
    pagination_complete: bool = True
    observed_settlement_lag: timedelta = timedelta(0)
    duplicate_records: bool = False
    unattributable_records: bool = False

    def __post_init__(self) -> None:
        if self.settlement_lag < timedelta(0):
            raise ValueError("settlement_lag cannot be negative")
        if self.observed_settlement_lag < timedelta(0):
            raise ValueError("observed_settlement_lag cannot be negative")
        if self.silent_truncate_to is not None and self.silent_truncate_to < 0:
            raise ValueError("silent_truncate_to cannot be negative")
        if self.attribution_surface is None:
            surface = (
                AttributionSurface.RECORD_FIELD
                if self.enumeration
                else AttributionSurface.ENUMERATION_UNAVAILABLE
            )
            object.__setattr__(self, "attribution_surface", surface)
        elif self.enumeration:
            if self.attribution_surface is AttributionSurface.ENUMERATION_UNAVAILABLE:
                raise ValueError("enumerating mock requires an attribution surface")
        elif self.attribution_surface is not AttributionSurface.ENUMERATION_UNAVAILABLE:
            raise ValueError(
                "confirmation-only mock must use ENUMERATION_UNAVAILABLE attribution"
            )


class SilentTruncationError(ConnectorCapabilityError):
    """The mocked remote capped results without signalling it."""


class MockCapabilityConfigurationError(ValueError):
    """The mock was configured without either useful capability."""


@dataclass(frozen=True, slots=True)
class _EnvelopeFields:
    record_id: str
    record_type: str
    schema_version: str
    tenant_id: str
    boundary_ref: str
    stream_id: str
    sequence: int
    prev_digest: str | None
    source: JsonObject
    clocks: ClocksModel
    signature: JsonObject


class _MockCore:
    def __init__(
        self,
        *,
        config: MockConnectorConfig,
        records: tuple[MockDestinationRecord, ...],
        destination_system: str,
        tenant_id: str,
        boundary_ref: str,
        key_id: str,
        private_key: Ed25519PrivateKey,
        retrieved_at: datetime,
    ) -> None:
        self._config = config
        self._records = records
        self._destination_system = destination_system
        self._tenant_id = tenant_id
        self._boundary_ref = boundary_ref
        self._key_id = key_id
        self._private_key = private_key
        self._retrieved_at = retrieved_at
        self._sequence = 0
        self._prev_digest: str | None = None

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._private_key.public_key()

    @property
    def key_id(self) -> str:
        return self._key_id

    def capabilities(self) -> ConnectorCapabilities:
        attribution_surface = self._config.attribution_surface
        assert attribution_surface is not None  # normalized in MockConnectorConfig
        return ConnectorCapabilities(
            enumeration=self._config.enumeration,
            confirmation=self._config.confirmation,
            authoritative_time=self._config.authoritative_time,
            settlement_lag=(self._config.settlement_lag if self._config.enumeration else None),
            attribution_surface=attribution_surface,
        )

    def _envelope_fields(
        self,
        record_type: str,
        *,
        authoritative_time: datetime | None,
    ) -> _EnvelopeFields:
        self._sequence += 1
        return _EnvelopeFields(
            record_id=_uuid7(self._retrieved_at),
            record_type=record_type,
            schema_version="0.1.0",
            tenant_id=self._tenant_id,
            boundary_ref=self._boundary_ref,
            stream_id=f"mock:{self._destination_system}",
            sequence=self._sequence,
            prev_digest=self._prev_digest,
            source={
                "connector": "mock",
                "destination_system": self._destination_system,
                "version": "0.1.0",
            },
            clocks=(
                ClocksModel(
                    source_time=_timestamp(self._retrieved_at),
                    authoritative_time=_timestamp(authoritative_time),
                )
                if authoritative_time is not None
                else ClocksModel(source_time=_timestamp(self._retrieved_at))
            ),
            signature={},
        )

    def _sign[RecordT: PopulationRecord | ExternalConfirmationRecord](
        self, record: RecordT
    ) -> RecordT:
        signed = sign_record(record, key_id=self._key_id, private_key=self._private_key)
        # ES-006a commits to the complete previous record, including signature.
        # This is deliberately not the ES-021 signature-excluded signing digest.
        self._prev_digest = canonical_digest(signed)
        return signed

    def _enumerate(self, scope: ConnectorScope, window: EnumerationWindow) -> PopulationRecord:
        if scope.destination_system != self._destination_system:
            raise ValueError("scope names a different destination system")
        matching = [
            record
            for record in self._records
            if record.action_family == scope.action_family
            and window.start <= record.authoritative_timestamp < window.end
        ]
        if self._config.silent_truncate_to is not None:
            cap = self._config.silent_truncate_to
            if len(matching) > cap:
                # The mocked destination did not signal the cap.  The adapter
                # knows its source contract and must turn that silence into a
                # loud failure rather than manufacture a usable denominator.
                raise SilentTruncationError(
                    f"destination silently truncated {len(matching)} records to {cap}"
                )
        returned = list(matching)
        if self._config.duplicate_records and returned:
            returned.append(returned[0])

        identifiers = [record.record_id for record in returned]
        actors = [
            {
                "record_identifier": record.record_id,
                "actor_attribute": (
                    None
                    if self._config.unattributable_records
                    else record.actor_attribute
                ),
            }
            for record in returned
        ]
        observed_ms = self._config.observed_settlement_lag // timedelta(milliseconds=1)
        authoritative = [record.authoritative_timestamp for record in returned]
        has_authoritative_time = self._config.authoritative_time
        body_data: dict[str, object] = {
            "action_family": scope.action_family,
            "destination_system": self._destination_system,
            "window_start": _timestamp(window.start),
            "window_end": _timestamp(window.end),
            "enumeration_query": {
                "scope": dict(scope.parameters),
                "window_start": _timestamp(window.start),
                "window_end": _timestamp(window.end),
            },
            "record_identifiers": identifiers,
            "count": len(identifiers),
            "pagination_complete": self._config.pagination_complete,
            "result_cap_hit": self._config.result_cap_hit,
            "retrieved_at": _timestamp(self._retrieved_at),
            "authoritative_timestamps": {
                "min": (
                    _timestamp(min(authoritative))
                    if authoritative and has_authoritative_time
                    else None
                ),
                "max": (
                    _timestamp(max(authoritative))
                    if authoritative and has_authoritative_time
                    else None
                ),
            },
            # Factual observations only.  Qualification, not the connector,
            # decides whether these observations establish isolation.
            "attribution_observations": actors,
            "observed_settlement_lag_ms": observed_ms,
        }
        # ES-019: the envelope relays the *destination's* timestamp, and ES-030
        # forbids representing it as an observation the collector made.  The
        # newest enumerated record is the only destination instant a population
        # can relay; `retrieved_at` is our own read clock and belongs in
        # source_time alone.  An empty population relays nothing and omits it.
        envelope = self._envelope_fields(
            "PopulationRecord",
            authoritative_time=(
                max(authoritative) if authoritative and has_authoritative_time else None
            ),
        )
        record = PopulationRecord(
            record_id=envelope.record_id,
            record_type="PopulationRecord",
            schema_version=envelope.schema_version,
            tenant_id=envelope.tenant_id,
            boundary_ref=envelope.boundary_ref,
            stream_id=envelope.stream_id,
            sequence=envelope.sequence,
            prev_digest=envelope.prev_digest,
            source=envelope.source,
            clocks=envelope.clocks,
            signature=envelope.signature,
            body=PopulationRecordBody.model_validate(body_data),
        )
        return self._sign(record)

    def _confirm(self, action_ref: ActionReference) -> ExternalConfirmationRecord:
        matched = next(
            (
                record
                for record in self._records
                if record.record_id == action_ref.destination_record_id
                and record.action_id == action_ref.action_id
            ),
            None,
        )
        if matched is None:
            status: ReconciliationStatus = "unmatched_without_evidence"
            timestamp = self._retrieved_at
            payload: object = {"missing": True}
        else:
            status = matched.reconciliation_status
            timestamp = matched.authoritative_timestamp
            payload = matched.payload or {
                "record_id": matched.record_id,
                "action_id": matched.action_id,
            }
        digest = "sha256:" + sha256(canonicalize(payload)).hexdigest()
        envelope = self._envelope_fields(
            "ExternalConfirmation",
            authoritative_time=(timestamp if self._config.authoritative_time else None),
        )
        record = ExternalConfirmationRecord(
            record_id=envelope.record_id,
            record_type="ExternalConfirmation",
            schema_version=envelope.schema_version,
            tenant_id=envelope.tenant_id,
            boundary_ref=envelope.boundary_ref,
            stream_id=envelope.stream_id,
            sequence=envelope.sequence,
            prev_digest=envelope.prev_digest,
            source=envelope.source,
            clocks=envelope.clocks,
            signature=envelope.signature,
            body=ExternalConfirmationBody(
                action_id=action_ref.action_id,
                destination_system=self._destination_system,
                destination_record_id=action_ref.destination_record_id,
                destination_record_digest=digest,
                authoritative_timestamp=_timestamp(timestamp),
                reconciliation_status=status,
                retrieved_at=_timestamp(self._retrieved_at),
            ),
        )
        return self._sign(record)


class MockEnumerationConnector(_MockCore):
    def enumerate(
        self, scope: ConnectorScope, window: EnumerationWindow
    ) -> PopulationRecord:
        return self._enumerate(scope, window)


class MockConfirmationConnector(_MockCore):
    def confirm(self, action_ref: ActionReference) -> ExternalConfirmationRecord:
        return self._confirm(action_ref)


class MockFullConnector(MockEnumerationConnector, MockConfirmationConnector):
    pass


def create_mock_connector(
    *,
    config: MockConnectorConfig | None = None,
    records: tuple[MockDestinationRecord, ...] = (),
    destination_system: str = "mock-destination",
    tenant_id: str = "mock-tenant",
    boundary_ref: str = "mock-boundary",
    key_id: str = "mock-evidence-key",
    private_key: Ed25519PrivateKey | None = None,
    retrieved_at: datetime | None = None,
) -> DestinationConnector:
    """Build a mock whose Python method surface matches its declared capabilities."""

    config = config or MockConnectorConfig()
    if not config.enumeration and not config.confirmation:
        raise MockCapabilityConfigurationError("mock requires at least one capability")
    if private_key is None:
        signing_key = Ed25519PrivateKey.generate()
    elif isinstance(private_key, Ed25519PrivateKey):
        signing_key = private_key
    else:
        raise TypeError("private_key must be an Ed25519PrivateKey")
    effective_retrieved_at = retrieved_at or datetime.now(UTC)
    if config.enumeration and config.confirmation:
        return MockFullConnector(
            config=config,
            records=records,
            destination_system=destination_system,
            tenant_id=tenant_id,
            boundary_ref=boundary_ref,
            key_id=key_id,
            private_key=signing_key,
            retrieved_at=effective_retrieved_at,
        )
    if config.enumeration:
        return MockEnumerationConnector(
            config=config,
            records=records,
            destination_system=destination_system,
            tenant_id=tenant_id,
            boundary_ref=boundary_ref,
            key_id=key_id,
            private_key=signing_key,
            retrieved_at=effective_retrieved_at,
        )
    return MockConfirmationConnector(
        config=config,
        records=records,
        destination_system=destination_system,
        tenant_id=tenant_id,
        boundary_ref=boundary_ref,
        key_id=key_id,
        private_key=signing_key,
        retrieved_at=effective_retrieved_at,
    )
