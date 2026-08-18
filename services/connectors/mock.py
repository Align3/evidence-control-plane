"""Configurable signed mock destination connector for EV-13 onward."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256

from sdk_python.evidence.canonical import canonicalize
from sdk_python.evidence.schema import (
    ClocksModel,
    ExternalConfirmationBody,
    JsonObject,
    PopulationRecordBody,
)
from services.connectors.base import (
    ActionReference,
    AttributionSurface,
    ConfirmationAccessPath,
    ConfirmationObservation,
    ConnectorCapabilities,
    ConnectorCapabilityError,
    ConnectorScope,
    DestinationConnector,
    EnumerationWindow,
    PopulationObservation,
    ReconciliationStatus,
)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("mock timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


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
    confirmation_access: ConfirmationAccessPath | None = None
    silent_truncate_to: int | None = None
    result_cap_hit: bool = False
    pagination_complete: bool = True
    observed_settlement_lag: timedelta = timedelta(0)
    duplicate_records: bool = False
    repeated_identifiers: bool = False
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
        if self.confirmation_access is None:
            access = (
                ConfirmationAccessPath.INDEPENDENT
                if self.confirmation
                else ConfirmationAccessPath.NOT_AVAILABLE
            )
            object.__setattr__(self, "confirmation_access", access)
        elif not self.confirmation:
            if self.confirmation_access is not ConfirmationAccessPath.NOT_AVAILABLE:
                raise ValueError(
                    "confirmation access must be not_available when confirmation is absent"
                )
        elif self.confirmation_access is ConfirmationAccessPath.NOT_AVAILABLE:
            raise ValueError(
                "confirmation access must be described when confirmation is available"
            )
        if (
            self.confirmation_access is ConfirmationAccessPath.SHARED_WITH_ENUMERATION
            and not self.enumeration
        ):
            raise ValueError(
                "confirmation access cannot be shared when enumeration is unavailable"
            )


class SilentTruncationError(ConnectorCapabilityError):
    """The mocked remote capped results without signalling it."""


class MockCapabilityConfigurationError(ValueError):
    """The mock was configured without either useful capability."""


class _MockCore:
    def __init__(
        self,
        *,
        config: MockConnectorConfig,
        records: tuple[MockDestinationRecord, ...],
        destination_system: str,
        retrieved_at: datetime,
    ) -> None:
        self._config = config
        self._records = records
        self._destination_system = destination_system
        self._retrieved_at = retrieved_at

    def capabilities(self) -> ConnectorCapabilities:
        attribution_surface = self._config.attribution_surface
        confirmation_access = self._config.confirmation_access
        assert attribution_surface is not None  # normalized in MockConnectorConfig
        assert confirmation_access is not None  # normalized in MockConnectorConfig
        return ConnectorCapabilities(
            enumeration=self._config.enumeration,
            confirmation=self._config.confirmation,
            authoritative_time=self._config.authoritative_time,
            settlement_lag=(self._config.settlement_lag if self._config.enumeration else None),
            attribution_surface=attribution_surface,
            confirmation_access=confirmation_access,
        )

    def _source(self) -> JsonObject:
        return {
            "connector": "mock",
            "destination_system": self._destination_system,
            "version": "0.1.0",
        }

    def _clocks(self, authoritative_time: datetime | None) -> ClocksModel:
        if authoritative_time is None:
            return ClocksModel(source_time=_timestamp(self._retrieved_at))
        return ClocksModel(
            source_time=_timestamp(self._retrieved_at),
            authoritative_time=_timestamp(authoritative_time),
        )

    def _enumerate(
        self, scope: ConnectorScope, window: EnumerationWindow
    ) -> PopulationObservation:
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
            # ES-015 / TM-010: a destination duplicate is two *distinct*
            # destination identifiers carrying identical content -- the same
            # action recorded twice by the destination.  Repeating one
            # identifier instead would break the denominator's set invariant
            # and is malformed enumeration data, not a duplicate; that case is
            # `repeated_identifiers` below, and the two must not be conflated.
            original = returned[0]
            returned.append(replace(original, record_id=f"{original.record_id}-duplicate"))
        if self._config.repeated_identifiers and returned:
            # Malformed enumeration: the same identifier observed twice. A
            # consumer must refuse this population rather than deduplicate it
            # or read it as a destination-side duplicate.
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
        authoritative_time = (
            max(authoritative) if authoritative and has_authoritative_time else None
        )
        return PopulationObservation(
            body=PopulationRecordBody.model_validate(body_data),
            clocks=self._clocks(authoritative_time),
            source=self._source(),
        )

    def _confirm(self, action_ref: ActionReference) -> ConfirmationObservation:
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
        return ConfirmationObservation(
            body=ExternalConfirmationBody(
                action_id=action_ref.action_id,
                destination_system=self._destination_system,
                destination_record_id=action_ref.destination_record_id,
                destination_record_digest=digest,
                authoritative_timestamp=_timestamp(timestamp),
                reconciliation_status=status,
                retrieved_at=_timestamp(self._retrieved_at),
            ),
            clocks=self._clocks(
                timestamp if self._config.authoritative_time else None
            ),
            source=self._source(),
        )


class MockEnumerationConnector(_MockCore):
    def enumerate(
        self, scope: ConnectorScope, window: EnumerationWindow
    ) -> PopulationObservation:
        return self._enumerate(scope, window)


class MockConfirmationConnector(_MockCore):
    def confirm(self, action_ref: ActionReference) -> ConfirmationObservation:
        return self._confirm(action_ref)


class MockFullConnector(MockEnumerationConnector, MockConfirmationConnector):
    pass


def create_mock_connector(
    *,
    config: MockConnectorConfig | None = None,
    records: tuple[MockDestinationRecord, ...] = (),
    destination_system: str = "mock-destination",
    retrieved_at: datetime | None = None,
) -> DestinationConnector:
    """Build a mock whose Python method surface matches its declared capabilities."""

    config = config or MockConnectorConfig()
    if not config.enumeration and not config.confirmation:
        raise MockCapabilityConfigurationError("mock requires at least one capability")
    effective_retrieved_at = retrieved_at or datetime.now(UTC)
    if config.enumeration and config.confirmation:
        return MockFullConnector(
            config=config,
            records=records,
            destination_system=destination_system,
            retrieved_at=effective_retrieved_at,
        )
    if config.enumeration:
        return MockEnumerationConnector(
            config=config,
            records=records,
            destination_system=destination_system,
            retrieved_at=effective_retrieved_at,
        )
    return MockConfirmationConnector(
        config=config,
        records=records,
        destination_system=destination_system,
        retrieved_at=effective_retrieved_at,
    )
