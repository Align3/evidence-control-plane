"""Destination connector contracts and the coverage-safety boundary.

Enumeration and confirmation deliberately live in separate protocols.  Code
that has only a ``DestinationConnector`` cannot call either operation until it
has performed the corresponding runtime capability check.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Literal, Never, Protocol, runtime_checkable

from sdk_python.evidence.schema import (
    ExternalConfirmationRecord,
    JsonValue,
    PopulationRecord,
)


class AttributionSurface(StrEnum):
    """What the destination API exposes, not an isolation qualification.

    These values distinguish the denominator-probe failure shapes.  In
    particular, ``CALLER_SETTABLE_FIELD`` does not become trustworthy merely
    because it is returned inline, and ``SEPARATE_SOURCE`` does not imply that
    the second source is complete or retained long enough.
    """

    RECORD_FIELD = "record_field"
    CALLER_SETTABLE_FIELD = "caller_settable_field"
    SEPARATE_SOURCE = "separate_source"
    NOT_RECORDED = "not_recorded"
    ENUMERATION_UNAVAILABLE = "enumeration_unavailable"


@dataclass(frozen=True, slots=True)
class ConnectorCapabilities:
    enumeration: bool
    confirmation: bool
    authoritative_time: bool
    settlement_lag: timedelta | None
    attribution_surface: AttributionSurface

    def __post_init__(self) -> None:
        if self.settlement_lag is not None and self.settlement_lag < timedelta(0):
            raise ValueError("settlement_lag cannot be negative")
        if not self.enumeration:
            if self.settlement_lag is not None:
                raise ValueError("settlement_lag requires enumeration capability")
            if self.attribution_surface is not AttributionSurface.ENUMERATION_UNAVAILABLE:
                raise ValueError(
                    "an enumeration-unavailable connector cannot describe an "
                    "enumeration attribution surface"
                )
        elif self.attribution_surface is AttributionSurface.ENUMERATION_UNAVAILABLE:
            raise ValueError(
                "an enumerating connector must describe the observed attribution surface"
            )


def _immutable_error(*_args: object, **_kwargs: object) -> Never:
    raise TypeError("connector scope parameters are immutable")


class _FrozenJsonList(list[JsonValue]):
    """A JSON-compatible list that cannot change after construction."""

    def __init__(self, values: list[JsonValue]) -> None:
        list.__init__(self, (_freeze_json(value) for value in values))

    append = clear = extend = insert = remove = reverse = sort = _immutable_error
    pop = __setitem__ = __delitem__ = __iadd__ = __imul__ = _immutable_error

    def __hash__(self) -> int:  # type: ignore[override]
        return hash(tuple(self))


class FrozenJsonObject(dict[str, JsonValue]):
    """Deeply immutable while remaining serializable by ordinary JSON tools."""

    def __init__(self, values: Mapping[str, JsonValue] | None = None) -> None:
        dict.__init__(
            self,
            {
                key: _freeze_json(value)
                for key, value in (values.items() if values is not None else ())
            },
        )

    clear = pop = popitem = setdefault = update = _immutable_error
    __setitem__ = __delitem__ = __ior__ = _immutable_error

    def __hash__(self) -> int:  # type: ignore[override]
        return hash(frozenset(self.items()))


def _freeze_json(value: JsonValue) -> JsonValue:
    if isinstance(value, dict):
        return FrozenJsonObject(value)
    if isinstance(value, list):
        return _FrozenJsonList(value)
    return value


@dataclass(frozen=True, slots=True)
class ConnectorScope:
    action_family: str
    destination_system: str
    parameters: Mapping[str, JsonValue] = field(default_factory=FrozenJsonObject)

    def __post_init__(self) -> None:
        if not self.action_family or not self.destination_system:
            raise ValueError("scope requires an action family and destination system")
        object.__setattr__(self, "parameters", FrozenJsonObject(self.parameters))


@dataclass(frozen=True, slots=True)
class EnumerationWindow:
    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        if self.start.tzinfo is None or self.start.utcoffset() is None:
            raise ValueError("window start must be timezone-aware")
        if self.end.tzinfo is None or self.end.utcoffset() is None:
            raise ValueError("window end must be timezone-aware")
        if self.start >= self.end:
            raise ValueError("window start must precede window end")


@dataclass(frozen=True, slots=True)
class ActionReference:
    action_id: str
    destination_record_id: str

    def __post_init__(self) -> None:
        if not self.action_id or not self.destination_record_id:
            raise ValueError("an action reference requires both identifiers")


@runtime_checkable
class DestinationConnector(Protocol):
    """Metadata common to every connector; no operational capability implied."""

    def capabilities(self) -> ConnectorCapabilities: ...


@runtime_checkable
class EnumerationConnector(DestinationConnector, Protocol):
    """A connector whose static surface includes denominator enumeration."""

    def enumerate(
        self, scope: ConnectorScope, window: EnumerationWindow
    ) -> PopulationRecord: ...


@runtime_checkable
class ConfirmationConnector(DestinationConnector, Protocol):
    """A connector whose static surface includes one-action confirmation."""

    def confirm(self, action_ref: ActionReference) -> ExternalConfirmationRecord: ...


class ConnectorCapabilityError(RuntimeError):
    """A requested operation is unavailable or capability metadata is dishonest."""


class WindowCoverageUnavailableError(ConnectorCapabilityError):
    """No denominator enumeration is available for a window-level claim."""


class ConnectorContractError(ConnectorCapabilityError):
    """A connector's reported capability and implemented surface disagree."""


class EnumerationUnusableError(ConnectorCapabilityError):
    """An enumeration result cannot be used as a denominator."""

    def __init__(self, message: str, *, population_record: PopulationRecord) -> None:
        super().__init__(message)
        self.population_record = population_record


class SettlementLagExceededError(EnumerationUnusableError):
    """Observed visibility lag exceeded the connector's declared bound."""


class EnumerationResponseMismatchError(EnumerationUnusableError):
    """The returned population does not describe the requested query."""


def _require_window_enumerator(
    connector: DestinationConnector,
    capabilities: ConnectorCapabilities,
) -> EnumerationConnector:
    if not capabilities.enumeration:
        raise WindowCoverageUnavailableError(
            "window-level coverage requires destination enumeration"
        )
    if not isinstance(connector, EnumerationConnector):
        raise ConnectorContractError(
            "connector reports enumeration but does not implement enumerate()"
        )
    return connector


def require_window_enumerator(connector: DestinationConnector) -> EnumerationConnector:
    """Return the typed enumeration capability or refuse a coverage request.

    Both the declaration and the structural method are checked.  A future
    connector cannot unlock coverage merely by returning ``enumeration=True``.
    Conversely, an accidentally present method cannot override an explicit
    ``enumeration=False`` declaration.
    """

    return _require_window_enumerator(connector, connector.capabilities())


def require_confirmer(connector: DestinationConnector) -> ConfirmationConnector:
    capabilities = connector.capabilities()
    if not capabilities.confirmation:
        raise ConnectorCapabilityError("connector does not support confirmation")
    if not isinstance(connector, ConfirmationConnector):
        raise ConnectorContractError(
            "connector reports confirmation but does not implement confirm()"
        )
    return connector


def enumerate_for_window_coverage(
    connector: DestinationConnector,
    scope: ConnectorScope,
    window: EnumerationWindow,
) -> PopulationRecord:
    """Enumerate and reject every explicitly unusable denominator signal.

    The rejected signed record is retained on the exception so EV-14 can store
    the evidence and EV-16 can state why a ratio was withheld.  A bound, empty
    enumeration is valid: zero is a possible authoritative population, while
    qualification is responsible for establishing that the query itself is an
    adequate source.  Exact request/response binding prevents a population
    that is empty merely because it answered a different query from passing.
    """

    capabilities = connector.capabilities()
    enumerator = _require_window_enumerator(connector, capabilities)
    if not capabilities.authoritative_time:
        raise WindowCoverageUnavailableError(
            "window-level coverage requires destination-authoritative time"
        )
    result = enumerator.enumerate(scope, window)

    mismatches: list[str] = []
    if result.body.action_family != scope.action_family:
        mismatches.append("action_family")
    if result.body.destination_system != scope.destination_system:
        mismatches.append("destination_system")
    if not _timestamp_matches(result.body.window_start, window.start):
        mismatches.append("window_start")
    if not _timestamp_matches(result.body.window_end, window.end):
        mismatches.append("window_end")
    query = result.body.enumeration_query
    if query.get("scope") != dict(scope.parameters):
        mismatches.append("enumeration_query.scope")
    if not _timestamp_matches(query.get("window_start"), window.start):
        mismatches.append("enumeration_query.window_start")
    if not _timestamp_matches(query.get("window_end"), window.end):
        mismatches.append("enumeration_query.window_end")
    if mismatches:
        raise EnumerationResponseMismatchError(
            "enumeration response does not match the request: " + ", ".join(mismatches),
            population_record=result,
        )

    identifiers = result.body.record_identifiers
    if identifiers is not None and result.body.count != len(identifiers):
        raise EnumerationResponseMismatchError(
            "enumeration count does not match the inline record identifiers",
            population_record=result,
        )
    if result.clocks.authoritative_time is None:
        raise EnumerationResponseMismatchError(
            "connector declared authoritative time but omitted it from the record clocks",
            population_record=result,
        )

    timestamp_range = result.body.authoritative_timestamps
    minimum = timestamp_range.get("min")
    maximum = timestamp_range.get("max")
    if result.body.count == 0:
        if minimum is not None or maximum is not None:
            raise EnumerationResponseMismatchError(
                "empty enumeration must have a null authoritative timestamp range",
                population_record=result,
            )
    elif (
        not isinstance(minimum, str)
        or not isinstance(maximum, str)
        or not _timestamp_within_window(minimum, window)
        or not _timestamp_within_window(maximum, window)
        or _parse_timestamp(minimum) > _parse_timestamp(maximum)
    ):
        raise EnumerationResponseMismatchError(
            "enumeration authoritative timestamp range is absent, inverted, or outside the window",
            population_record=result,
        )
    if result.body.result_cap_hit:
        raise EnumerationUnusableError(
            "enumeration result cap was hit; the denominator is truncated",
            population_record=result,
        )
    if not result.body.pagination_complete:
        raise EnumerationUnusableError(
            "enumeration pagination is incomplete; the denominator is truncated",
            population_record=result,
        )

    observed_ms = (result.body.model_extra or {}).get("observed_settlement_lag_ms")
    if observed_ms is not None:
        if not isinstance(observed_ms, int) or isinstance(observed_ms, bool):
            raise ConnectorContractError(
                "observed_settlement_lag_ms must be an integer"
            )
        declared = capabilities.settlement_lag
        if declared is None:
            raise ConnectorContractError(
                "enumeration result reports settlement lag without a declared bound"
            )
        if timedelta(milliseconds=observed_ms) > declared:
            raise SettlementLagExceededError(
                "observed settlement lag exceeded the connector's declared bound",
                population_record=result,
            )
    return result


def _parse_timestamp(value: str) -> datetime:
    """Parse a schema-validated timestamp for request/response instant matching."""

    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def _timestamp_matches(value: JsonValue, expected: datetime) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return _parse_timestamp(value) == expected.astimezone(UTC)
    except ValueError:
        return False


def _timestamp_within_window(value: str, window: EnumerationWindow) -> bool:
    try:
        parsed = _parse_timestamp(value)
    except ValueError:
        return False
    return window.start.astimezone(UTC) <= parsed < window.end.astimezone(UTC)


type ReconciliationStatus = Literal[
    "matched",
    "unmatched_with_evidence",
    "unmatched_without_evidence",
    "duplicate",
    "ambiguous",
    "out_of_scope",
]
