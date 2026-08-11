"""Destination connector contracts and the coverage-safety boundary.

Enumeration and confirmation deliberately live in separate protocols.  Code
that has only a ``DestinationConnector`` cannot call either operation until it
has performed the corresponding runtime capability check.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Literal, Protocol, runtime_checkable

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


@dataclass(frozen=True, slots=True)
class ConnectorScope:
    action_family: str
    destination_system: str
    parameters: dict[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.action_family or not self.destination_system:
            raise ValueError("scope requires an action family and destination system")
        object.__setattr__(self, "parameters", MappingProxyType(dict(self.parameters)))


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


def require_window_enumerator(connector: DestinationConnector) -> EnumerationConnector:
    """Return the typed enumeration capability or refuse a coverage request.

    Both the declaration and the structural method are checked.  A future
    connector cannot unlock coverage merely by returning ``enumeration=True``.
    Conversely, an accidentally present method cannot override an explicit
    ``enumeration=False`` declaration.
    """

    capabilities = connector.capabilities()
    if not capabilities.enumeration:
        raise WindowCoverageUnavailableError(
            "window-level coverage requires destination enumeration"
        )
    if not isinstance(connector, EnumerationConnector):
        raise ConnectorContractError(
            "connector reports enumeration but does not implement enumerate()"
        )
    return connector


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
    the evidence and EV-16 can state why a ratio was withheld.
    """

    enumerator = require_window_enumerator(connector)
    result = enumerator.enumerate(scope, window)
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

    capabilities = connector.capabilities()
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


type ReconciliationStatus = Literal[
    "matched",
    "unmatched_with_evidence",
    "unmatched_without_evidence",
    "duplicate",
    "ambiguous",
    "out_of_scope",
]
