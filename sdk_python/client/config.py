"""Per-family fail behaviour and client configuration (IN-009, IN-013).

There is deliberately no global fail-behaviour setting and no default policy
for an unconfigured family. IN-009 makes the choice a property of the action
family, and a global flag with per-family overrides would reintroduce exactly
the thing it forbids: a single switch that silently decides the behaviour of
families nobody thought about. An unconfigured family is a configuration error,
raised at emission, not a family that quietly inherits someone else's risk
appetite.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Literal

FailBehaviour = Literal["fail_open", "fail_closed"]

#: IN-013 requires the operational trade-off to be stated where the choice is
#: made. This is the sentence a configurer must acknowledge verbatim, so it
#: cannot be satisfied by a passing comment in a deployment manifest.
FAIL_CLOSED_TRADE_OFF = (
    "fail_closed: when evidence collection is unavailable, the action is "
    "refused. Our outage becomes your outage for this action family."
)


class ClientConfigurationError(ValueError):
    """The client was configured in a way IN-009 or IN-013 forbids."""


class UnconfiguredFamilyError(ClientConfigurationError):
    """An action family was used with no fail behaviour configured for it."""


@dataclass(frozen=True, slots=True)
class PolicyChange:
    """The audit record IN-009 requires for a fail-behaviour change."""

    action_family: str
    previous: FailBehaviour
    current: FailBehaviour
    changed_by: str
    reason: str
    changed_at: datetime

    def __post_init__(self) -> None:
        if not self.action_family:
            raise ClientConfigurationError(
                "a policy change must name its action family"
            )
        if self.previous == self.current:
            raise ClientConfigurationError("a policy change must change the behaviour")
        _require_attribution(self.changed_by, self.reason)


@dataclass(frozen=True, slots=True)
class FamilyPolicy:
    """One action family's fail behaviour, with its authorising attribution.

    Constructed through :meth:`fail_open` or :meth:`fail_closed` rather than
    positionally, so that selecting fail-closed forces the IN-013 acknowledgement
    through the type system instead of through review.
    """

    behaviour: FailBehaviour
    acknowledged_by: str
    reason: str
    acknowledged_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    trade_off_acknowledged: str | None = None

    def __post_init__(self) -> None:
        _require_attribution(self.acknowledged_by, self.reason)
        if self.behaviour == "fail_closed":
            if self.trade_off_acknowledged != FAIL_CLOSED_TRADE_OFF:
                raise ClientConfigurationError(
                    "IN-013: fail_closed requires the operational trade-off to be "
                    "acknowledged verbatim at configuration time; expected "
                    f"{FAIL_CLOSED_TRADE_OFF!r}"
                )
        elif self.trade_off_acknowledged is not None:
            raise ClientConfigurationError(
                "the fail-closed trade-off cannot be acknowledged for a fail-open family"
            )

    @classmethod
    def fail_open(cls, *, acknowledged_by: str, reason: str) -> FamilyPolicy:
        return cls(
            behaviour="fail_open", acknowledged_by=acknowledged_by, reason=reason
        )

    @classmethod
    def fail_closed(
        cls, *, acknowledged_by: str, reason: str, trade_off_acknowledged: str
    ) -> FamilyPolicy:
        return cls(
            behaviour="fail_closed",
            acknowledged_by=acknowledged_by,
            reason=reason,
            trade_off_acknowledged=trade_off_acknowledged,
        )

    def changed_to(
        self,
        behaviour: FailBehaviour,
        *,
        action_family: str,
        changed_by: str,
        reason: str,
        **kwargs: str,
    ) -> tuple[FamilyPolicy, PolicyChange]:
        """Return the replacement policy *and* the audit record for the change.

        Returning both together is the point: there is no setter that mutates a
        policy in place, so a caller cannot alter fail behaviour without
        producing the IN-009 audit record in the same expression.
        """

        if behaviour == "fail_closed":
            replacement = FamilyPolicy.fail_closed(
                acknowledged_by=changed_by,
                reason=reason,
                trade_off_acknowledged=kwargs.get("trade_off_acknowledged", ""),
            )
        else:
            replacement = FamilyPolicy.fail_open(
                acknowledged_by=changed_by, reason=reason
            )
        change = PolicyChange(
            action_family=action_family,
            previous=self.behaviour,
            current=behaviour,
            changed_by=changed_by,
            reason=reason,
            changed_at=datetime.now(UTC),
        )
        return replacement, change


@dataclass(frozen=True, slots=True)
class ClientConfig:
    """Immutable client configuration. Buffer bound is required, not defaulted."""

    tenant_id: str
    boundary_ref: str
    collector_id: str
    deployment: str
    buffer_bound: int
    families: Mapping[str, FamilyPolicy]
    #: IN-011's second trigger: unreachable for longer than this emits a gap
    #: even if the buffer never fills. EV-09 owns wiring it to a timer.
    silence_threshold_seconds: int | None = None

    def __post_init__(self) -> None:
        for name, value in (
            ("tenant_id", self.tenant_id),
            ("boundary_ref", self.boundary_ref),
            ("collector_id", self.collector_id),
            ("deployment", self.deployment),
        ):
            if not value:
                raise ClientConfigurationError(f"{name} is required")
        if self.buffer_bound < 1:
            raise ClientConfigurationError("buffer_bound must be at least 1")
        if not self.families:
            raise ClientConfigurationError(
                "IN-009: at least one action family must declare a fail behaviour; "
                "there is no global default"
            )
        if self.silence_threshold_seconds is not None and self.silence_threshold_seconds < 1:
            raise ClientConfigurationError("silence_threshold_seconds must be positive")
        object.__setattr__(self, "families", MappingProxyType(dict(self.families)))

    def policy_for(self, action_family: str) -> FamilyPolicy:
        """Return the family's policy, or refuse. Never falls back to a default."""

        try:
            return self.families[action_family]
        except KeyError as exc:
            configured = ", ".join(sorted(self.families)) or "none"
            raise UnconfiguredFamilyError(
                f"action family {action_family!r} has no configured fail behaviour "
                f"(configured: {configured}). IN-009 forbids inferring one."
            ) from exc

    def __iter__(self) -> Iterator[str]:
        return iter(self.families)


def _require_attribution(who: str, reason: str) -> None:
    if not who:
        raise ClientConfigurationError("a fail-behaviour decision requires an author")
    if not reason:
        raise ClientConfigurationError("a fail-behaviour decision requires a reason")
