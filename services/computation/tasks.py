"""Celery scheduling wrapper for EV-14 population enumeration.

Celery controls *when* derived work runs.  It never becomes an evidence
write queue: the task calls ``PopulationService`` synchronously, and its
``acks_late`` acknowledgement can occur only after that call has returned
from the committed PostgreSQL transaction.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, cast

from celery import shared_task  # type: ignore[import-untyped]
from celery.app.task import Task  # type: ignore[import-untyped]
from celery.result import AsyncResult  # type: ignore[import-untyped]

from sdk_python.evidence.schema import JsonValue
from services.connectors import ConnectorScope, DestinationConnector, EnumerationWindow

from .population import (
    PopulationAcknowledgement,
    PopulationRequest,
    PopulationService,
    SettlementLagPendingError,
)


@dataclass(frozen=True, slots=True)
class PopulationTaskRuntime:
    """Worker-local dependencies; private keys and connectors never enter the broker."""

    service: PopulationService
    connectors: Mapping[str, DestinationConnector]


_runtime: PopulationTaskRuntime | None = None


def configure_population_tasks(runtime: PopulationTaskRuntime | None) -> None:
    """Install worker-local dependencies, or clear them during test teardown."""

    global _runtime
    _runtime = runtime


def _timestamp(value: object, *, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be an ISO-8601 timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
    return parsed


def _request(payload: Mapping[str, object]) -> tuple[str, PopulationRequest]:
    connector_id = payload.get("connector_id")
    tenant_id = payload.get("tenant_id")
    boundary_ref = payload.get("boundary_ref")
    action_family = payload.get("action_family")
    destination_system = payload.get("destination_system")
    parameters = payload.get("parameters", {})
    if not isinstance(connector_id, str) or not connector_id:
        raise ValueError("population task requires connector_id")
    if not isinstance(tenant_id, str) or not isinstance(boundary_ref, str):
        raise ValueError("population task requires tenant_id and boundary_ref")
    if not isinstance(action_family, str) or not isinstance(destination_system, str):
        raise ValueError("population task requires action_family and destination_system")
    if not isinstance(parameters, dict) or any(
        not isinstance(key, str) for key in parameters
    ):
        raise ValueError("population task parameters must be a JSON object")
    return connector_id, PopulationRequest(
        tenant_id=tenant_id,
        boundary_ref=boundary_ref,
        scope=ConnectorScope(
            action_family=action_family,
            destination_system=destination_system,
            parameters=cast(Mapping[str, JsonValue], parameters),
        ),
        window=EnumerationWindow(
            start=_timestamp(payload.get("window_start"), label="window_start"),
            end=_timestamp(payload.get("window_end"), label="window_end"),
        ),
    )


def population_task_payload(
    *, request: PopulationRequest, connector_id: str
) -> dict[str, JsonValue]:
    """Serialize only public scheduling inputs; no connector or signing key."""

    if not connector_id:
        raise ValueError("connector_id must be non-empty")
    return {
        "connector_id": connector_id,
        "tenant_id": request.tenant_id,
        "boundary_ref": request.boundary_ref,
        "action_family": request.scope.action_family,
        "destination_system": request.scope.destination_system,
        "parameters": dict(request.scope.parameters),
        "window_start": request.window.start.isoformat(),
        "window_end": request.window.end.isoformat(),
    }


def _result(acknowledgement: PopulationAcknowledgement) -> dict[str, Any]:
    return {
        "population_ref": acknowledgement.population_ref,
        "record_digest": acknowledgement.record_digest,
        "stream_id": acknowledgement.stream_id,
        "sequence": acknowledgement.sequence,
        # Operational alerts make connector failure loud. They do not decide
        # coverage_ratio; EV-16 consumes the signed record for that decision.
        "enumeration_alerts": list(acknowledgement.enumeration_alerts),
        "disagreements": [
            {
                "previous_population_ref": finding.previous_population_ref,
                "current_population_ref": finding.current_population_ref,
                "differing_fields": list(finding.differing_fields),
            }
            for finding in acknowledgement.disagreements
        ],
    }


@shared_task(
    bind=True,
    name="evidence.population.enumerate",
    acks_late=True,
    reject_on_worker_lost=True,
    max_retries=None,
)  # type: ignore[untyped-decorator]
def record_population_task(task: Task, payload: Mapping[str, object]) -> dict[str, Any]:
    """Run one scheduled enumeration and acknowledge only its committed result."""

    runtime = _runtime
    if runtime is None:
        raise RuntimeError("population task runtime is not configured")
    connector_id, request = _request(payload)
    connector = runtime.connectors.get(connector_id)
    if connector is None:
        raise ValueError(f"unknown population connector: {connector_id}")
    try:
        acknowledgement = runtime.service.record_enumeration(request, connector)
    except SettlementLagPendingError as error:
        # ETA is an optimisation, not the control. The service re-checks at
        # execution, so an early delivery or direct invocation still cannot
        # enumerate an unsettled window.
        raise task.retry(eta=error.eligible_at) from error
    return _result(acknowledgement)


def schedule_population_enumeration(
    *, request: PopulationRequest, connector_id: str
) -> AsyncResult[Any]:
    """Enqueue for the qualified eligibility instant, never for immediate execution."""

    runtime = _runtime
    if runtime is None:
        raise RuntimeError("population task runtime is not configured")
    if connector_id not in runtime.connectors:
        raise ValueError(f"unknown population connector: {connector_id}")
    eligible_at = runtime.service.scheduled_for(request)
    return record_population_task.apply_async(
        args=[population_task_payload(request=request, connector_id=connector_id)],
        eta=eligible_at,
    )


__all__ = [
    "PopulationTaskRuntime",
    "configure_population_tasks",
    "population_task_payload",
    "record_population_task",
    "schedule_population_enumeration",
]
