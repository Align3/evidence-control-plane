"""Settlement-gated production of issuer-signed ``PopulationRecord`` evidence.

The connector returns unsigned destination facts.  This service waits for the
qualification's settlement lag, constructs the governed envelope, signs it
with the tenant's registered issuer key, and appends it synchronously.  A
truncated observation is still evidence and is therefore stored faithfully;
whether it can support a ratio is EV-16's decision.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import Connection, RowMapping, select, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from sdk_python.evidence.schema import PopulationRecord, PopulationRecordBody, serialize_record
from sdk_python.evidence.signing import (
    record_signature_bytes,
    record_signing_bytes,
    sign_record,
)
from services.admin.schema import boundaries, boundary_action_families, qualification_records
from services.connectors import (
    ConnectorScope,
    DestinationConnector,
    EnumerationResponseMismatchError,
    EnumerationUnusableError,
    EnumerationWindow,
    PopulationObservation,
    enumerate_for_window_coverage,
)
from services.ingestion.receipts import (
    RegisteredPublicKey,
    parse_canonical_record_wire,
    parse_timestamp,
    verify_record_origin_signature,
)
from services.ledger import (
    TenantEngines,
    digest_bytes,
    digest_ref,
    parse_digest_ref,
    population_partition,
    tenant_connection,
    validate_tenant_id,
)
from services.ledger.schema import keys

SCHEMA_VERSION = "0.1.0"
PRODUCER_VERSION = "0.1.0"


class PopulationServiceError(ValueError):
    """A population observation cannot be safely produced or recorded."""


class SettlementLagPendingError(PopulationServiceError):
    """Enumeration was attempted before the qualified settlement lag elapsed."""

    def __init__(self, *, eligible_at: datetime) -> None:
        super().__init__(
            "enumeration is not eligible until the settlement lag has elapsed at "
            f"{eligible_at.isoformat()}"
        )
        self.eligible_at = eligible_at


class ConnectorQualificationMismatchError(PopulationServiceError):
    """Runtime connector metadata disagrees with the signed qualification."""


class PopulationObservationTimingError(PopulationServiceError):
    """The connector returned a snapshot taken outside the eligible run time."""


class IssuerSignerError(PopulationServiceError):
    """The configured hosted signer is not a usable registered issuer key."""


class PopulationConflictError(PopulationServiceError):
    """The append conflicts with an existing population identity or position."""


class PopulationLedgerUnavailableError(RuntimeError):
    """The signed record could not be durably committed."""


@dataclass(frozen=True, slots=True)
class IssuerSigner:
    """Tenant issuer key used to authenticate the hosted observation."""

    key_id: str
    private_key: Ed25519PrivateKey


@dataclass(frozen=True, slots=True)
class PopulationRequest:
    """One bounded enumeration, with no caller-controlled envelope position."""

    tenant_id: str
    boundary_ref: str
    scope: ConnectorScope
    window: EnumerationWindow

    def __post_init__(self) -> None:
        validate_tenant_id(self.tenant_id)
        if not self.boundary_ref:
            raise ValueError("population request requires a boundary_ref")


@dataclass(frozen=True, slots=True)
class PopulationDisagreement:
    """Two immutable observations of one window disagree on destination facts."""

    previous_population_ref: str
    current_population_ref: str
    differing_fields: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PopulationAcknowledgement:
    """Returned only after the signed record is durably committed."""

    population_ref: str
    record_digest: str
    stream_id: str
    sequence: int
    enumeration_alerts: tuple[str, ...]
    disagreements: tuple[PopulationDisagreement, ...]


@dataclass(frozen=True, slots=True)
class _QualificationBinding:
    settlement_lag: timedelta
    boundary_start: datetime
    boundary_end: datetime
    enumeration_capable: bool


def _uuid7(at: datetime) -> str:
    """Generate a UUIDv7 on Python versions before ``uuid.uuid7`` exists."""

    unix_ms = int(at.timestamp() * 1_000)
    if not 0 <= unix_ms < 1 << 48:  # pragma: no cover - datetime's practical range
        raise ValueError("UUIDv7 timestamp is outside the 48-bit millisecond range")
    random = os.urandom(10)
    value = (
        unix_ms.to_bytes(6, "big")
        + bytes([0x70 | (random[0] & 0x0F), random[1]])
        + bytes([0x80 | (random[2] & 0x3F)])
        + random[3:10]
    )
    return str(uuid.UUID(bytes=value))


def _rfc3339(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise PopulationServiceError("population clock returned a naive timestamp")
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _stream_id(request: PopulationRequest) -> str:
    return ":".join(
        (
            request.tenant_id,
            "population",
            request.boundary_ref,
            request.scope.action_family,
            request.scope.destination_system,
        )
    )


def _binding(connection: Connection, request: PopulationRequest) -> _QualificationBinding:
    row = connection.execute(
        select(
            boundaries.c.window_start,
            boundaries.c.window_end,
            qualification_records.c.settlement_lag_s,
            qualification_records.c.enumeration_capable,
        )
        .select_from(
            boundaries.join(
                boundary_action_families,
                (boundaries.c.tenant_id == boundary_action_families.c.tenant_id)
                & (boundaries.c.boundary_ref == boundary_action_families.c.boundary_ref),
            ).join(
                qualification_records,
                (
                    boundary_action_families.c.tenant_id
                    == qualification_records.c.tenant_id
                )
                & (
                    boundary_action_families.c.qualification_ref
                    == qualification_records.c.qualification_ref
                )
                & (
                    boundary_action_families.c.action_family
                    == qualification_records.c.action_family
                )
                & (
                    boundary_action_families.c.destination_system
                    == qualification_records.c.destination_system
                ),
            )
        )
        .where(
            boundaries.c.tenant_id == request.tenant_id,
            boundaries.c.boundary_ref == request.boundary_ref,
            boundary_action_families.c.action_family == request.scope.action_family,
            boundary_action_families.c.destination_system
            == request.scope.destination_system,
        )
    ).mappings().one_or_none()
    if row is None:
        raise PopulationServiceError(
            "the boundary does not bind this action family and destination to a "
            "qualification"
        )
    if request.window.start < row["window_start"] or request.window.end > row["window_end"]:
        raise PopulationServiceError("enumeration window lies outside the assurance boundary")
    return _QualificationBinding(
        settlement_lag=timedelta(seconds=row["settlement_lag_s"]),
        boundary_start=row["window_start"],
        boundary_end=row["window_end"],
        enumeration_capable=row["enumeration_capable"],
    )


def _validate_connector(
    connector: DestinationConnector, binding: _QualificationBinding
) -> None:
    capabilities = connector.capabilities()
    if not binding.enumeration_capable:
        raise ConnectorQualificationMismatchError(
            "the boundary's qualification does not permit enumeration"
        )
    if not capabilities.enumeration:
        raise ConnectorQualificationMismatchError(
            "the configured connector does not provide the qualified enumeration capability"
        )
    if capabilities.settlement_lag != binding.settlement_lag:
        raise ConnectorQualificationMismatchError(
            "connector settlement lag does not match the signed qualification"
        )


def _validate_observation_time(
    observation: PopulationObservation,
    *,
    eligible_at: datetime,
    observed_at: datetime,
) -> None:
    retrieved_at = parse_timestamp(observation.body.retrieved_at)
    source_time = parse_timestamp(observation.clocks.source_time)
    if retrieved_at != source_time:
        raise PopulationObservationTimingError(
            "body.retrieved_at must equal clocks.source_time for the enumeration read"
        )
    if retrieved_at < eligible_at:
        raise PopulationObservationTimingError(
            "connector returned a snapshot retrieved before settlement eligibility"
        )
    if retrieved_at > observed_at:
        raise PopulationObservationTimingError(
            "connector returned a snapshot retrieved in the future"
        )


def _enumeration_alerts(
    observation: PopulationObservation, *, declared_lag: timedelta
) -> tuple[str, ...]:
    alerts: list[str] = []
    if observation.body.result_cap_hit:
        alerts.append("result_cap_hit")
    if not observation.body.pagination_complete:
        alerts.append("pagination_incomplete")
    observed_ms = (observation.body.model_extra or {}).get("observed_settlement_lag_ms")
    if observed_ms is not None and (
        not isinstance(observed_ms, int) or isinstance(observed_ms, bool)
    ):
        raise PopulationServiceError(
            "observed_settlement_lag_ms must be an integer when present"
        )
    if isinstance(observed_ms, int):
        if timedelta(milliseconds=observed_ms) > declared_lag:
            alerts.append("settlement_lag_exceeded")
    return tuple(alerts)


def _registered_issuer_key(
    connection: Connection,
    *,
    tenant_id: str,
    signer: IssuerSigner,
    signed_at: datetime,
) -> RegisteredPublicKey:
    row = connection.execute(
        select(
            keys.c.public_key,
            keys.c.valid_from,
            keys.c.valid_until,
            keys.c.compromised_from,
        ).where(
            keys.c.tenant_id == tenant_id,
            keys.c.key_id == signer.key_id,
            keys.c.namespace == "issuer",
        )
    ).mappings().one_or_none()
    if row is None:
        raise IssuerSignerError("configured population signer is not a registered issuer key")
    if signed_at < row["valid_from"]:
        raise IssuerSignerError("configured issuer key is not yet valid")
    if row["valid_until"] is not None and signed_at >= row["valid_until"]:
        raise IssuerSignerError("configured issuer key has expired")
    if row["compromised_from"] is not None and signed_at >= row["compromised_from"]:
        raise IssuerSignerError("configured issuer key is compromised")
    public_key = signer.private_key.public_key()
    if public_key.public_bytes_raw() != bytes(row["public_key"]):
        raise IssuerSignerError("configured issuer private key does not match the registry")
    return RegisteredPublicKey(namespace="issuer", public_key=public_key)


def _comparison_body(record: PopulationRecord) -> dict[str, Any]:
    body = record.body.model_dump(mode="json", exclude_unset=True)
    # A repeated read necessarily has a new retrieval instant.  Everything
    # else is destination evidence and a change is surfaced as a finding.
    body.pop("retrieved_at", None)
    return body


def _disagreements(
    previous_rows: list[RowMapping], current: PopulationRecord
) -> tuple[PopulationDisagreement, ...]:
    current_body = _comparison_body(current)
    findings: list[PopulationDisagreement] = []
    for row in previous_rows:
        previous, _ = parse_canonical_record_wire(bytes(row["received_wire_bytes"]))
        if not isinstance(previous, PopulationRecord):  # pragma: no cover - table invariant
            raise PopulationServiceError("population table contains a non-PopulationRecord")
        previous_body = _comparison_body(previous)
        differing = tuple(
            sorted(
                key
                for key in set(previous_body) | set(current_body)
                if previous_body.get(key) != current_body.get(key)
            )
        )
        if differing:
            findings.append(
                PopulationDisagreement(
                    previous_population_ref=str(row["population_ref"]),
                    current_population_ref=current.record_id,
                    differing_fields=differing,
                )
            )
    return tuple(findings)


class PopulationService:
    """Enumerate, issuer-sign, and synchronously append denominator evidence."""

    def __init__(
        self,
        *,
        tenant_engines: TenantEngines,
        issuer_signers: Mapping[str, IssuerSigner],
        clock: Callable[[], datetime] | None = None,
        record_id_factory: Callable[[datetime], str] | None = None,
    ) -> None:
        self._tenant_engines = tenant_engines
        self._issuer_signers = dict(issuer_signers)
        self._clock = clock or (lambda: datetime.now(UTC))
        self._record_id_factory = record_id_factory or _uuid7

    def scheduled_for(self, request: PopulationRequest) -> datetime:
        """Return the first instant at which this window may be enumerated."""

        with tenant_connection(self._tenant_engines, request.tenant_id) as connection:
            binding = _binding(connection, request)
        return request.window.end + binding.settlement_lag

    def record_enumeration(
        self,
        request: PopulationRequest,
        connector: DestinationConnector,
    ) -> PopulationAcknowledgement:
        """Return only after the signed observation has committed synchronously."""

        observed_at = self._clock()
        if observed_at.tzinfo is None or observed_at.utcoffset() is None:
            raise PopulationServiceError("population clock returned a naive timestamp")
        signer = self._issuer_signers.get(request.tenant_id)
        if signer is None:
            raise IssuerSignerError("no population issuer signer configured for tenant")
        with tenant_connection(self._tenant_engines, request.tenant_id) as connection:
            binding = _binding(connection, request)
            # Check custody before reaching the destination. A P2/P3 worker
            # without issuer signing access must fail closed rather than make
            # an observation it cannot authenticate and durably retain.
            _registered_issuer_key(
                connection,
                tenant_id=request.tenant_id,
                signer=signer,
                signed_at=observed_at,
            )
        eligible_at = request.window.end + binding.settlement_lag
        if observed_at < eligible_at:
            raise SettlementLagPendingError(eligible_at=eligible_at)

        _validate_connector(connector, binding)
        gate_error: EnumerationUnusableError | None = None
        try:
            observation = enumerate_for_window_coverage(
                connector, request.scope, request.window
            )
        except EnumerationResponseMismatchError:
            raise
        except EnumerationUnusableError as error:
            # Explicit truncation and observed lag overrun are facts worth
            # retaining. The acknowledgement surfaces operational alerts;
            # EV-16 independently interprets the signed flags for coverage.
            observation = error.population_observation
            gate_error = error

        _validate_observation_time(
            observation, eligible_at=eligible_at, observed_at=observed_at
        )
        alerts = _enumeration_alerts(observation, declared_lag=binding.settlement_lag)
        if gate_error is not None and not alerts:
            # Defensive: every persistable refusal must have a machine-readable
            # reason in the signed body, not only an exception message.
            raise PopulationServiceError(
                "connector refusal had no signed enumeration alert"
            )
        return self._append(
            request=request,
            observation=observation,
            observed_at=observed_at,
            signer=signer,
            enumeration_alerts=alerts,
        )

    def _append(
        self,
        *,
        request: PopulationRequest,
        observation: PopulationObservation,
        observed_at: datetime,
        signer: IssuerSigner,
        enumeration_alerts: tuple[str, ...],
    ) -> PopulationAcknowledgement:
        stream_id = _stream_id(request)
        partition = population_partition(request.tenant_id)
        try:
            with tenant_connection(self._tenant_engines, request.tenant_id) as connection:
                connection.execute(text("SET LOCAL synchronous_commit = on"))
                registered_key = _registered_issuer_key(
                    connection,
                    tenant_id=request.tenant_id,
                    signer=signer,
                    signed_at=observed_at,
                )
                connection.execute(
                    text("SELECT pg_advisory_xact_lock(hashtextextended(:lock, 0))"),
                    {"lock": f"population:{request.tenant_id}:{stream_id}"},
                )
                last = connection.execute(
                    select(
                        partition.c.sequence,
                        partition.c.received_wire_bytes,
                    )
                    .where(partition.c.stream_id == stream_id)
                    .order_by(partition.c.sequence.desc())
                    .limit(1)
                ).mappings().one_or_none()
                sequence = 1 if last is None else int(last["sequence"]) + 1
                prev_digest = (
                    None
                    if last is None
                    else digest_ref(digest_bytes(bytes(last["received_wire_bytes"])))
                )
                unsigned = PopulationRecord(
                    record_id=self._record_id_factory(observed_at),
                    record_type="PopulationRecord",
                    schema_version=SCHEMA_VERSION,
                    tenant_id=request.tenant_id,
                    boundary_ref=request.boundary_ref,
                    stream_id=stream_id,
                    sequence=sequence,
                    prev_digest=prev_digest,
                    source={
                        "implementation": "population-service",
                        "version": PRODUCER_VERSION,
                        "connector": observation.source,
                    },
                    clocks=observation.clocks,
                    body=observation.body,
                    signature={},
                )
                record = sign_record(
                    unsigned,
                    key_id=signer.key_id,
                    private_key=signer.private_key,
                )
                signing_bytes = record_signing_bytes(record)
                wire_bytes = serialize_record(record)
                verify_record_origin_signature(
                    record,
                    verification_keys={signer.key_id: registered_key},
                    signing_bytes=signing_bytes,
                )
                previous = connection.execute(
                    select(partition.c.population_ref, partition.c.received_wire_bytes).where(
                        partition.c.action_family == request.scope.action_family,
                        partition.c.destination_system == request.scope.destination_system,
                        partition.c.window_start == request.window.start,
                        partition.c.window_end == request.window.end,
                    )
                ).mappings().all()
                findings = _disagreements(list(previous), record)
                body: PopulationRecordBody = record.body
                connection.execute(
                    partition.insert(),
                    {
                        "population_ref": record.record_id,
                        "tenant_id": record.tenant_id,
                        "boundary_ref": record.boundary_ref,
                        "stream_id": record.stream_id,
                        "sequence": record.sequence,
                        "prev_digest": (
                            None
                            if record.prev_digest is None
                            else parse_digest_ref(record.prev_digest)
                        ),
                        "record_digest": digest_bytes(signing_bytes),
                        "action_family": body.action_family,
                        "destination_system": body.destination_system,
                        "window_start": parse_timestamp(body.window_start),
                        "window_end": parse_timestamp(body.window_end),
                        "enumeration_query": body.enumeration_query,
                        "identifier_digest": (
                            None
                            if body.identifier_digest is None
                            else parse_digest_ref(body.identifier_digest)
                        ),
                        "identifiers": body.record_identifiers,
                        "count": body.count,
                        "pagination_complete": body.pagination_complete,
                        "result_cap_hit": body.result_cap_hit,
                        "retrieved_at": parse_timestamp(body.retrieved_at),
                        "authoritative_timestamps": body.authoritative_timestamps,
                        "source_time": parse_timestamp(record.clocks.source_time),
                        "authoritative_time": (
                            None
                            if record.clocks.authoritative_time is None
                            else parse_timestamp(record.clocks.authoritative_time)
                        ),
                        "key_id": signer.key_id,
                        "key_namespace": "issuer",
                        "signature": record_signature_bytes(record),
                        "canonical_bytes": signing_bytes,
                        "received_wire_bytes": wire_bytes,
                    },
                )
        except PopulationServiceError:
            raise
        except IntegrityError as exc:
            raise PopulationConflictError(
                "population record conflicts with the append-only ledger"
            ) from exc
        except SQLAlchemyError as exc:
            raise PopulationLedgerUnavailableError(
                "population task was not acknowledged because durable commit failed"
            ) from exc

        return PopulationAcknowledgement(
            population_ref=record.record_id,
            record_digest=digest_ref(sha256(wire_bytes).digest()),
            stream_id=record.stream_id,
            sequence=record.sequence,
            enumeration_alerts=enumeration_alerts,
            disagreements=findings,
        )


__all__ = [
    "ConnectorQualificationMismatchError",
    "IssuerSigner",
    "IssuerSignerError",
    "PopulationAcknowledgement",
    "PopulationConflictError",
    "PopulationDisagreement",
    "PopulationLedgerUnavailableError",
    "PopulationObservationTimingError",
    "PopulationRequest",
    "PopulationService",
    "PopulationServiceError",
    "SettlementLagPendingError",
]
