"""Generate the EV-11 honest-contrast fixture pair.

Two complete runs of one pipeline. The only thing that differs between them is
**when the human review happens**: before the action is dispatched, or after
the destination has already committed it. Everything else -- the code path, the
records emitted, the connector, the coverage computation, the issuance -- is
identical, and neither run is told which outcome it is supposed to produce.

That is what makes the pair a *contrast* rather than an illustration. The late
run does not set a flag saying "count me as ineffective"; it performs the
review after the ExecutionReceipt exists, records the action state it actually
observed at that moment, and lets EV-11's evaluator reach its own verdict. If
the evaluator were wrong, this tool would emit a fixture claiming effective
oversight over a review that arrived too late, and the fixture would say so.

**Provenance, stated plainly.** The destination is the committed mock connector
(`services/connectors/mock.py`), not a live org: this pair demonstrates
oversight effectiveness, which is a property of the review timeline, not of the
destination. The Salesforce fixtures under `tests/fixtures/salesforce-live*`
remain the live-destination artifacts. The qualification is built to the shape
recorded in `docs/qualifications/salesforce-record-create.md` -- the committed
pattern -- with mock-destination values in the fields that describe the
destination. The reviewer identity is synthetic. Every signature, receipt,
ledger write, evaluation, and attestation is real and reproducible.

Requires `DATABASE_URL`, `EVIDENCE_SIGNING_KEY_PATH`, `ISSUER_SIGNING_KEY_PATH`.
Networked only to Postgres. Never runs in CI.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select, text

from sdk_python.client import (
    FAIL_CLOSED_TRADE_OFF,
    ClientConfig,
    EvidenceClient,
    FamilyPolicy,
    SigningIdentity,
)
from sdk_python.evidence.bundle import assemble_bundle
from sdk_python.evidence.canonical import canonicalize
from sdk_python.evidence.schema import (
    AssuranceBoundaryRecord,
    ExternalConfirmationRecord,
    HumanReviewRecord,
    PopulationRecord,
    QualificationRecord,
    RecordEnvelope,
    parse_record,
)
from sdk_python.evidence.signing import sign_record, verify_attestation_signatures
from sdk_python.evidence.versions import (
    require_published_methodology_version,
    require_published_schema_version,
)
from services.admin import record_boundary, record_qualification
from services.attestation import (
    AttestationRequest,
    AttestationSource,
    EvidenceSigner,
    IssuerIdentity,
    IssuerSigner,
    RelyingParty,
    issue_attestation,
)
from services.computation.coverage import (
    CoverageBoundary,
    TimeInterval,
    compute_coverage,
)
from services.computation.oversight import evaluate_oversight
from services.computation.population import (
    IssuerSigner as PopulationIssuerSigner,
)
from services.computation.population import (
    PopulationRequest,
    PopulationService,
)
from services.computation.reconciliation import reconcile
from services.connectors import ActionReference, ConnectorScope, EnumerationWindow
from services.connectors.mock import (
    MockConnectorConfig,
    MockDestinationRecord,
    create_mock_connector,
)
from services.ingestion.api import create_app
from services.ingestion.receipts import (
    RegisteredPublicKey,
    create_ingestion_receipt,
    verify_record_origin_signature,
)
from services.ingestion.service import IngestionService, IssuerSigningKey
from services.ledger import (
    LedgerConfig,
    TenantEngines,
    evidence_partition,
    migrator_engine,
    population_partition,
    provision_tenant,
    tenant_connection,
)
from tools.generate_salesforce_live_fixtures import (
    _load_ed25519,
    _required_env,
    _timestamp,
    _uuid7,
    _write_json,
    derive_action_evidence,
    read_ledger_evidence,
    read_registered_scope,
)

SCHEMA_VERSION = require_published_schema_version("1.0.0")
METHODOLOGY_VERSION = require_published_methodology_version("1.0.0")
VERIFIER_VERSION = "0.1.0"
GENERATOR_VERSION = "0.1.0"

ACTION_FAMILY = "refund.issue"
DESTINATION_SYSTEM = "mock-refunds"
#: Settlement lag zero, so the enumeration window is eligible the moment it
#: closes. A demo that sleeps for five minutes is a demo nobody runs, and the
#: lag is a property of the destination rather than of the oversight claim.
SETTLEMENT_LAG = timedelta(0)

ReviewPoint = Literal["before_dispatch", "after_commitment"]


@dataclass(frozen=True, slots=True)
class Variant:
    """One run's identity. Nothing here names an expected verdict."""

    name: str
    tenant_prefix: str
    review_point: ReviewPoint


@dataclass(frozen=True, slots=True)
class Run:
    """One execution of a variant, in its own tenant.

    Each run provisions a fresh tenant rather than re-entering one. The ledger
    is append-only by construction -- EV-06 puts immutability in the database,
    not in a convention -- so a rerun cannot clear the previous run's evidence,
    and re-entering a tenant would either fork a stream at an occupied position
    or bind a second collector to a key already bound to the first. Both are
    the ledger refusing to let a demo overwrite history, which is correct, and
    a fixture regenerator that needs history overwritten is asking for the
    wrong thing.
    """

    variant: Variant
    token: str

    @property
    def name(self) -> str:
        return self.variant.name

    @property
    def review_point(self) -> ReviewPoint:
        return self.variant.review_point

    @property
    def tenant_id(self) -> str:
        return f"{self.variant.tenant_prefix}_{self.token}"

    @property
    def boundary_ref(self) -> str:
        return f"{self.tenant_id}:refund-issue:1"

    @property
    def evidence_key_id(self) -> str:
        return f"{self.tenant_id}-evidence-dev-1"

    @property
    def issuer_key_id(self) -> str:
        return f"{self.tenant_id}-issuer-dev-1"

    @property
    def collector_id(self) -> str:
        return f"{self.tenant_id}-collector-1"


VARIANTS = (
    Variant(
        name="oversight-reviewed-in-time",
        tenant_prefix="oversight_intime",
        review_point="before_dispatch",
    ),
    Variant(
        name="oversight-reviewed-late",
        tenant_prefix="oversight_late",
        review_point="after_commitment",
    ),
)


def _ms(value: datetime) -> datetime:
    """Truncate to milliseconds, the precision the record timestamps carry."""

    return value.replace(microsecond=(value.microsecond // 1_000) * 1_000)


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _canonical_digest(value: Any) -> str:
    return _digest(canonicalize(value))


def _unsigned_bytes_and_signature(record: Any) -> tuple[bytes, bytes]:
    """The exact bytes the key covered, and the raw signature (ES-021)."""

    payload = record.model_dump(mode="json", exclude_unset=True)
    signature = payload.pop("signature")
    canonical = canonicalize(payload)
    raw = base64.urlsafe_b64decode(signature["sig"] + "=" * (-len(signature["sig"]) % 4))
    return canonical, raw


def _envelope(
    variant: Run,
    *,
    record_type: str,
    record_id: str,
    stream_id: str,
    body: Any,
    clocks: Any,
    source: Any,
) -> dict[str, Any]:
    return {
        "record_id": record_id,
        "record_type": record_type,
        "schema_version": SCHEMA_VERSION,
        "tenant_id": variant.tenant_id,
        "boundary_ref": variant.boundary_ref,
        "stream_id": stream_id,
        "sequence": 1,
        "prev_digest": None,
        "source": source,
        "clocks": clocks,
        "body": body,
        "signature": {},
    }


def _generator_source(connector_source: Any = None) -> dict[str, Any]:
    source: dict[str, Any] = {
        "implementation": "oversight-contrast-fixture-generator",
        "version": GENERATOR_VERSION,
    }
    if connector_source is not None:
        source["connector"] = connector_source
    return source


# --------------------------------------------------------------------------
# Constitutive records, to the committed qualification pattern
# --------------------------------------------------------------------------


def build_qualification_record(
    variant: Run,
    *,
    issued_at: datetime,
    evidence_key: Ed25519PrivateKey,
    qualified_at: datetime,
    window_start: datetime,
    window_end: datetime,
) -> QualificationRecord:
    """The signed §5.2 record, shaped by the committed qualification pattern.

    `docs/qualifications/salesforce-record-create.md` is the committed template
    for what a qualification has to establish: how enumeration is scoped, how
    the acting identity is isolated, whether confirmation is independent, and
    what the assigned class rests on. Those fields are answered here for the
    mock destination, and `class_evidence.probe` names this generator rather
    than a live probe, because no live probe was run.
    """

    unsigned = QualificationRecord.model_validate(
        _envelope(
            variant,
            record_type="QualificationRecord",
            record_id=_uuid7(issued_at),
            stream_id=f"{variant.tenant_id}:evidence:mock:qualification",
            clocks={"source_time": _timestamp(issued_at)},
            source=_generator_source(),
            body={
                "action_family": ACTION_FAMILY,
                "destination_system": DESTINATION_SYSTEM,
                "enumeration": {
                    "api": "mock destination enumeration",
                    "scoping": "actor attribute plus half-open window",
                    "ordering": "authoritative_timestamp ASC, record_id ASC",
                    "pagination": "single batch",
                    "result_cap": None,
                    "capable": True,
                },
                "identity_isolation": {
                    "attribute": "actor_attribute",
                    # The mock exposes the acting identity as a record field it
                    # does not let a caller forge, so isolation is exact by
                    # construction -- which is a property of the mock, not a
                    # finding about a real destination.
                    "vendor_settable": False,
                    "conditional_on": None,
                    "partial_isolation_notes": (
                        "exact: the mock destination attributes every record to "
                        "the acting principal and offers no override"
                    ),
                },
                "confirmation": {
                    "api": "mock destination retrieve by record id",
                    "independent_of_enumeration": True,
                    "capable": True,
                },
                "temporal": {
                    "authoritative_timestamp_source": "mock destination commit time",
                    "measured_settlement_lag_s": int(SETTLEMENT_LAG.total_seconds()),
                },
                "retention_period": "P180D",
                "mutability": {"deletion_possible": False, "trace_available": True},
                "assigned_class": "C1",
                "class_evidence": {
                    "probe": "tools/generate_oversight_contrast_fixtures.py",
                    "condition": "mock destination; no live org was probed",
                },
                "trial": {
                    "window_reconciled": (
                        f"{_timestamp(window_start)}/{_timestamp(window_end)}"
                    ),
                    "match_rate": "1.0000",
                },
                "qualified_at": _timestamp(qualified_at),
                "revalidation_cadence": "PT1H",
            },
        )
    )
    return sign_record(unsigned, key_id=variant.evidence_key_id, private_key=evidence_key)


def build_boundary_record(
    variant: Run,
    *,
    qualification: QualificationRecord,
    issued_at: datetime,
    evidence_key: Ed25519PrivateKey,
    window_start: datetime,
    window_end: datetime,
) -> AssuranceBoundaryRecord:
    """The signed §5.1 record naming the scope the attestation claims within."""

    unsigned = AssuranceBoundaryRecord.model_validate(
        _envelope(
            variant,
            record_type="AssuranceBoundary",
            record_id=_uuid7(issued_at),
            stream_id=f"{variant.tenant_id}:evidence:mock:boundary",
            clocks={"source_time": _timestamp(issued_at)},
            source=_generator_source(),
            body={
                "boundary_version": "1",
                "tenant": variant.tenant_id,
                "deployment": "demo",
                "agent_identities": ["mock-agent"],
                "action_families": [
                    {
                        "action_family": ACTION_FAMILY,
                        "destination_system": DESTINATION_SYSTEM,
                        "qualification_ref": qualification.record_id,
                    }
                ],
                "destination_systems": [DESTINATION_SYSTEM],
                "enforcement_points": ["connector"],
                "policy_refs": ["demo-only:no-reliance"],
                "window_start": _timestamp(window_start),
                "window_end": _timestamp(window_end),
                "collection_modes": ["inline"],
                "fail_behaviour": {ACTION_FAMILY: "fail_closed"},
                "qualification_refs": [qualification.record_id],
            },
        )
    )
    return sign_record(unsigned, key_id=variant.evidence_key_id, private_key=evidence_key)


def register_scope(
    variant: Run,
    *,
    evidence_key: Ed25519PrivateKey,
    issuer_key: Ed25519PrivateKey,
    declared_from: datetime,
    declared_until: datetime,
) -> None:
    """Provision the tenant and declare the scope the evidence will cite.

    DM-017's foreign key means an evidence row cannot name a boundary that was
    never declared, so this runs before the agent emits anything.
    """

    engine = migrator_engine(LedgerConfig.from_env())
    now = datetime.now(UTC)
    try:
        with engine.begin() as connection:
            provision_tenant(
                connection,
                tenant_id=variant.tenant_id,
                name=f"Oversight demo ({variant.review_point})",
                deployment_profile="p1_hosted",
                key_custody="client_held",
                evidence_region="eu-west-1",
            )
            connection.execute(
                text(
                    "INSERT INTO collectors (collector_id, tenant_id, implementation,"
                    " version, mode, expected_cadence_s, registered_at)"
                    " VALUES (:cid, :tid, 'sdk-python', '0.1.0', 'checkpoint', 60, now())"
                    " ON CONFLICT (collector_id) DO NOTHING"
                ),
                {"cid": variant.collector_id, "tid": variant.tenant_id},
            )
            connection.execute(
                text(
                    "INSERT INTO keys (key_id, tenant_id, collector_id, namespace,"
                    " public_key, custody, valid_from)"
                    " VALUES (:kid, :tid, :cid, 'evidence', :pk, 'client_held', now())"
                    " ON CONFLICT (key_id) DO NOTHING"
                ),
                {
                    "kid": variant.evidence_key_id,
                    "tid": variant.tenant_id,
                    "cid": variant.collector_id,
                    "pk": evidence_key.public_key().public_bytes_raw(),
                },
            )
            connection.execute(
                text(
                    "INSERT INTO keys (key_id, tenant_id, namespace, public_key,"
                    " custody, valid_from)"
                    " VALUES (:kid, :tid, 'issuer', :pk, 'client_held', now())"
                    " ON CONFLICT (key_id) DO NOTHING"
                ),
                {
                    "kid": variant.issuer_key_id,
                    "tid": variant.tenant_id,
                    "pk": issuer_key.public_key().public_bytes_raw(),
                },
            )
            if connection.execute(
                text("SELECT 1 FROM boundaries WHERE boundary_ref = :ref"),
                {"ref": variant.boundary_ref},
            ).scalar_one_or_none() is not None:
                print(f"  scope already declared: {variant.boundary_ref}")
                return

            qualification = build_qualification_record(
                variant,
                issued_at=now,
                evidence_key=evidence_key,
                # When the qualification was actually performed: now. Choosing
                # an instant before the window would answer CM-003's question
                # for it.
                qualified_at=now,
                window_start=declared_from,
                window_end=declared_until,
            )
            canonical, signature = _unsigned_bytes_and_signature(qualification)
            record_qualification(
                connection,
                record=qualification,
                canonical_bytes=canonical,
                signature=signature,
                receipt=create_ingestion_receipt(
                    qualification,
                    ingest_time=datetime.now(UTC),
                    issuer_key_id=variant.issuer_key_id,
                    issuer_private_key=issuer_key,
                ),
            )
            boundary = build_boundary_record(
                variant,
                qualification=qualification,
                issued_at=now,
                evidence_key=evidence_key,
                window_start=declared_from,
                window_end=declared_until,
            )
            canonical, signature = _unsigned_bytes_and_signature(boundary)
            record_boundary(
                connection,
                record=boundary,
                canonical_bytes=canonical,
                signature=signature,
                receipt=create_ingestion_receipt(
                    boundary,
                    ingest_time=datetime.now(UTC),
                    issuer_key_id=variant.issuer_key_id,
                    issuer_private_key=issuer_key,
                ),
            )
            print(f"  scope declared: {variant.boundary_ref}")
    finally:
        engine.dispose()


# --------------------------------------------------------------------------
# The EV-08 client, delivering into EV-07 ingestion in-process
# --------------------------------------------------------------------------


async def _asgi_post(app: Any, path: str, body: bytes) -> tuple[int, bytes]:
    """POST to an ASGI app in-process. No socket, same code path."""

    sent = False
    status = 500
    chunks: list[bytes] = []

    async def receive() -> dict[str, Any]:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        nonlocal status
        if message["type"] == "http.response.start":
            status = int(message["status"])
        elif message["type"] == "http.response.body":
            chunks.append(bytes(message.get("body", b"")))

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.1"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
        ],
        "client": ("127.0.0.1", 0),
        "server": ("127.0.0.1", 80),
    }
    await app(scope, receive, send)
    return status, b"".join(chunks)


def build_client(
    variant: Run, *, evidence_key: Ed25519PrivateKey, issuer_key: Ed25519PrivateKey
) -> EvidenceClient:
    """An EV-08 client delivering into EV-07's ingestion, in-process."""

    service = IngestionService(
        tenant_engines=TenantEngines(LedgerConfig.from_env()),
        issuer_signers={
            variant.tenant_id: IssuerSigningKey(
                key_id=variant.issuer_key_id, private_key=issuer_key
            )
        },
    )
    app = create_app(service)

    class InProcessTransport:
        def submit(self, wire: bytes) -> None:
            status, payload = asyncio.run(_asgi_post(app, "/v1/evidence", wire))
            if status >= 400:
                raise RuntimeError(
                    f"ingestion refused the record: {status} {payload.decode()[:300]}"
                )

    return EvidenceClient(
        config=ClientConfig(
            tenant_id=variant.tenant_id,
            boundary_ref=variant.boundary_ref,
            collector_id=variant.collector_id,
            deployment="demo",
            buffer_bound=16,
            families={
                ACTION_FAMILY: FamilyPolicy.fail_closed(
                    acknowledged_by="ev11-fixture-maintainer",
                    reason=(
                        "an oversight fixture must not be built on evidence "
                        "ingestion refused"
                    ),
                    trade_off_acknowledged=FAIL_CLOSED_TRADE_OFF,
                ),
            },
        ),
        identity=SigningIdentity(key_id=variant.evidence_key_id, private_key=evidence_key),
        transport=InProcessTransport(),
    )


# --------------------------------------------------------------------------
# One run of the timeline
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ActionTimeline:
    """What actually happened, in the order it happened."""

    action_id: str
    destination_record_id: str
    proposed_at: datetime
    committed_at: datetime
    reviewed_at: datetime
    #: The state the action was observed to be in when the review was taken.
    #: Derived from this timeline, never asserted by the caller.
    state_at_review: str
    review_record_id: str


def run_timeline(variant: Run, client: EvidenceClient) -> ActionTimeline:
    """Emit one action's evidence in real time, reviewing it at the configured point.

    The state recorded on the review is read from where the timeline has got
    to, not chosen: before dispatch the action is `proposed`, and once the
    destination has returned a commit it is `committed`. A run configured to
    review late therefore records `committed` because that is what was true,
    which is the only reason the fixture it produces is worth anything.
    """

    action_id = str(uuid.uuid4())
    destination_record_id = f"mock-{uuid.uuid4().hex[:12]}"
    state = "proposed"

    parameters = {"amount": "42.00", "currency": "GBP", "reason": "duplicate charge"}
    proposed_at = datetime.now(UTC)
    client.emit_action_proposal(
        {
            "action_family": ACTION_FAMILY,
            "action_id": action_id,
            "tool": "refunds.issue",
            "parameters_digest": _canonical_digest(parameters),
            "purpose": "return a duplicate charge to the customer",
            "target_ref": "customer:demo-1",
            "risk_class": "requires_human_review",
            "proposed_at": _timestamp(proposed_at),
        },
        action_family=ACTION_FAMILY,
    )

    def take_review(at_state: str) -> tuple[datetime, str]:
        """Render the review surface, then record the decision taken on it.

        ES-013: `evidence_shown` digests the bytes that were rendered, so the
        payload is built once and both rendered and digested from that one
        object. A digest computed from a separate reconstruction would be the
        server-side claim ES-013 refuses to let pass unlabelled.
        """

        rendered = {
            "action_id": action_id,
            "action_family": ACTION_FAMILY,
            "parameters": parameters,
            "state": at_state,
        }
        shown_bytes = canonicalize(rendered)
        decided_at = datetime.now(UTC)
        result = client.emit_human_review(
            {
                "action_id": action_id,
                "reviewer_identity": "reviewer:demo-1",
                "reviewer_authority": {
                    "role": "refunds-approver",
                    "limit": {"amount": "500.00", "currency": "GBP"},
                },
                "surface": {
                    "implementation": "oversight-contrast-fixture-generator",
                    "rendered": "canonical JSON, digested from the rendered bytes",
                },
                "evidence_shown": _digest(shown_bytes),
                "evidence_shown_refs": [f"action:{action_id}"],
                "options_offered": ["approve", "deny", "modify", "escalate"],
                "time_available_ms": 600_000,
                "time_taken_ms": 4_000,
                "decision": "approve",
                "modifications": None,
                "action_state_at_review": at_state,
                "decided_at": _timestamp(decided_at),
            },
            action_family=ACTION_FAMILY,
        )
        return decided_at, result.record_id

    reviewed_at: datetime | None = None
    review_record_id: str | None = None
    state_at_review: str | None = None
    if variant.review_point == "before_dispatch":
        state_at_review = state
        reviewed_at, review_record_id = take_review(state)

    # The action runs. The mock destination commits it and returns the bytes
    # the receipt binds; nothing here invents a response.
    dispatched_at = datetime.now(UTC)
    response = json.dumps(
        {"id": destination_record_id, "status": "committed"},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    committed_at = datetime.now(UTC)
    state = "committed"
    client.emit_execution_receipt(
        {
            "action_id": action_id,
            "dispatch_attempt": 1,
            "connector_identity": DESTINATION_SYSTEM,
            "connector_version": "mock-0.1.0",
            "destination_response_digest": _digest(response),
            "destination_record_ref": destination_record_id,
            "status": "committed",
            "dispatched_at": _timestamp(dispatched_at),
            "responded_at": _timestamp(committed_at),
        },
        action_family=ACTION_FAMILY,
    )

    if variant.review_point == "after_commitment":
        state_at_review = state
        reviewed_at, review_record_id = take_review(state)

    if reviewed_at is None or review_record_id is None or state_at_review is None:
        raise RuntimeError(f"no review was taken for variant {variant.name!r}")
    return ActionTimeline(
        action_id=action_id,
        destination_record_id=destination_record_id,
        proposed_at=proposed_at,
        committed_at=committed_at,
        reviewed_at=reviewed_at,
        state_at_review=state_at_review,
        review_record_id=review_record_id,
    )


def read_human_reviews(variant: Run) -> tuple[HumanReviewRecord, ...]:
    """Read the reviews back out of the ledger, as a hosted evaluator would.

    The evaluator is handed what the ledger holds, not the objects this process
    happens to have in memory. A fixture whose oversight verdict was computed
    over the tool's own variables would demonstrate the tool, not the ledger.
    """

    partition = evidence_partition(variant.tenant_id)
    engines = TenantEngines(LedgerConfig.from_env())
    try:
        with tenant_connection(engines, variant.tenant_id) as connection:
            rows = connection.execute(
                select(partition.c.received_wire_bytes)
                .where(partition.c.record_type == "HumanReview")
                .order_by(partition.c.stream_id, partition.c.sequence)
            ).scalars().all()
    finally:
        engines.dispose()
    reviews = tuple(parse_record(bytes(row)) for row in rows)
    for review in reviews:
        if not isinstance(review, HumanReviewRecord):  # pragma: no cover - filtered above
            raise RuntimeError("evidence partition returned a non-HumanReview record")
    return reviews  # type: ignore[return-value]


def read_population_record(variant: Run, population_ref: str) -> PopulationRecord:
    table = population_partition(variant.tenant_id)
    engines = TenantEngines(LedgerConfig.from_env())
    try:
        with tenant_connection(engines, variant.tenant_id) as connection:
            wire = connection.execute(
                select(table.c.received_wire_bytes).where(
                    table.c.population_ref == population_ref
                )
            ).scalar_one()
    finally:
        engines.dispose()
    record = parse_record(bytes(wire))
    if not isinstance(record, PopulationRecord):  # pragma: no cover - table invariant
        raise RuntimeError("population partition returned a non-PopulationRecord")
    return record


def build_confirmation_record(
    variant: Run,
    observation: Any,
    *,
    issued_at: datetime,
    issuer_key: Ed25519PrivateKey,
) -> ExternalConfirmationRecord:
    unsigned = ExternalConfirmationRecord.model_validate(
        _envelope(
            variant,
            record_type="ExternalConfirmation",
            record_id=_uuid7(issued_at),
            stream_id=f"{variant.tenant_id}:issuer:mock:confirmation",
            clocks=observation.clocks.model_dump(mode="json", exclude_unset=True),
            source=_generator_source(observation.source),
            body=observation.body.model_dump(mode="json", exclude_unset=True),
        )
    )
    return sign_record(unsigned, key_id=variant.issuer_key_id, private_key=issuer_key)


def generate(variant: Run, *, output_root: Path) -> dict[str, Any]:
    """Run one variant end to end and write its fixture set."""

    evidence_key = _load_ed25519("EVIDENCE_SIGNING_KEY_PATH")
    issuer_key = _load_ed25519("ISSUER_SIGNING_KEY_PATH")

    declared_from = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    register_scope(
        variant,
        evidence_key=evidence_key,
        issuer_key=issuer_key,
        declared_from=declared_from,
        declared_until=declared_from + timedelta(days=30),
    )

    # The window opens after the scope exists. CM-003 asks whether the
    # qualification was in force at the window's start, and a window that opens
    # before the declaration answers that question dishonestly.
    window_start = _ms(datetime.now(UTC))
    client = build_client(variant, evidence_key=evidence_key, issuer_key=issuer_key)
    timeline = run_timeline(variant, client)
    # The window closes when the work finished, not at a round number chosen
    # afterwards: a window whose end has not yet arrived is not eligible for
    # enumeration, and one padded past the work is a window the evidence does
    # not cover.
    window_end = _ms(datetime.now(UTC))

    scope = ConnectorScope(ACTION_FAMILY, DESTINATION_SYSTEM)
    window = EnumerationWindow(start=window_start, end=window_end)
    connector = create_mock_connector(
        config=MockConnectorConfig(settlement_lag=SETTLEMENT_LAG),
        records=(
            MockDestinationRecord(
                record_id=timeline.destination_record_id,
                action_id=timeline.action_id,
                action_family=ACTION_FAMILY,
                authoritative_timestamp=timeline.committed_at,
            ),
        ),
        destination_system=DESTINATION_SYSTEM,
        retrieved_at=datetime.now(UTC),
    )
    population_service = PopulationService(
        tenant_engines=TenantEngines(LedgerConfig.from_env()),
        issuer_signers={
            variant.tenant_id: PopulationIssuerSigner(variant.issuer_key_id, issuer_key)
        },
    )
    acknowledgement = population_service.record_enumeration(
        PopulationRequest(
            tenant_id=variant.tenant_id,
            boundary_ref=variant.boundary_ref,
            scope=scope,
            window=window,
        ),
        connector,
    )
    population = read_population_record(variant, acknowledgement.population_ref)

    generated_at = datetime.now(UTC)
    confirmation = build_confirmation_record(
        variant,
        connector.confirm(
            ActionReference(
                action_id=timeline.action_id,
                destination_record_id=timeline.destination_record_id,
            )
        ),
        issued_at=generated_at,
        issuer_key=issuer_key,
    )
    confirmations = (confirmation,)

    ledger_records, ledger_provenance = read_ledger_evidence(variant.tenant_id)
    evidence_records = tuple(item.record for item in ledger_records)
    reconciliation_results = reconcile(population, evidence_records, confirmations)
    action_evidence = derive_action_evidence(
        reconciliation_results=reconciliation_results,
        confirmations=confirmations,
        ledger_records=ledger_records,
    )
    registered = read_registered_scope(
        tenant_id=variant.tenant_id,
        name="refund-issue",
        action_family=ACTION_FAMILY,
        destination_system=DESTINATION_SYSTEM,
    )
    coverage = compute_coverage(
        reconciliation_results=reconciliation_results,
        population=population,
        boundary=CoverageBoundary(
            boundary_ref=variant.boundary_ref,
            window=TimeInterval(window_start, window_end),
            clock_skew_threshold_ms=5_000,
        ),
        qualification_history=registered.qualifications,
        action_evidence=action_evidence,
    )

    reviews = read_human_reviews(variant)
    # Reported alongside the attestation so a reader can see the verdict the
    # evaluator reached, not only the assertions that survived it.
    report = evaluate_oversight(
        reviews,
        required_action_ids=(timeline.action_id,),
        tenant_id=variant.tenant_id,
        boundary_ref=variant.boundary_ref,
        window_start=window_start,
        window_end=window_end,
    )

    request = AttestationRequest(
        tenant_id=variant.tenant_id,
        record_id=_uuid7(generated_at + timedelta(milliseconds=4)),
        stream_id=f"{variant.tenant_id}:attestation:oversight-contrast",
        sequence=1,
        prev_digest=None,
        source=AttestationSource(
            service="oversight-contrast-fixture-generator", version=GENERATOR_VERSION
        ),
        coverage=coverage,
        action_families=(ACTION_FAMILY,),
        operated_action_families=(ACTION_FAMILY,),
        # The action required human review, so its id is declared here whether
        # or not a review arrived in time. Deriving this from the reviews held
        # would make the A-07/A-08 claims self-confirming.
        review_action_ids=(timeline.action_id,),
        human_reviews=reviews,
        outcome_action_ids=(),
        authoritative_source=None,
        outcome_records=(),
        methodology_version=METHODOLOGY_VERSION,
        verifier_version=VERIFIER_VERSION,
        verification_status="self_computed",
        relying_parties=(
            RelyingParty(name="demo fixture evaluator", relationship="evaluation"),
        ),
        validity_from=generated_at,
        validity_until=generated_at + timedelta(days=30),
        liability_ref="demo-only:no-reliance",
        issued_at=generated_at,
        issuer=IssuerIdentity(
            name="Evidence Control Plane demo", identifier=variant.tenant_id
        ),
    )
    engine = migrator_engine(LedgerConfig.from_env())
    try:
        with engine.begin() as connection:
            attestation = issue_attestation(
                request,
                connection=connection,
                evidence_signer=EvidenceSigner(variant.evidence_key_id, evidence_key),
                issuer_signer=IssuerSigner(variant.issuer_key_id, issuer_key),
            )
    finally:
        engine.dispose()

    verification_keys = {
        variant.evidence_key_id: RegisteredPublicKey(
            namespace="evidence", public_key=evidence_key.public_key()
        ),
        variant.issuer_key_id: RegisteredPublicKey(
            namespace="issuer", public_key=issuer_key.public_key()
        ),
    }
    for record in (
        registered.qualification_record,
        registered.boundary_record,
        population,
        *confirmations,
        *evidence_records,
    ):
        verify_record_origin_signature(record, verification_keys=verification_keys)
    verify_attestation_signatures(
        attestation.record,
        evidence_public_keys={variant.evidence_key_id: evidence_key.public_key()},
        issuer_public_keys={variant.issuer_key_id: issuer_key.public_key()},
    )

    bundle_records: tuple[RecordEnvelope, ...] = (
        registered.boundary_record,
        registered.qualification_record,
        population,
        *confirmations,
        *evidence_records,
        attestation.record,
    )
    bundle_bytes = assemble_bundle(bundle_records)

    output_dir = output_root / variant.name
    output_dir.mkdir(parents=True, exist_ok=True)
    _write_json(
        output_dir / "01-timeline.json",
        {
            "review_point": variant.review_point,
            "action_id": timeline.action_id,
            "destination_record_id": timeline.destination_record_id,
            "proposed_at": _timestamp(timeline.proposed_at),
            "committed_at": _timestamp(timeline.committed_at),
            "reviewed_at": _timestamp(timeline.reviewed_at),
            "action_state_at_review": timeline.state_at_review,
            "review_record_id": timeline.review_record_id,
            "ledger_provenance": ledger_provenance,
        },
    )
    _write_json(
        output_dir / "02-human-reviews.json",
        [review.model_dump(mode="json", exclude_unset=True) for review in reviews],
    )
    _write_json(
        output_dir / "03-oversight-report.json",
        {
            "required_action_ids": list(report.required_action_ids),
            "reviewed_action_ids": list(report.reviewed_action_ids),
            "effective_action_ids": list(report.effective_action_ids),
            "missing_action_ids": list(report.missing_action_ids),
            "evaluations": [
                {
                    "record_id": item.record_id,
                    "action_id": item.action_id,
                    "effective": item.effective,
                    "reason": item.reason.value,
                }
                for item in report.evaluations
            ],
        },
    )
    _write_json(
        output_dir / "04-population-record.json",
        population.model_dump(mode="json", exclude_unset=True),
    )
    _write_json(
        output_dir / "05-external-confirmations.json",
        [item.model_dump(mode="json", exclude_unset=True) for item in confirmations],
    )
    _write_json(
        output_dir / "06-evidence-records.json",
        [item.model_dump(mode="json", exclude_unset=True) for item in evidence_records],
    )
    _write_json(
        output_dir / "07-qualification-record.json",
        registered.qualification_record.model_dump(mode="json", exclude_unset=True),
    )
    _write_json(
        output_dir / "08-assurance-boundary.json",
        registered.boundary_record.model_dump(mode="json", exclude_unset=True),
    )
    _write_json(
        output_dir / "09-attestation-window.json",
        attestation.record.model_dump(mode="json", exclude_unset=True),
    )
    (output_dir / "10-bundle.json").write_bytes(bundle_bytes)

    body = attestation.record.body
    assertion_ids = [item["assertion_id"] for item in body.assertions]
    summary = {
        "variant": variant.name,
        "tenant_id": variant.tenant_id,
        "review_point": variant.review_point,
        "action_state_at_review": timeline.state_at_review,
        "assertion_ids": assertion_ids,
        "effective_action_ids": list(report.effective_action_ids),
        "oversight_exclusions": [
            item
            for item in body.exclusions
            if str(item.get("kind", "")).startswith("human_review")
        ],
        "coverage_ratio": body.coverage_ratio,
        "counts": body.counts,
    }
    _write_json(output_dir / "00-summary.json", summary)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("tests/fixtures"),
        help="directory to write both fixture sets into",
    )
    args = parser.parse_args()
    _required_env("DATABASE_URL")

    # One token for the pair, so both runs are visibly from the same session.
    token = uuid.uuid4().hex[:8]
    summaries = []
    for variant in VARIANTS:
        print(f"{variant.name}:")
        summaries.append(generate(Run(variant, token), output_root=args.output_root))
        print(f"  written: {args.output_root / variant.name}")

    print()
    for summary in summaries:
        print(
            f"  {summary['variant']}: state_at_review={summary['action_state_at_review']} "
            f"assertions={summary['assertion_ids']} "
            f"effective={summary['effective_action_ids']} "
            f"exclusions={[item.get('reason') for item in summary['oversight_exclusions']]}"
        )


if __name__ == "__main__":
    main()
