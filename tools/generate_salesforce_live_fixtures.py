"""Generate signed demo fixtures from the qualified live Salesforce probe org.

This is an explicit, networked maintenance command. It never runs in CI and
never writes Salesforce data. The caller supplies Salesforce JWT settings, the
demo evidence/issuer Ed25519 key paths, and a `DATABASE_URL` naming the
evidence ledger, through environment variables.

**Nothing here asserts a pipeline result.** Every record this tool writes is
produced by the shipping entry point that owns it -- EV-15 `reconcile`, EV-16
`compute_coverage`, EV-17 `issue_attestation` -- over inputs read from the
live org and the real ledger. In particular the matched count is whatever the
ledger and the reconciler produce together; it is never supplied as a
constant.

That property is the whole point of the artifact. A fixture that reports 0/10
because the evidence side was handed an empty tuple is indistinguishable, on
its face, from one that reports 0/10 because the ledger genuinely holds no
matching evidence. The first proves nothing and the second proves the claim
the product exists to make, so the empty case has to arrive by the same route
as the matched case. `--require-matches` exists so a run that is *supposed* to
demonstrate a match fails loudly rather than quietly emitting an honest zero.

The same code path therefore serves both fixture sets: the honest-zero case
over an empty ledger, and the honest-match case over a ledger holding records
emitted through the EV-08 SDK path. Neither branches on its expected outcome.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select

from sdk_python.evidence.bundle import assemble_bundle
from sdk_python.evidence.canonical import canonicalize
from sdk_python.evidence.schema import (
    ActionProposalRecord,
    AssuranceBoundaryRecord,
    EvidenceRecord,
    ExecutionReceiptRecord,
    ExternalConfirmationRecord,
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
from services.admin.boundary import (
    BoundaryVersion,
    boundary_versions,
)
from services.admin.qualification import (
    Qualification,
    qualification_history,
)
from services.admin.schema import boundaries, qualification_records
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
    ActionEvidence,
    CoverageBoundary,
    TimeInterval,
    compute_coverage,
)
from services.computation.reconciliation import reconcile
from services.connectors import (
    ActionReference,
    ConnectorScope,
    EnumerationWindow,
    FileRs256Signer,
    SalesforceConnector,
    SalesforceConnectorConfig,
    SalesforceJwtBearerAuth,
    SalesforceJwtBearerConfig,
    SalesforceRestClient,
    confirm_salesforce_identity,
    exchange_jwt_bearer,
)
from services.ingestion.receipts import (
    RegisteredPublicKey,
    verify_record_origin_signature,
)
from services.ledger import (
    LedgerConfig,
    TenantEngines,
    evidence_partition,
    migrator_engine,
    tenant_connection,
)

# Underscored, not hyphenated: the ledger derives a partition name from the
# tenant id and rejects anything outside the SQL identifier grammar. A tenant
# the records name but the ledger cannot address is not a tenant.
TENANT_ID = "salesforce_probe"
BOUNDARY_REF = "salesforce_probe:case-create:1"
WINDOW_START = datetime(2026, 8, 18, 8, 55, tzinfo=UTC)
WINDOW_END = datetime(2026, 8, 18, 8, 56, tzinfo=UTC)
QUALIFIED_AT = datetime(2026, 8, 18, 8, 50, tzinfo=UTC)
EVIDENCE_KEY_ID = "salesforce-live-evidence-dev-1"
ISSUER_KEY_ID = "salesforce-live-issuer-dev-1"

# ES-035 and CM-025 enumerate what a verifier is obliged to support. These are
# checked against the registries at import rather than carried as constants a
# reader has to trust: a fixture signed under an unpublished version is refused
# by every conformant verifier, which is a slow and confusing way to discover a
# typo.
SCHEMA_VERSION = require_published_schema_version("1.0.0")
METHODOLOGY_VERSION = require_published_methodology_version("1.0.0")
VERIFIER_VERSION = "0.1.0"
GENERATOR_VERSION = "0.2.0"

# The evidence types that carry RC-001's stable relation to a destination
# record. Reconciliation reads no other type, so querying for more would widen
# the ledger read without widening what it can establish.
LEDGER_EVIDENCE_TYPES = ("ActionProposal", "ExecutionReceipt")


class LedgerUnavailableError(RuntimeError):
    """The evidence ledger could not be read.

    Raised rather than degrading to an empty evidence set. An unreachable
    ledger and a ledger holding nothing produce the same coverage number and
    mean entirely different things, and only one of them is a claim this tool
    is entitled to publish.
    """


def _parse_instant(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise argparse.ArgumentTypeError("window bounds require an explicit offset")
    return parsed.astimezone(UTC)


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def _load_ed25519(name: str) -> Ed25519PrivateKey:
    path = Path(_required_env(name)).expanduser().resolve(strict=True)
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise RuntimeError(f"{name} must point to an Ed25519 private key")
    return key


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _uuid7(at: datetime) -> str:
    unix_ms = int(at.timestamp() * 1_000)
    random = os.urandom(10)
    value = (
        unix_ms.to_bytes(6, "big")
        + bytes([0x70 | (random[0] & 0x0F), random[1]])
        + bytes([0x80 | (random[2] & 0x3F)])
        + random[3:10]
    )
    return str(uuid.UUID(bytes=value))


def _model_json(record: RecordEnvelope) -> dict[str, Any]:
    return record.model_dump(mode="json", exclude_unset=True)


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _public_key_b64(private_key: Ed25519PrivateKey) -> str:
    return base64.urlsafe_b64encode(
        private_key.public_key().public_bytes_raw()
    ).rstrip(b"=").decode("ascii")


def _envelope(
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
        "tenant_id": TENANT_ID,
        "boundary_ref": BOUNDARY_REF,
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
        "implementation": "salesforce-live-fixture-generator",
        "version": GENERATOR_VERSION,
    }
    if connector_source is not None:
        source["connector"] = connector_source
    return source


# --------------------------------------------------------------------------
# The evidence ledger -- genuinely read, never assumed
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LedgerEvidence:
    """One evidence record as the ledger holds it, with its ES-030 receipt.

    The wire bytes and the receipt travel together because neither is
    sufficient alone: the record says what the customer signed, the receipt
    says which complete artifact this service observed, and a relying party
    checking the match needs both to redo the reconciliation rather than
    take the generator's word for its result.
    """

    record: EvidenceRecord
    wire: bytes
    receipt_key_id: str | None
    receipt_signature: bytes | None
    receipt_canonical_bytes: bytes | None

    def to_json(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "record": self.record.model_dump(mode="json", exclude_unset=True),
            "received_wire_utf8_hex": self.wire.hex(),
        }
        if (
            self.receipt_key_id is not None
            and self.receipt_signature is not None
            and self.receipt_canonical_bytes is not None
        ):
            payload["ingestion_receipt"] = {
                "key_id": self.receipt_key_id,
                "signature_base64url": base64.urlsafe_b64encode(
                    self.receipt_signature
                ).rstrip(b"=").decode("ascii"),
                "canonical_utf8_hex": self.receipt_canonical_bytes.hex(),
            }
        return payload


def read_ledger_evidence(
    tenant_id: str,
) -> tuple[tuple[LedgerEvidence, ...], dict[str, Any]]:
    """Read every reconcilable evidence record this tenant holds.

    Returns the records -- with the wire bytes and ES-030 receipts that make
    them checkable by someone who does not trust this tool -- and a provenance
    block describing the read itself, so a reader of the fixture can tell an
    empty ledger from an unread one. The provenance is what makes a zero
    checkable; without it the number is just an assertion with better manners.
    """

    config = LedgerConfig.from_env()
    partition = evidence_partition(tenant_id)
    engines = TenantEngines(config)
    try:
        with tenant_connection(engines, tenant_id) as connection:
            rows = (
                connection.execute(
                    select(
                        partition.c.received_wire_bytes,
                        partition.c.receipt_key_id,
                        partition.c.receipt_signature,
                        partition.c.receipt_canonical_bytes,
                    )
                    .where(partition.c.record_type.in_(LEDGER_EVIDENCE_TYPES))
                    .order_by(partition.c.stream_id, partition.c.sequence)
                )
                .mappings()
                .all()
            )
    except Exception as error:  # noqa: BLE001 -- re-raised as a refusal below
        raise LedgerUnavailableError(
            f"evidence ledger read failed for tenant {tenant_id!r}: {error}"
        ) from error
    finally:
        engines.dispose()

    evidence = tuple(
        LedgerEvidence(
            record=parse_record(bytes(row["received_wire_bytes"])),
            wire=bytes(row["received_wire_bytes"]),
            receipt_key_id=row["receipt_key_id"],
            receipt_signature=(
                bytes(row["receipt_signature"])
                if row["receipt_signature"] is not None
                else None
            ),
            receipt_canonical_bytes=(
                bytes(row["receipt_canonical_bytes"])
                if row["receipt_canonical_bytes"] is not None
                else None
            ),
        )
        for row in rows
    )
    provenance = {
        "queried": True,
        "tenant_id": tenant_id,
        "partition": partition.name,
        "record_types": list(LEDGER_EVIDENCE_TYPES),
        "rows_returned": len(evidence),
        "action_proposals": sum(
            isinstance(item.record, ActionProposalRecord) for item in evidence
        ),
        "execution_receipts": sum(
            isinstance(item.record, ExecutionReceiptRecord) for item in evidence
        ),
        "with_ingestion_receipt": sum(
            item.receipt_signature is not None for item in evidence
        ),
    }
    return evidence, provenance


@dataclass(frozen=True, slots=True)
class RegisteredScope:
    """The boundary and qualification as the ledger recorded them.

    Read back rather than re-minted. A generator that signs a fresh boundary
    after the window has run produces a record whose recording time is later
    than the window it claims to govern, and AR-027 floors the effective
    interval at exactly that instant -- so re-minting is how an attestation
    comes to assert a boundary was in force across a window that closed before
    the boundary existed.
    """

    boundary_version: BoundaryVersion
    qualifications: tuple[Qualification, ...]
    #: The recording instant, derived from the ES-032 issuer receipt that
    #: `boundary_versions` re-verifies against the registered keys.
    recorded_at: datetime
    #: The exact signed records the ledger holds, republished verbatim.
    boundary_record: AssuranceBoundaryRecord
    qualification_record: QualificationRecord


def read_registered_scope(
    *, tenant_id: str, name: str, action_family: str, destination_system: str
) -> RegisteredScope:
    """Read the declared scope the evidence was emitted under."""

    engine = migrator_engine(LedgerConfig.from_env())
    try:
        with engine.begin() as connection:
            versions = boundary_versions(
                connection, tenant_id=tenant_id, name=name
            )
            history = qualification_history(
                connection,
                tenant_id=tenant_id,
                action_family=action_family,
                destination_system=destination_system,
            )
            # The authoritative bytes (ES-021, DM-023): every projected column
            # above is rebuildable from these, and only these carry the
            # signature a relying party can check.
            # EV-31 stores the complete wire artifact for constitutive
            # records, so the fixture republishes exactly what the ledger
            # holds rather than reassembling a look-alike from its parts.
            boundary_row = connection.execute(
                select(boundaries.c.received_wire_bytes)
                .where(
                    boundaries.c.tenant_id == tenant_id,
                    boundaries.c.name == name,
                )
                .order_by(boundaries.c.version.desc())
                .limit(1)
            ).scalar_one()
            qualification_rows = connection.execute(
                select(qualification_records.c.received_wire_bytes).where(
                    qualification_records.c.tenant_id == tenant_id,
                    qualification_records.c.action_family == action_family,
                    qualification_records.c.destination_system == destination_system,
                )
            ).scalars().all()
    finally:
        engine.dispose()
    if not versions:
        raise RuntimeError(
            f"no AssuranceBoundary named {name!r} is declared for {tenant_id!r}; "
            "seed the scope before generating a fixture that cites it"
        )
    if not history:
        raise RuntimeError(
            f"no QualificationRecord for {action_family}/{destination_system}"
        )
    latest = versions[-1]
    boundary = parse_record(bytes(boundary_row))
    qualification = parse_record(bytes(qualification_rows[-1]))
    assert isinstance(boundary, AssuranceBoundaryRecord)
    assert isinstance(qualification, QualificationRecord)
    return RegisteredScope(
        boundary_version=latest,
        qualifications=history,
        recorded_at=latest.recorded_at,
        boundary_record=boundary,
        qualification_record=qualification,
    )


# --------------------------------------------------------------------------
# Constitutive records -- signed, not omitted
# --------------------------------------------------------------------------


def build_qualification_record(
    *,
    config: SalesforceConnectorConfig,
    issued_at: datetime,
    evidence_key: Ed25519PrivateKey,
    qualified_at: datetime = QUALIFIED_AT,
    window_start: datetime = WINDOW_START,
    window_end: datetime = WINDOW_END,
) -> QualificationRecord:
    """The signed §5.2 record the AssuranceBoundary references.

    TM-013 requires the class a bundle claims to be checkable from the bundle
    itself. A verifier handed an attestation claiming C1 with no qualification
    assigning C1 before the window opens cannot confirm the claim, and refuses
    it -- correctly. Omitting this record is what made the previous fixture set
    unverifiable.
    """

    unsigned = QualificationRecord.model_validate(
        _envelope(
            record_type="QualificationRecord",
            record_id=_uuid7(issued_at),
            stream_id=f"{TENANT_ID}:evidence:salesforce:qualification",
            clocks={"source_time": _timestamp(issued_at)},
            source=_generator_source(),
            body={
                "action_family": config.action_family,
                "destination_system": config.destination_system,
                "enumeration": {
                    "api": "SOQL Case query",
                    "scoping": "CreatedById plus half-open CreatedDate window",
                    "ordering": "CreatedDate ASC, Id ASC",
                    "pagination": "queryMore batchSize 2000",
                    "result_cap": None,
                    "capable": True,
                },
                "identity_isolation": {
                    "attribute": "CreatedById",
                    # CM-005: forgeable only by a principal holding
                    # PermissionsCreateAuditFields, which is why the class is
                    # conditional and revalidated org-wide before every window.
                    "vendor_settable": False,
                    "conditional_on": "no principal holds PermissionsCreateAuditFields",
                    "partial_isolation_notes": (
                        "exact with the permission ungranted; forged records are "
                        "indistinguishable per-record once it is granted"
                    ),
                },
                "confirmation": {
                    "api": "SOQL Case retrieve by Id",
                    "independent_of_enumeration": False,
                    "capable": True,
                },
                "temporal": {
                    "authoritative_timestamp_source": "Salesforce CreatedDate",
                    "measured_settlement_lag_s": 0,
                },
                "retention_period": "P180D",
                "mutability": {
                    "deletion_possible": False,
                    "trace_available": True,
                },
                "assigned_class": "C1",
                "class_evidence": {
                    "probe": "docs/qualifications/salesforce-record-create.md",
                    "condition": "PermissionsCreateAuditFields held by no principal",
                },
                "trial": {
                    "window_reconciled": f"{_timestamp(window_start)}/{_timestamp(window_end)}",
                    "match_rate": "1.0000",
                },
                "qualified_at": _timestamp(qualified_at),
                "revalidation_cadence": "PT1H",
            },
        )
    )
    # ES-033: a QualificationRecord's primary proof is evidence-namespace.
    return sign_record(unsigned, key_id=EVIDENCE_KEY_ID, private_key=evidence_key)


def build_boundary_record(
    *,
    config: SalesforceConnectorConfig,
    qualification: QualificationRecord,
    issued_at: datetime,
    evidence_key: Ed25519PrivateKey,
    window_start: datetime = WINDOW_START,
    window_end: datetime = WINDOW_END,
) -> AssuranceBoundaryRecord:
    """The signed §5.1 record naming the scope the attestation claims within."""

    unsigned = AssuranceBoundaryRecord.model_validate(
        _envelope(
            record_type="AssuranceBoundary",
            record_id=_uuid7(issued_at),
            stream_id=f"{TENANT_ID}:evidence:salesforce:boundary",
            clocks={"source_time": _timestamp(issued_at)},
            source=_generator_source(),
            body={
                "boundary_version": "1",
                "tenant": TENANT_ID,
                "deployment": "probe",
                "agent_identities": [config.integration_user_id],
                # Objects, not bare names. ES-009 requires every declared
                # family to carry its qualification, and `services.admin`
                # refuses a boundary whose entries cannot be read that way --
                # so a bare-string list is a declaration the shipping service
                # would not have accepted.
                "action_families": [
                    {
                        "action_family": config.action_family,
                        "destination_system": config.destination_system,
                        "qualification_ref": qualification.record_id,
                    }
                ],
                "destination_systems": [config.destination_system],
                "enforcement_points": ["connector"],
                "policy_refs": ["demo-only:no-reliance"],
                "window_start": _timestamp(window_start),
                "window_end": _timestamp(window_end),
                "collection_modes": ["inline"],
                "fail_behaviour": {config.action_family: "fail_closed"},
                # The reference is the signed record's own id, so the verifier
                # resolves it inside the bundle rather than trusting a label.
                "qualification_refs": [qualification.record_id],
            },
        )
    )
    # ES-033: an AssuranceBoundary's primary proof is evidence-namespace.
    return sign_record(unsigned, key_id=EVIDENCE_KEY_ID, private_key=evidence_key)


def build_population_record(
    observation: Any, *, issued_at: datetime, issuer_key: Ed25519PrivateKey
) -> PopulationRecord:
    unsigned = PopulationRecord.model_validate(
        _envelope(
            record_type="PopulationRecord",
            record_id=_uuid7(issued_at),
            stream_id=f"{TENANT_ID}:issuer:salesforce:population",
            clocks=observation.clocks.model_dump(mode="json", exclude_unset=True),
            source=_generator_source(observation.source),
            body=observation.body.model_dump(mode="json", exclude_unset=True),
        )
    )
    # ES-033: a PopulationRecord is a hosted observation, issuer-namespace.
    return sign_record(unsigned, key_id=ISSUER_KEY_ID, private_key=issuer_key)


def build_confirmation_record(
    observation: Any, *, issued_at: datetime, issuer_key: Ed25519PrivateKey
) -> ExternalConfirmationRecord:
    unsigned = ExternalConfirmationRecord.model_validate(
        _envelope(
            record_type="ExternalConfirmation",
            record_id=_uuid7(issued_at),
            stream_id=f"{TENANT_ID}:issuer:salesforce:confirmation",
            clocks=observation.clocks.model_dump(mode="json", exclude_unset=True),
            source=_generator_source(observation.source),
            body=observation.body.model_dump(mode="json", exclude_unset=True),
        )
    )
    return sign_record(unsigned, key_id=ISSUER_KEY_ID, private_key=issuer_key)


@dataclass(frozen=True, slots=True)
class ConfirmationTarget:
    """One Case to confirm, and where its action identity came from.

    The provenance travels with the target rather than being recomputed from
    the ledger afterwards. Deriving it separately is how the manifest came to
    claim a ledger-derived identity for a run that had used the probe
    fallback: two statements about the same fact, free to disagree.
    """

    destination_record_id: str
    action_id: str
    #: The receipt the identity was read from; `None` for the probe fallback.
    receipt_record_id: str | None

    @property
    def derived_from_ledger(self) -> bool:
        return self.receipt_record_id is not None


def select_confirmation_targets(
    ledger_records: tuple[LedgerEvidence, ...], identifiers: list[str]
) -> tuple[ConfirmationTarget, ...]:
    """Choose which Cases to confirm, and under which action identity.

    The action id is read from the ledger receipt and never invented. EV-15
    matches a receipt to a confirmation by action identity, and an identity
    minted here could not equal one minted when the action was *proposed* --
    which happens before the destination record exists and therefore cannot be
    derived from its id. A generator that composes `"<prefix>:<CaseId>"` is
    guaranteed never to match a real EV-08 action, so the honest-match fixture
    it is supposed to produce is unreachable by construction.

    A ledger holding evidence is not the same as a ledger holding evidence
    *about an enumerated record*: an ActionProposal with no receipt, or a
    receipt naming a Case outside the window, selects nothing. Each returned
    target therefore carries whether its identity came from a receipt.
    """

    population_ids = set(identifiers)
    targets: list[ConfirmationTarget] = []
    seen: set[str] = set()
    for item in ledger_records:
        record = item.record
        if not isinstance(record, ExecutionReceiptRecord):
            continue
        destination_id = record.body.destination_record_ref
        if destination_id in population_ids and destination_id not in seen:
            seen.add(destination_id)
            targets.append(
                ConfirmationTarget(
                    destination_record_id=destination_id,
                    action_id=record.body.action_id,
                    receipt_record_id=record.record_id,
                )
            )
    if targets:
        return tuple(targets)
    # No ledger receipt names an enumerated record, so no confirmation can
    # match whatever identity it carries. One Case is still confirmed, to
    # exercise the destination's confirmation capability, under an identity
    # that is transparently not an action id -- and that is *not derived from
    # the destination record*, so "an action id never contains the id of the
    # record it produced" holds for every confirmation this tool emits, and
    # stays checkable by inspection.
    return (
        ConfirmationTarget(
            destination_record_id=identifiers[0],
            action_id=f"unmatched-probe:{uuid.uuid4()}",
            receipt_record_id=None,
        ),
    )


def derive_action_evidence(
    *,
    reconciliation_results: tuple[Any, ...],
    confirmations: tuple[ExternalConfirmationRecord, ...],
    ledger_records: tuple[LedgerEvidence, ...],
) -> tuple[ActionEvidence, ...]:
    """Derive EV-16's evidence inputs from what reconciliation actually bound.

    The linkage is read from the reconciliation result, not guessed from a
    shared destination id. EV-16 refuses a confirmation that is not bound to a
    matched result, and it is right to: a destination record existing is not
    evidence that an agent created it, which is the whole reason EV-15 will not
    treat confirmation alone as support.

    A result with no bound confirmation therefore contributes nothing, and the
    action stays unevidenced rather than acquiring support from the fact that
    somebody enumerated it.
    """

    confirmations_by_record_id = {
        confirmation.record_id: confirmation for confirmation in confirmations
    }
    receipts_by_destination: dict[str, ExecutionReceiptRecord] = {}
    for item in ledger_records:
        if isinstance(item.record, ExecutionReceiptRecord):
            receipts_by_destination.setdefault(
                item.record.body.destination_record_ref, item.record
            )

    evidence: list[ActionEvidence] = []
    for result in reconciliation_results:
        confirmation_id = getattr(result, "confirmation_record_id", None)
        if confirmation_id is None:
            continue
        confirmation = confirmations_by_record_id.get(confirmation_id)
        if confirmation is None:
            continue
        evidence.append(
            ActionEvidence(
                destination_record_id=result.destination_record_id,
                confirmation=confirmation,
            )
        )
    return tuple(evidence)


def generate(
    output_dir: Path,
    *,
    require_matches: bool,
    timeout_s: float = 15.0,
    window_start: datetime = WINDOW_START,
    window_end: datetime = WINDOW_END,
) -> dict[str, Any]:
    username = _required_env("SALESFORCE_USERNAME")
    auth_config = SalesforceJwtBearerConfig.from_token_endpoint(
        client_id=_required_env("SALESFORCE_CLIENT_ID"),
        subject=username,
        token_endpoint=_required_env("SALESFORCE_TOKEN_ENDPOINT"),
    )
    token = exchange_jwt_bearer(
        SalesforceJwtBearerAuth(
            config=auth_config,
            signer=FileRs256Signer(_required_env("SALESFORCE_PRIVATE_KEY_PATH")),
        ).build_token_request(),
        timeout_s=timeout_s,
    )
    identity = confirm_salesforce_identity(
        token, expected_username=username, timeout_s=timeout_s
    )
    config = SalesforceConnectorConfig(
        api_version="v67.0", integration_user_id=identity.user_id
    )
    connector = SalesforceConnector(
        client=SalesforceRestClient(token, api_version=config.api_version),
        config=config,
    )
    scope = ConnectorScope(
        config.action_family, config.destination_system, config.scope_parameters
    )
    window = EnumerationWindow(window_start, window_end)

    # The conditional-C1 precondition, re-checked org-wide before the window is
    # enumerated at all. `enumerate` raises if this is not clean; the explicit
    # check here only produces a clearer diagnostic.
    permission = connector.revalidate_qualification()
    if not permission.c1_eligible:
        raise RuntimeError(
            f"Salesforce conditional C1 is unavailable: {permission.outcome.value}"
        )

    population_observation = connector.enumerate(scope, window)
    identifiers = list(population_observation.body.record_identifiers or ())
    if not identifiers:
        raise RuntimeError("live enumeration returned an empty population")
    attribution = (population_observation.body.model_extra or {}).get(
        "attribution_observations"
    )
    if not isinstance(attribution, list) or any(
        not isinstance(item, dict)
        or item.get("actor_attribute") != config.integration_user_id
        for item in attribution
    ):
        raise RuntimeError("live population attribution does not match integration user")

    # The read this whole tool exists to make honest -- and it happens before
    # confirmation, because the ledger decides which Cases are worth
    # confirming and under which action identity.
    ledger_records, ledger_provenance = read_ledger_evidence(TENANT_ID)
    targets = select_confirmation_targets(ledger_records, identifiers)
    confirmation_observations = tuple(
        connector.confirm(
            ActionReference(
                action_id=target.action_id,
                destination_record_id=target.destination_record_id,
            )
        )
        for target in targets
    )

    observed_now = datetime.now(UTC)
    generated_at = observed_now.replace(
        microsecond=(observed_now.microsecond // 1_000) * 1_000
    )
    evidence_key = _load_ed25519("EVIDENCE_SIGNING_KEY_PATH")
    issuer_key = _load_ed25519("ISSUER_SIGNING_KEY_PATH")

    # The constitutive records are read, never authored here. The scope was
    # declared before the action ran; re-signing it now would produce a record
    # whose recording time is later than the window it governs.
    registered = read_registered_scope(
        tenant_id=TENANT_ID,
        name="case-create",
        action_family=config.action_family,
        destination_system=config.destination_system,
    )

    population = build_population_record(
        population_observation,
        issued_at=generated_at + timedelta(milliseconds=2),
        issuer_key=issuer_key,
    )
    confirmations = tuple(
        build_confirmation_record(
            observation,
            issued_at=generated_at + timedelta(milliseconds=3 + index),
            issuer_key=issuer_key,
        )
        for index, observation in enumerate(confirmation_observations)
    )

    ledger_evidence_records = tuple(item.record for item in ledger_records)
    reconciliation_results = reconcile(
        population, ledger_evidence_records, confirmations
    )
    matched_count = sum(
        result.status.value == "matched" for result in reconciliation_results
    )
    if require_matches and matched_count == 0:
        raise RuntimeError(
            "--require-matches was set and the ledger produced no matched record; "
            "emitting an honest zero here would misrepresent the fixture set's purpose"
        )

    action_evidence = derive_action_evidence(
        reconciliation_results=reconciliation_results,
        confirmations=confirmations,
        ledger_records=ledger_records,
    )

    # The qualification history as the ledger holds it, including its hosted
    # recorded_at. Rebuilding it here would let this tool choose the instant
    # CM-004 dates the class from.
    coverage_boundary = CoverageBoundary(
        boundary_ref=BOUNDARY_REF,
        window=TimeInterval(window_start, window_end),
        clock_skew_threshold_ms=5_000,
    )
    coverage = compute_coverage(
        reconciliation_results=reconciliation_results,
        population=population,
        boundary=coverage_boundary,
        qualification_history=registered.qualifications,
        action_evidence=action_evidence,
    )
    request = AttestationRequest(
        tenant_id=TENANT_ID,
        record_id=_uuid7(generated_at + timedelta(milliseconds=4)),
        stream_id=f"{TENANT_ID}:attestation:salesforce-live",
        sequence=1,
        prev_digest=None,
        source=AttestationSource(
            service="salesforce-live-fixture-generator", version=GENERATOR_VERSION
        ),
        coverage=coverage,
        action_families=(config.action_family,),
        operated_action_families=(config.action_family,),
        outcome_action_ids=(),
        # No human review was in scope for a record-create probe, so the
        # A-07/A-08 inputs are empty rather than absent -- EV-11 withholds
        # those assertions from an empty set rather than assuming none
        # were required.
        review_action_ids=(),
        human_reviews=(),
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
        name="Evidence Control Plane demo",
        identifier="salesforce-probe",
        ),
    )
    # Issued through the ledger-backed path: `issue_attestation` loads the
    # boundary history itself and re-verifies each stored ES-032 receipt, so
    # A-02 rests on a recording time this tool cannot influence and could not
    # fabricate by handing over a BoundaryVersion of its own construction.
    engine = migrator_engine(LedgerConfig.from_env())
    try:
        with engine.begin() as connection:
            attestation = issue_attestation(
                request,
                connection=connection,
                evidence_signer=EvidenceSigner(EVIDENCE_KEY_ID, evidence_key),
                issuer_signer=IssuerSigner(ISSUER_KEY_ID, issuer_key),
            )
    finally:
        engine.dispose()

    verification_keys = {
        EVIDENCE_KEY_ID: RegisteredPublicKey(
            namespace="evidence", public_key=evidence_key.public_key()
        ),
        ISSUER_KEY_ID: RegisteredPublicKey(
            namespace="issuer", public_key=issuer_key.public_key()
        ),
    }
    for record in (
        registered.qualification_record,
        registered.boundary_record,
        population,
        *confirmations,
    ):
        verify_record_origin_signature(record, verification_keys=verification_keys)
    verify_attestation_signatures(
        attestation.record,
        evidence_public_keys={EVIDENCE_KEY_ID: evidence_key.public_key()},
        issuer_public_keys={ISSUER_KEY_ID: issuer_key.public_key()},
    )

    # ES-034 permits any number of non-singleton record types, and a bundle
    # asserting a matched count while withholding the records that produced it
    # asks the relying party to trust the issuer for the one number it cares
    # about. The proposal and receipt travel with the claim.
    bundle_records: tuple[RecordEnvelope, ...] = (
        registered.boundary_record,
        registered.qualification_record,
        population,
        *confirmations,
        *ledger_evidence_records,
        attestation.record,
    )
    bundle_bytes = assemble_bundle(bundle_records)

    output_dir.mkdir(parents=True, exist_ok=True)
    permission_json = {
        "outcome": permission.outcome.value,
        "c1_eligible": permission.c1_eligible,
        "checked_at": _timestamp(permission.checked_at),
        "last_confirmed_clean_at": (
            _timestamp(permission.last_confirmed_clean_at)
            if permission.last_confirmed_clean_at is not None
            else None
        ),
        "failure_code": permission.failure_code,
    }
    readable_files: dict[str, object] = {
        "01-permission-check.json": permission_json,
        "02-population-observation.json": {
            "body": population_observation.body.model_dump(
                mode="json", exclude_unset=True
            ),
            "clocks": population_observation.clocks.model_dump(
                mode="json", exclude_unset=True
            ),
            "source": population_observation.source,
        },
        "03-population-record.json": _model_json(population),
        "04-confirmation-observations.json": [
            {
                "body": observation.body.model_dump(mode="json", exclude_unset=True),
                "clocks": observation.clocks.model_dump(
                    mode="json", exclude_unset=True
                ),
                "source": observation.source,
            }
            for observation in confirmation_observations
        ],
        "05-external-confirmations.json": [
            _model_json(record) for record in confirmations
        ],
        "06-reconciliation-results.json": [
            {**asdict(result), "status": result.status.value}
            for result in reconciliation_results
        ],
        "07-coverage-report.json": coverage.to_payload(),
        "10-qualification-record.json": _model_json(registered.qualification_record),
        "11-assurance-boundary.json": _model_json(registered.boundary_record),
        # The exact bytes the ledger holds, with the issuer receipts that bind
        # them, so EV-15 can be re-run from published artifacts rather than
        # believed.
        "13-ledger-evidence.json": [item.to_json() for item in ledger_records],
    }
    for filename, value in readable_files.items():
        _write_json(output_dir / filename, value)
    # Artifact of record: the verifier consumes these exact canonical wire
    # bytes. Never route a signed record through `_write_json`, because parsing
    # and indenting it after signing produces semantically equivalent JSON but
    # not the RFC 8785 wire artifact ES-001 requires a verifier to receive.
    attestation_filename = "08-attestation-window.json"
    (output_dir / attestation_filename).write_bytes(canonicalize(attestation.record))
    (output_dir / "12-bundle.json").write_bytes(bundle_bytes)

    manifest = {
        "fixture_set": "salesforce-live-case-create",
        "generator_version": GENERATOR_VERSION,
        "generated_at": _timestamp(generated_at),
        "schema_version": SCHEMA_VERSION,
        "methodology_version": METHODOLOGY_VERSION,
        "live_source": {
            "api_version": config.api_version,
            "destination_system": config.destination_system,
            "integration_username": identity.username,
            "integration_user_id": identity.user_id,
            "organization_id": identity.organization_id,
            "sobject": config.sobject,
            "window_start": _timestamp(window_start),
            "window_end": _timestamp(window_end),
        },
        # The provenance that makes the matched count checkable rather than
        # merely stated.
        "evidence_ledger": ledger_provenance,
        "computation": {
            "reconciliation": "EV-15 reconcile over live population and ledger evidence",
            "coverage": "EV-16 compute_coverage",
            "issuance": "EV-17 issue_attestation",
            "population_count": len(identifiers),
            "confirmed_count": len(confirmations),
            # How many confirmations carry an identity read from a ledger
            # receipt (EV-15 RC-001). Counted from the selected targets, not
            # inferred from the ledger being non-empty: evidence that names no
            # enumerated record selects nothing, and reporting otherwise would
            # be the manifest asserting a provenance it never established.
            "confirmations_with_ledger_derived_action_id": sum(
                target.derived_from_ledger for target in targets
            ),
            "matched_count": matched_count,
            "coverage_ratio": coverage.to_payload()["coverage_ratio"],
            "ratio_state": coverage.to_payload()["ratio_state"],
        },
        "verification_keys": {
            EVIDENCE_KEY_ID: {
                "namespace": "evidence",
                "public_key_base64url": _public_key_b64(evidence_key),
            },
            ISSUER_KEY_ID: {
                "namespace": "issuer",
                "public_key_base64url": _public_key_b64(issuer_key),
            },
        },
        "files": sorted(
            [*readable_files, attestation_filename, "12-bundle.json"]
        ),
        "ledger_artifacts": {
            "file": "13-ledger-evidence.json",
            "contains": (
                "the received wire bytes and ES-030 ingestion receipt for every "
                "evidence record the reconciliation read"
            ),
        },
        "bundle": {
            "file": "12-bundle.json",
            "records": [record.record_type for record in bundle_records],
            "verify_with": (
                "verifier-go/cmd/verify -mode bundle -offline "
                "-keyring <keyring.json> -as-of <RFC3339> 12-bundle.json"
            ),
        },
    }
    _write_json(output_dir / "09-manifest.json", manifest)

    # Reparse the exact saved bytes, not only the in-memory objects: a fixture
    # is only as good as what landed on disk.
    for filename in (
        "03-population-record.json",
        "10-qualification-record.json",
        "11-assurance-boundary.json",
    ):
        verify_record_origin_signature(
            parse_record((output_dir / filename).read_bytes()),
            verification_keys=verification_keys,
        )
    for saved in json.loads(
        (output_dir / "05-external-confirmations.json").read_text(encoding="utf-8")
    ):
        verify_record_origin_signature(
            parse_record(json.dumps(saved).encode("utf-8")),
            verification_keys=verification_keys,
        )
    verify_attestation_signatures(
        parse_record((output_dir / "08-attestation-window.json").read_bytes()),  # type: ignore[arg-type]
        evidence_public_keys={EVIDENCE_KEY_ID: evidence_key.public_key()},
        issuer_public_keys={ISSUER_KEY_ID: issuer_key.public_key()},
    )
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("tests/fixtures/salesforce-live"),
    )
    parser.add_argument(
        "--require-matches",
        action="store_true",
        help=(
            "fail unless the ledger produces at least one matched record; for the "
            "honest-match fixture set, where an honest zero would be a silent "
            "failure to exercise the path the set exists to demonstrate"
        ),
    )
    parser.add_argument(
        "--timeout-s",
        type=float,
        default=15.0,
        help="per-request Salesforce timeout; raise it on a slow link",
    )
    parser.add_argument(
        "--window-start",
        type=_parse_instant,
        default=WINDOW_START,
        help="RFC 3339 attestation window start (default: the probe minute)",
    )
    parser.add_argument(
        "--window-end",
        type=_parse_instant,
        default=WINDOW_END,
        help="RFC 3339 attestation window end, exclusive",
    )
    args = parser.parse_args()
    manifest = generate(
        args.output_dir,
        require_matches=args.require_matches,
        timeout_s=args.timeout_s,
        window_start=args.window_start,
        window_end=args.window_end,
    )
    computation = manifest["computation"]
    ledger = manifest["evidence_ledger"]
    print(
        f"population {computation['population_count']} | "
        f"ledger rows {ledger['rows_returned']} "
        f"(proposals {ledger['action_proposals']}, "
        f"receipts {ledger['execution_receipts']}) | "
        f"matched {computation['matched_count']} | "
        f"ratio {computation['coverage_ratio']}"
    )


if __name__ == "__main__":
    main()
