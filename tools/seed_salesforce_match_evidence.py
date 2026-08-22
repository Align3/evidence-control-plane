"""Seed the honest-match fixture set: a real Case with real evidence (EV-42).

This is the counterpart to `generate_salesforce_live_fixtures.py`. That tool
reports whatever the ledger holds; this one puts something in it, the same way
an agent would.

**It writes to Salesforce.** Exactly one Case, through the ordinary REST
create, as the integration user, so the record it produces is attributed the
way a genuine agent action would be. The Case id is printed so it can be
deleted afterwards.

The ordering matters and is the whole point. The action identity is minted
*before* the Case exists, carried on the `ActionProposal`, and then repeated on
the `ExecutionReceipt` alongside the destination record it produced. That is
why an identity composed from the Case id can never match: at the moment the
action is proposed there is no Case id to compose one from.

Both records are emitted through the EV-08 `EvidenceClient` and land in the
ledger through the EV-07 ingestion service, which mints the ES-030 receipt that
the ledger's own constraint requires. Nothing is inserted directly: the
`ck_evidence_records_origin_metadata` check refuses an evidence row without a
receipt, which is precisely the property that makes a seeded match honest.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import time
import urllib.request
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import text

from sdk_python.client import (
    FAIL_CLOSED_TRADE_OFF,
    ClientConfig,
    EvidenceClient,
    FamilyPolicy,
    SigningIdentity,
)
from sdk_python.evidence.canonical import canonicalize
from sdk_python.evidence.schema import AssuranceBoundaryRecord, QualificationRecord
from services.admin import record_boundary, record_qualification
from services.connectors import (
    FileRs256Signer,
    SalesforceConnectorConfig,
    SalesforceJwtBearerAuth,
    SalesforceJwtBearerConfig,
    confirm_salesforce_identity,
    exchange_jwt_bearer,
)
from services.ingestion.api import create_app
from services.ingestion.service import IngestionService, IssuerSigningKey
from services.ledger import (
    LedgerConfig,
    TenantEngines,
    migrator_engine,
    provision_tenant,
)
from tools.generate_salesforce_live_fixtures import (
    BOUNDARY_REF,
    EVIDENCE_KEY_ID,
    ISSUER_KEY_ID,
    TENANT_ID,
    _load_ed25519,
    _required_env,
    _timestamp,
    build_boundary_record,
    build_qualification_record,
)

COLLECTOR_ID = f"{TENANT_ID}-collector-1"
ACTION_FAMILY = "record.create"
SUBJECT = "EV-42 honest-match probe"


def _sha256_ref(payload: bytes) -> str:
    """ES-003 digest of bytes that actually crossed the wire."""

    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _unsigned_bytes_and_signature(record: Any) -> tuple[bytes, bytes]:
    """The exact bytes the customer key covered, and the raw signature.

    ES-021: `sig` covers the record *excluding* its own signature member, so
    the ledger stores those bytes verbatim rather than re-deriving them.
    """

    payload = record.model_dump(mode="json", exclude_unset=True)
    signature = payload.pop("signature")
    canonical = canonicalize(payload)
    raw = base64.urlsafe_b64decode(signature["sig"] + "=" * (-len(signature["sig"]) % 4))
    return canonical, raw


def register_scope(
    *,
    config: SalesforceConnectorConfig,
    evidence_key: Ed25519PrivateKey,
    issuer_key: Ed25519PrivateKey,
    window_start: datetime,
    window_end: datetime,
) -> None:
    """Provision the tenant and declare the scope the evidence will cite.

    DM-017's foreign key means an evidence row cannot name a boundary that was
    never declared, so the declaration has to exist before the agent emits
    anything about actions inside it.
    """

    ledger = LedgerConfig.from_env()
    engine = migrator_engine(ledger)
    now = datetime.now(UTC)
    # When the qualification was actually performed. Backdating this is the
    # same defect as backdating `recorded_at`, one field over: CM-003 asks
    # whether a qualification was in force at the window's start, and a
    # qualified_at chosen to sit before the window always answers yes.
    qualified_at = now
    try:
        with engine.begin() as connection:
            provision_tenant(
                connection,
                tenant_id=TENANT_ID,
                name="Salesforce Probe",
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
                {"cid": COLLECTOR_ID, "tid": TENANT_ID},
            )
            connection.execute(
                text(
                    "INSERT INTO keys (key_id, tenant_id, collector_id, namespace,"
                    " public_key, custody, valid_from)"
                    " VALUES (:kid, :tid, :cid, 'evidence', :pk, 'client_held', now())"
                    " ON CONFLICT (key_id) DO NOTHING"
                ),
                {
                    "kid": EVIDENCE_KEY_ID,
                    "tid": TENANT_ID,
                    "cid": COLLECTOR_ID,
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
                    "kid": ISSUER_KEY_ID,
                    "tid": TENANT_ID,
                    "pk": issuer_key.public_key().public_bytes_raw(),
                },
            )

            # Re-running a seeding pass must not require a fresh database, and
            # the scope is one declaration: present or absent as a whole. A
            # second qualification under a fresh instant would be a *new*
            # declaration, not a retry.
            if connection.execute(
                text("SELECT 1 FROM boundaries WHERE boundary_ref = :ref"),
                {"ref": BOUNDARY_REF},
            ).scalar_one_or_none() is not None:
                print(f"  scope already declared: {BOUNDARY_REF}")
                return

            # The same builders the fixture generator uses, so the declared
            # scope and the attested scope cannot drift apart.
            qualification: QualificationRecord = build_qualification_record(
                config=config,
                issued_at=now,
                evidence_key=evidence_key,
                qualified_at=qualified_at,
                window_start=window_start,
                window_end=window_end,
            )
            canonical, signature = _unsigned_bytes_and_signature(qualification)
            qualification_ref = record_qualification(
                connection,
                record=qualification,
                canonical_bytes=canonical,
                signature=signature,
            )
            boundary: AssuranceBoundaryRecord = build_boundary_record(
                config=config,
                qualification=qualification,
                issued_at=now,
                evidence_key=evidence_key,
                window_start=window_start,
                window_end=window_end,
            )
            canonical, signature = _unsigned_bytes_and_signature(boundary)
            # The hosted observation time, not a value the signer chose.
            # AR-027 floors the boundary's effective interval at this instant
            # precisely so a boundary cannot be backdated into force; handing
            # it a signer-supplied instant hands the party the attestation is
            # about the power to decide when its own boundary took effect.
            record_boundary(
                connection,
                record=boundary,
                canonical_bytes=canonical,
                signature=signature,
                recorded_at=datetime.now(UTC),
            )
            print(f"  scope declared: {BOUNDARY_REF} -> {qualification_ref}")
    finally:
        engine.dispose()


def create_case(
    token: Any, *, api_version: str, timeout_s: float, request_payload: bytes
) -> tuple[str, str, bytes]:
    """Perform the action. Returns (case_id, CreatedDate, raw response bytes).

    The raw response is returned so the ExecutionReceipt can bind the bytes the
    destination actually sent, rather than a digest of something the tool made
    up afterwards.
    """

    base = token.instance_url.rstrip("/")
    request = urllib.request.Request(  # noqa: S310 -- Salesforce HTTPS instance URL
        f"{base}/services/data/{api_version}/sobjects/Case",
        data=request_payload,
        headers={
            "Authorization": f"Bearer {token.access_token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout_s) as response:  # noqa: S310
        response_bytes = response.read()
    created = json.loads(response_bytes)
    case_id = str(created["id"])
    _, created_date = read_case(
        token, case_id=case_id, api_version=api_version, timeout_s=timeout_s
    )
    return case_id, created_date, response_bytes


def read_case(
    token: Any, *, case_id: str, api_version: str, timeout_s: float
) -> tuple[str, str]:
    """Read a Case's authoritative creation time from the destination."""

    base = token.instance_url.rstrip("/")
    read = urllib.request.Request(  # noqa: S310 -- Salesforce HTTPS instance URL
        f"{base}/services/data/{api_version}/sobjects/Case/{case_id}"
        "?fields=Id,CreatedDate,CreatedById",
        headers={"Authorization": f"Bearer {token.access_token}"},
        method="GET",
    )
    with urllib.request.urlopen(read, timeout=timeout_s) as response:  # noqa: S310
        fetched = json.loads(response.read())
    return case_id, str(fetched["CreatedDate"])


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
    *, evidence_key: Ed25519PrivateKey, issuer_key: Ed25519PrivateKey
) -> EvidenceClient:
    """An EV-08 client delivering into EV-07's ingestion in-process.

    Posted through the ASGI app rather than over a socket: the code path is
    identical, and a demo tool that needs a running server to seed a fixture is
    a demo tool nobody runs.
    """

    service = IngestionService(
        tenant_engines=TenantEngines(LedgerConfig.from_env()),
        issuer_signers={
            TENANT_ID: IssuerSigningKey(
                key_id=ISSUER_KEY_ID, private_key=issuer_key
            )
        },
    )
    app = create_app(service)

    class InProcessTransport:
        """Delivers to the ingestion app without a socket."""

        def submit(self, wire: bytes) -> None:
            status, payload = asyncio.run(_asgi_post(app, "/v1/evidence", wire))
            if status >= 400:
                raise RuntimeError(
                    f"ingestion refused the record: {status} {payload.decode()[:300]}"
                )

    return EvidenceClient(
        config=ClientConfig(
            tenant_id=TENANT_ID,
            boundary_ref=BOUNDARY_REF,
            collector_id=COLLECTOR_ID,
            deployment="probe",
            buffer_bound=16,
            families={
                ACTION_FAMILY: FamilyPolicy.fail_closed(
                    acknowledged_by="ev42-fixture-maintainer",
                    reason="a seeded match must not be recorded if ingestion refuses it",
                    # IN-013 requires the operational trade-off verbatim, so
                    # a fail-closed family cannot be configured by someone who
                    # has not read what it costs.
                    trade_off_acknowledged=FAIL_CLOSED_TRADE_OFF,
                ),
            },
        ),
        identity=SigningIdentity(key_id=EVIDENCE_KEY_ID, private_key=evidence_key),
        transport=InProcessTransport(),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout-s", type=float, default=60.0)
    parser.add_argument(
        "--without-evidence",
        action="store_true",
        help=(
            "create the Case but emit no ActionProposal or ExecutionReceipt, "
            "for the honest-zero window: an enumerated action the ledger holds "
            "no evidence about, alongside a ledger that is not empty"
        ),
    )
    args = parser.parse_args()

    username = _required_env("SALESFORCE_USERNAME")
    token = exchange_jwt_bearer(
        SalesforceJwtBearerAuth(
            config=SalesforceJwtBearerConfig.from_token_endpoint(
                client_id=_required_env("SALESFORCE_CLIENT_ID"),
                subject=username,
                token_endpoint=_required_env("SALESFORCE_TOKEN_ENDPOINT"),
            ),
            signer=FileRs256Signer(_required_env("SALESFORCE_PRIVATE_KEY_PATH")),
        ).build_token_request(),
        timeout_s=args.timeout_s,
    )
    identity = confirm_salesforce_identity(
        token, expected_username=username, timeout_s=args.timeout_s
    )
    config = SalesforceConnectorConfig(
        api_version="v67.0", integration_user_id=identity.user_id
    )
    evidence_key = _load_ed25519("EVIDENCE_SIGNING_KEY_PATH")
    issuer_key = _load_ed25519("ISSUER_SIGNING_KEY_PATH")

    # The scope must exist before any evidence can cite it, and the window is
    # not known until the Case is created -- so the scope is declared for a
    # window anchored on now, and the Case is created inside it.
    now = datetime.now(UTC)
    window_start = now.replace(second=0, microsecond=0)
    window_end = window_start + timedelta(minutes=1)
    # The boundary declares the deployment period it governs, not the single
    # minute a probe happens to use. AR-027 still floors its effective interval
    # at when it was recorded, so declaring generously buys nothing improper --
    # it just stops each probe needing its own boundary version.
    declared_from = datetime.now(UTC).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    register_scope(
        config=config,
        evidence_key=evidence_key,
        issuer_key=issuer_key,
        window_start=declared_from,
        window_end=declared_from + timedelta(days=30),
    )

    # The attestation window opens *after* the scope was declared. Waiting for
    # the next minute boundary is the honest way to get there: the alternative
    # is choosing a window that started before the qualification existed, which
    # is what CM-003 refuses and what backdating was hiding.
    scope_ready = datetime.now(UTC)
    window_start = scope_ready.replace(second=0, microsecond=0) + timedelta(minutes=1)
    window_end = window_start + timedelta(minutes=1)
    wait_s = (window_start - datetime.now(UTC)).total_seconds()
    if wait_s > 0:
        print(f"  waiting {wait_s:.0f}s for a window that opens after the scope")
        time.sleep(wait_s)
    client = build_client(evidence_key=evidence_key, issuer_key=issuer_key)

    # ---- The ordering below is the entire point of this tool. ----
    #
    # A proposal authored after its own action is not evidence of intent; it is
    # a record written to fit an outcome already known. Nothing here reads the
    # destination's clock to stamp a body: every instant is the moment this
    # process reached that line.

    action_id = str(uuid.uuid4())
    request_payload = json.dumps(
        {"Subject": SUBJECT, "Status": "New", "Origin": "Web"},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

    proposed_at = datetime.now(UTC)
    if args.without_evidence:
        # The unevidenced case. The Case is still created inside a declared,
        # qualified window, so the population is real and the reconciler has
        # somewhere to look -- it simply finds nothing about this action.
        dispatched_at = datetime.now(UTC)
        case_id, created_date, _ = create_case(
            token,
            api_version=config.api_version,
            timeout_s=args.timeout_s,
            request_payload=request_payload,
        )
        print(f"  Case {case_id} created at {created_date}, no evidence emitted")
        occurred_at = datetime.fromisoformat(created_date.replace("Z", "+00:00"))
        if not window_start <= occurred_at < window_end:
            raise RuntimeError("the Case landed outside the declared window")
        print()
        print("Generate the honest-zero fixture set with:")
        print(
            f"  python tools/generate_salesforce_live_fixtures.py \\\n"
            f"    --window-start {_timestamp(window_start)} "
            f"--window-end {_timestamp(window_end)} \\\n"
            f"    --output-dir tests/fixtures/salesforce-live"
        )
        print()
        print(f"Probe Case created in the live org: {case_id}")
        return

    client.emit(
        "ActionProposal",
        {
            "action_family": ACTION_FAMILY,
            "action_id": action_id,
            "tool": "salesforce.case.create",
            # The digest of the request this proposal authorises, taken over
            # the bytes actually sent below.
            "parameters_digest": _sha256_ref(request_payload),
            "purpose": "EV-42 honest-match fixture",
            "target_ref": config.destination_system,
            "risk_class": "low",
            "proposed_at": _timestamp(proposed_at),
        },
        action_family=ACTION_FAMILY,
    )
    print(f"  ActionProposal emitted at {_timestamp(proposed_at)}, action {action_id}")

    dispatched_at = datetime.now(UTC)
    case_id, created_date, response_bytes = create_case(
        token,
        api_version=config.api_version,
        timeout_s=args.timeout_s,
        request_payload=request_payload,
    )
    responded_at = datetime.now(UTC)
    print(f"  Case {case_id} created at {created_date} (destination clock)")

    client.emit(
        "ExecutionReceipt",
        {
            "action_id": action_id,
            "dispatch_attempt": 1,
            "connector_identity": config.destination_system,
            "connector_version": "1.0.0",
            # The digest of what the destination actually returned.
            "destination_response_digest": _sha256_ref(response_bytes),
            "destination_record_ref": case_id,
            "status": "succeeded",
            "dispatched_at": _timestamp(dispatched_at),
            "responded_at": _timestamp(responded_at),
        },
        action_family=ACTION_FAMILY,
    )
    print(f"  ExecutionReceipt emitted, dispatch {_timestamp(dispatched_at)}"
          f" -> response {_timestamp(responded_at)}")

    occurred_at = datetime.fromisoformat(created_date.replace("Z", "+00:00"))
    if not window_start <= occurred_at < window_end:
        raise RuntimeError(
            f"the Case was created at {created_date}, outside the declared window "
            f"{_timestamp(window_start)}/{_timestamp(window_end)}; re-run rather "
            "than widening the window to fit"
        )
    if not proposed_at < dispatched_at <= responded_at:
        raise RuntimeError("evidence instants are not in dispatch order")

    print()
    print("Generate the matched fixture set with:")
    print(
        f"  python tools/generate_salesforce_live_fixtures.py --require-matches \\\n"
        f"    --window-start {_timestamp(window_start)} "
        f"--window-end {_timestamp(window_end)} \\\n"
        f"    --output-dir tests/fixtures/salesforce-live-matched"
    )
    print()
    print(f"Probe Case created in the live org: {case_id}")


if __name__ == "__main__":
    main()
