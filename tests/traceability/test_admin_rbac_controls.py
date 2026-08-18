"""Structural and adversarial verification of SE-019 and SE-020."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI, Request

from services.admin import (
    ROLE_CAPABILITIES,
    AdminPrincipal,
    AdminRole,
    AuthenticationError,
    Capability,
    create_admin_app,
)


@dataclass(frozen=True, slots=True)
class Response:
    status_code: int
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body)


@dataclass
class RecordingBackend:
    calls: list[tuple[str, str, dict[str, Any]]] = field(default_factory=list)

    def overview(self, *, tenant_id: str) -> dict[str, Any]:
        return {
            "coverage_status": "reconciled",
            "gap_count": 2,
            "unmatched_count": 3,
            "attestation_count": 4,
        }

    def _record(
        self, operation: str, tenant_id: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        self.calls.append((operation, tenant_id, payload))
        return {"message": operation}

    def record_boundary(
        self, *, tenant_id: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        return self._record("boundary", tenant_id, payload)

    def record_qualification(
        self, *, tenant_id: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        return self._record("qualification", tenant_id, payload)

    def issue_attestation(
        self, *, tenant_id: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        return self._record("issue", tenant_id, payload)

    def revoke_attestation(
        self,
        *,
        tenant_id: str,
        attestation_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        return self._record("revoke", tenant_id, {**payload, "id": attestation_id})

    def supersede_attestation(
        self,
        *,
        tenant_id: str,
        attestation_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        return self._record("supersede", tenant_id, {**payload, "id": attestation_id})


def _principal(*roles: AdminRole, tenant: str = "acme") -> AdminPrincipal:
    return AdminPrincipal.from_roles(
        subject=":".join(("test", *(role.value for role in roles))),
        tenants=[tenant],
        roles=roles,
    )


def _auth(principals: dict[str, AdminPrincipal]) -> Any:
    def authenticate(request: Request) -> AdminPrincipal:
        header = request.headers.get("authorization", "")
        token = header.removeprefix("Bearer ")
        try:
            return principals[token]
        except KeyError as exc:
            raise AuthenticationError("valid bearer authentication required") from exc

    return authenticate


async def _request(
    app: FastAPI,
    *,
    method: str,
    path: str,
    credential: str | None = None,
    payload: dict[str, Any] | None = None,
) -> Response:
    raw = json.dumps(payload or {}).encode()
    headers = [(b"content-type", b"application/json")]
    if credential is not None:
        headers.append((b"authorization", f"Bearer {credential}".encode()))
    messages: list[dict[str, Any]] = []
    received = False

    async def receive() -> dict[str, Any]:
        nonlocal received
        if not received:
            received = True
            return {"type": "http.request", "body": raw, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    await app(
        {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.5"},
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "root_path": "",
            "headers": headers,
            "client": ("test", 123),
            "server": ("testserver", 80),
        },
        receive,
        send,
    )
    start = next(item for item in messages if item["type"] == "http.response.start")
    body = b"".join(
        item.get("body", b"")
        for item in messages
        if item["type"] == "http.response.body"
    )
    return Response(status_code=start["status"], body=body)


def _post(
    app: FastAPI, path: str, *, credential: str | None, payload: dict[str, Any]
) -> Response:
    return asyncio.run(
        _request(
            app,
            method="POST",
            path=path,
            credential=credential,
            payload=payload,
        )
    )


def test_se_019_admin_permissions_are_four_distinct_capabilities() -> None:
    assert {capability.value for capability in Capability} == {
        "boundary.manage",
        "qualification.manage",
        "attestation.issue",
        "attestation.revoke",
    }
    assert ROLE_CAPABILITIES[AdminRole.BOUNDARY_MANAGER] == {
        Capability.MANAGE_BOUNDARIES
    }
    assert ROLE_CAPABILITIES[AdminRole.QUALIFICATION_MANAGER] == {
        Capability.MANAGE_QUALIFICATIONS
    }
    assert ROLE_CAPABILITIES[AdminRole.ATTESTATION_ISSUER] == {
        Capability.ISSUE_ATTESTATIONS
    }
    assert ROLE_CAPABILITIES[AdminRole.REVOCATION_OPERATOR] == {
        Capability.REVOKE_ATTESTATIONS
    }


def test_se_020_engineering_role_cannot_issue_or_revoke() -> None:
    backend = RecordingBackend()
    app = create_admin_app(
        backend,
        authenticate=_auth({"engineering": _principal(AdminRole.ENGINEERING)}),
    )
    forged = {
        "roles": ["attestation_issuer", "revocation_operator"],
        "capabilities": ["attestation.issue", "attestation.revoke"],
    }

    issue = _post(
        app,
        "/api/admin/acme/attestations",
        credential="engineering",
        payload=forged,
    )
    revoke = _post(
        app,
        "/api/admin/acme/attestations/a-1/revocations",
        credential="engineering",
        payload=forged,
    )
    # Supersession records a replacement attestation, so it is an issuance
    # route and SE-020 must close it against engineering too.
    supersede = _post(
        app,
        "/api/admin/acme/attestations/a-1/supersessions",
        credential="engineering",
        payload=forged,
    )

    assert issue.status_code == 403
    assert revoke.status_code == 403
    assert supersede.status_code == 403
    assert backend.calls == []


def test_each_capability_dispatches_only_its_own_operation() -> None:
    backend = RecordingBackend()
    principals = {
        "boundary": _principal(AdminRole.BOUNDARY_MANAGER),
        "qualification": _principal(AdminRole.QUALIFICATION_MANAGER),
        "issuer": _principal(AdminRole.ATTESTATION_ISSUER),
        "revoker": _principal(AdminRole.REVOCATION_OPERATOR),
    }
    app = create_admin_app(backend, authenticate=_auth(principals))
    probes = (
        ("boundary", "/api/admin/acme/boundaries", "boundary"),
        ("qualification", "/api/admin/acme/qualifications", "qualification"),
        ("issuer", "/api/admin/acme/attestations", "issue"),
        ("revoker", "/api/admin/acme/attestations/a-1/revocations", "revoke"),
    )
    for credential, path, expected in probes:
        response = _post(
            app, path, credential=credential, payload={"command": expected}
        )
        assert response.status_code == 201, response.body

    assert [call[0] for call in backend.calls] == [item[2] for item in probes]

    # Supersession is the fifth write endpoint and spans two capabilities, so
    # no single-capability role may reach it. Asserting that here keeps this
    # test an exhaustive statement about the write surface rather than a
    # sample of it.
    before = len(backend.calls)
    for credential in principals:
        refused = _post(
            app,
            "/api/admin/acme/attestations/a-1/supersessions",
            credential=credential,
            payload={"command": "supersede"},
        )
        assert refused.status_code == 403, (credential, refused.body)
    assert len(backend.calls) == before


def test_supersession_requires_issuance_and_revocation_together() -> None:
    """SE-019/SE-020: superseding records a new attestation (AR-011).

    Gating it on revocation alone would hand a revocation operator the
    issuer's authority by another route, so neither half may reach it and
    the refusals must land before the backend is touched.
    """

    backend = RecordingBackend()
    principals = {
        "revoker": _principal(AdminRole.REVOCATION_OPERATOR),
        "issuer": _principal(AdminRole.ATTESTATION_ISSUER),
        "both": _principal(
            AdminRole.ATTESTATION_ISSUER, AdminRole.REVOCATION_OPERATOR
        ),
    }
    app = create_admin_app(backend, authenticate=_auth(principals))
    path = "/api/admin/acme/attestations/a-1/supersessions"

    for credential in ("revoker", "issuer"):
        refused = _post(
            app, path, credential=credential, payload={"forged": credential}
        )
        assert refused.status_code == 403, (credential, refused.body)
    assert backend.calls == []

    allowed = _post(app, path, credential="both", payload={"command": "supersede"})
    assert allowed.status_code == 201, allowed.body
    assert [call[0] for call in backend.calls] == ["supersede"]

    # The revoker keeps its own operation; requiring both capabilities for
    # supersession must not have widened or narrowed plain revocation.
    revoked = _post(
        app,
        "/api/admin/acme/attestations/a-1/revocations",
        credential="revoker",
        payload={"command": "revoke"},
    )
    assert revoked.status_code == 201, revoked.body
    assert [call[0] for call in backend.calls] == ["supersede", "revoke"]


def test_console_overview_exposes_status_gaps_and_unmatched_without_write_access() -> None:
    backend = RecordingBackend()
    app = create_admin_app(
        backend,
        authenticate=_auth({"engineering": _principal(AdminRole.ENGINEERING)}),
    )
    response = asyncio.run(
        _request(
            app,
            method="GET",
            path="/api/admin/acme/overview",
            credential="engineering",
        )
    )

    assert response.status_code == 200
    assert response.json() == {
        "coverage_status": "reconciled",
        "gap_count": 2,
        "unmatched_count": 3,
        "attestation_count": 4,
        "subject": "test:engineering",
        "capabilities": ["boundary.manage", "qualification.manage"],
    }


def test_cross_tenant_and_unauthenticated_requests_fail_before_dispatch() -> None:
    backend = RecordingBackend()
    app = create_admin_app(
        backend,
        authenticate=_auth({"issuer": _principal(AdminRole.ATTESTATION_ISSUER)}),
    )
    wrong_tenant = _post(
        app,
        "/api/admin/globex/attestations",
        credential="issuer",
        payload={},
    )
    unauthenticated = _post(
        app,
        "/api/admin/acme/attestations",
        credential=None,
        payload={},
    )
    mismatched_body = _post(
        app,
        "/api/admin/acme/attestations",
        credential="issuer",
        payload={"tenant_id": "globex"},
    )

    assert wrong_tenant.status_code == 403
    assert unauthenticated.status_code == 401
    assert mismatched_body.status_code == 422
    assert backend.calls == []
