"""Authenticated API and static console for EV-20 administration."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Protocol

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .rbac import (
    AdminPrincipal,
    AuthenticationError,
    AuthorizationError,
    Capability,
    authorize,
)

JsonObject = Mapping[str, Any]
Authenticator = Callable[[Request], AdminPrincipal]


class AdminBackend(Protocol):
    """Operations rendered by the console after authorization succeeds."""

    def overview(self, *, tenant_id: str) -> JsonObject: ...

    def record_boundary(self, *, tenant_id: str, payload: JsonObject) -> JsonObject: ...

    def record_qualification(
        self, *, tenant_id: str, payload: JsonObject
    ) -> JsonObject: ...

    def issue_attestation(
        self, *, tenant_id: str, payload: JsonObject
    ) -> JsonObject: ...

    def revoke_attestation(
        self,
        *,
        tenant_id: str,
        attestation_id: str,
        payload: JsonObject,
    ) -> JsonObject: ...

    def supersede_attestation(
        self,
        *,
        tenant_id: str,
        attestation_id: str,
        payload: JsonObject,
    ) -> JsonObject: ...


def _tenant_payload(payload: dict[str, Any], *, tenant_id: str) -> dict[str, Any]:
    declared = payload.get("tenant_id")
    if declared is not None and declared != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="payload tenant_id disagrees with the authorized route tenant",
        )
    return {**payload, "tenant_id": tenant_id}


def create_admin_app(
    backend: AdminBackend,
    *,
    authenticate: Authenticator,
    static_root: Path | None = None,
) -> FastAPI:
    """Create the admin app.

    Authentication is required as a construction argument: there is no
    development bypass or header-to-permission fallback that can accidentally
    reach production. The authenticator verifies identity; this module alone
    resolves authorization before dispatching to ``backend``.
    """

    app = FastAPI(title="Evidence administration", version="0.1.0")
    assets = static_root or Path(__file__).resolve().parents[2] / "web" / "admin"

    def require(
        *capabilities: Capability,
    ) -> Callable[[Request, str], AdminPrincipal]:
        """Require the exact tenant grant, and every capability named.

        Passing no capability authorizes on the tenant grant alone. Passing
        more than one requires *all* of them, which is what an operation
        whose effect spans two capabilities needs: holding either half must
        not be enough to reach it.
        """

        def dependency(request: Request, tenant_id: str) -> AdminPrincipal:
            try:
                principal = authenticate(request)
            except AuthenticationError as exc:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=str(exc),
                ) from exc
            try:
                authorize(principal, tenant_id=tenant_id)
                for capability in capabilities:
                    authorize(
                        principal,
                        tenant_id=tenant_id,
                        capability=capability,
                    )
            except AuthorizationError as exc:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=str(exc),
                ) from exc
            return principal

        return dependency

    # SE-019 grants four capabilities; the read-only overview deliberately
    # requires none of them beyond the tenant grant (see decision log).
    overview_access = Depends(require())
    boundary_access = Depends(require(Capability.MANAGE_BOUNDARIES))
    qualification_access = Depends(require(Capability.MANAGE_QUALIFICATIONS))
    issuance_access = Depends(require(Capability.ISSUE_ATTESTATIONS))
    revocation_access = Depends(require(Capability.REVOKE_ATTESTATIONS))
    # Supersession both issues a replacement attestation (AR-011: the
    # superseding record is recorded through the same append path as any
    # other issuance) and retires the original. Gating it on revocation
    # alone would let a revocation operator issue attestations without
    # holding `attestation.issue`, which is exactly the separation SE-019
    # draws and SE-020 relies on. It therefore requires both halves.
    supersession_access = Depends(
        require(Capability.ISSUE_ATTESTATIONS, Capability.REVOKE_ATTESTATIONS)
    )

    @app.get("/api/admin/{tenant_id}/overview")
    def overview(
        tenant_id: str,
        principal: AdminPrincipal = overview_access,
    ) -> dict[str, Any]:
        return {
            **backend.overview(tenant_id=tenant_id),
            "subject": principal.subject,
            "capabilities": sorted(item.value for item in principal.capabilities),
        }

    @app.post("/api/admin/{tenant_id}/boundaries", status_code=status.HTTP_201_CREATED)
    def record_boundary(
        tenant_id: str,
        payload: dict[str, Any],
        _principal: AdminPrincipal = boundary_access,
    ) -> JsonObject:
        return backend.record_boundary(
            tenant_id=tenant_id,
            payload=_tenant_payload(payload, tenant_id=tenant_id),
        )

    @app.post(
        "/api/admin/{tenant_id}/qualifications",
        status_code=status.HTTP_201_CREATED,
    )
    def record_qualification(
        tenant_id: str,
        payload: dict[str, Any],
        _principal: AdminPrincipal = qualification_access,
    ) -> JsonObject:
        return backend.record_qualification(
            tenant_id=tenant_id,
            payload=_tenant_payload(payload, tenant_id=tenant_id),
        )

    @app.post(
        "/api/admin/{tenant_id}/attestations",
        status_code=status.HTTP_201_CREATED,
    )
    def issue_attestation(
        tenant_id: str,
        payload: dict[str, Any],
        _principal: AdminPrincipal = issuance_access,
    ) -> JsonObject:
        return backend.issue_attestation(
            tenant_id=tenant_id,
            payload=_tenant_payload(payload, tenant_id=tenant_id),
        )

    @app.post(
        "/api/admin/{tenant_id}/attestations/{attestation_id}/revocations",
        status_code=status.HTTP_201_CREATED,
    )
    def revoke_attestation(
        tenant_id: str,
        attestation_id: str,
        payload: dict[str, Any],
        _principal: AdminPrincipal = revocation_access,
    ) -> JsonObject:
        return backend.revoke_attestation(
            tenant_id=tenant_id,
            attestation_id=attestation_id,
            payload=_tenant_payload(payload, tenant_id=tenant_id),
        )

    @app.post(
        "/api/admin/{tenant_id}/attestations/{attestation_id}/supersessions",
        status_code=status.HTTP_201_CREATED,
    )
    def supersede_attestation(
        tenant_id: str,
        attestation_id: str,
        payload: dict[str, Any],
        _principal: AdminPrincipal = supersession_access,
    ) -> JsonObject:
        return backend.supersede_attestation(
            tenant_id=tenant_id,
            attestation_id=attestation_id,
            payload=_tenant_payload(payload, tenant_id=tenant_id),
        )

    app.mount("/admin/assets", StaticFiles(directory=assets), name="admin-assets")

    @app.get("/admin", include_in_schema=False)
    def admin_index() -> FileResponse:
        return FileResponse(assets / "index.html")

    return app


__all__ = ["AdminBackend", "Authenticator", "JsonObject", "create_admin_app"]
