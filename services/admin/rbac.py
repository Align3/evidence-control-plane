"""Fail-closed role separation for the EV-20 administrative surface."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType


class Capability(StrEnum):
    """The four independently grantable administrative actions in SE-019."""

    MANAGE_BOUNDARIES = "boundary.manage"
    MANAGE_QUALIFICATIONS = "qualification.manage"
    ISSUE_ATTESTATIONS = "attestation.issue"
    REVOKE_ATTESTATIONS = "attestation.revoke"


class AdminRole(StrEnum):
    ENGINEERING = "engineering"
    BOUNDARY_MANAGER = "boundary_manager"
    QUALIFICATION_MANAGER = "qualification_manager"
    ATTESTATION_ISSUER = "attestation_issuer"
    REVOCATION_OPERATOR = "revocation_operator"


_ROLE_CAPABILITIES: dict[AdminRole, frozenset[Capability]] = {
    AdminRole.ENGINEERING: frozenset(
        {Capability.MANAGE_BOUNDARIES, Capability.MANAGE_QUALIFICATIONS}
    ),
    AdminRole.BOUNDARY_MANAGER: frozenset({Capability.MANAGE_BOUNDARIES}),
    AdminRole.QUALIFICATION_MANAGER: frozenset(
        {Capability.MANAGE_QUALIFICATIONS}
    ),
    AdminRole.ATTESTATION_ISSUER: frozenset({Capability.ISSUE_ATTESTATIONS}),
    AdminRole.REVOCATION_OPERATOR: frozenset({Capability.REVOKE_ATTESTATIONS}),
}
ROLE_CAPABILITIES: Mapping[AdminRole, frozenset[Capability]] = MappingProxyType(
    _ROLE_CAPABILITIES
)


class AuthenticationError(PermissionError):
    """The request has no authenticated administrative identity."""


class AuthorizationError(PermissionError):
    """An identity is authenticated but lacks tenant access or capability."""


@dataclass(frozen=True, slots=True)
class AdminPrincipal:
    subject: str
    tenants: frozenset[str]
    capabilities: frozenset[Capability]

    @classmethod
    def from_roles(
        cls,
        *,
        subject: str,
        tenants: Iterable[str],
        roles: Iterable[AdminRole],
    ) -> AdminPrincipal:
        tenant_set = frozenset(tenants)
        if not subject or not tenant_set or any(not tenant for tenant in tenant_set):
            raise ValueError("an admin principal needs a subject and explicit tenants")
        capabilities = frozenset(
            capability for role in roles for capability in ROLE_CAPABILITIES[role]
        )
        return cls(
            subject=subject,
            tenants=tenant_set,
            capabilities=capabilities,
        )


def authorize(
    principal: AdminPrincipal,
    *,
    tenant_id: str,
    capability: Capability | None = None,
) -> None:
    """Authorize only exact tenant grants and exact capabilities.

    There is deliberately no wildcard tenant and no implicit capability
    inheritance. A future role therefore cannot accidentally become an issuer
    merely by being described as "admin" or "engineering".
    """

    if tenant_id not in principal.tenants:
        raise AuthorizationError(f"no administrative access to tenant {tenant_id!r}")
    if capability is not None and capability not in principal.capabilities:
        raise AuthorizationError(f"missing capability {capability.value!r}")


__all__ = [
    "ROLE_CAPABILITIES",
    "AdminPrincipal",
    "AdminRole",
    "AuthenticationError",
    "AuthorizationError",
    "Capability",
    "authorize",
]
