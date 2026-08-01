"""Identifier derivation for per-tenant partitions and roles.

`tenant_id` reaches SQL identifiers, so the mapping has to be both safe and
**injective**: two distinct tenants must never derive the same partition or
role name, or isolation collapses silently. Rather than escaping a permissive
identifier, the tenant id itself is constrained to a character set that maps
one-to-one onto identifiers, and the constraint is enforced by a CHECK on
``tenants`` as well as here.
"""

from __future__ import annotations

import re

#: The parent partitioned table. Application roles hold no privilege on it;
#: naming it is how a cross-tenant read would be spelled, so it must fail
#: (SE-011, AC-014).
EVIDENCE_PARENT_TABLE = "evidence_records"

PARTITION_PREFIX = f"{EVIDENCE_PARENT_TABLE}_"
TENANT_ROLE_PREFIX = "evidence_tenant_"

#: Group role holding SELECT on the registry tables (`tenants`, `collectors`,
#: `keys`). Every tenant role is a member; it holds nothing on evidence.
REGISTRY_READER_ROLE = "evidence_registry_reader"

#: The complete privilege set any application role may hold on evidence
#: (DM-004, AC-012, SE-012). This tuple is the single place the answer is
#: written down; provisioning asserts against it and the acceptance test
#: reads it back out of the catalogue.
APP_GRANTS: tuple[str, ...] = ("INSERT", "SELECT")

# Lowercase alphanumerics and underscores, not starting or ending with an
# underscore. No hyphens, no case: the mapping to an identifier is then the
# identity function, so it cannot collide.
_TENANT_ID = re.compile(r"^[a-z0-9](?:[a-z0-9_]{0,46}[a-z0-9])?$")

#: The same rule, as a SQL predicate, for the CHECK constraint on `tenants`.
TENANT_ID_SQL_PATTERN = "^[a-z0-9]([a-z0-9_]{0,46}[a-z0-9])?$"


def validate_tenant_id(tenant_id: str) -> str:
    """Return `tenant_id` unchanged, or raise.

    Called before any identifier is interpolated into DDL. The regex is
    anchored and rejects quotes, so no injection survives it.
    """
    if not _TENANT_ID.fullmatch(tenant_id):
        raise ValueError(
            f"invalid tenant_id {tenant_id!r}: must match {TENANT_ID_SQL_PATTERN}"
        )
    return tenant_id


def partition_name(tenant_id: str) -> str:
    """Name of the tenant's evidence partition."""
    return f"{PARTITION_PREFIX}{validate_tenant_id(tenant_id)}"


def application_role(tenant_id: str) -> str:
    """Name of the role the application assumes when acting for this tenant.

    This is the role that holds `INSERT` and `SELECT` on exactly one
    partition. It is what `current_user` reports inside a tenant session.
    """
    return f"{TENANT_ROLE_PREFIX}{validate_tenant_id(tenant_id)}"
