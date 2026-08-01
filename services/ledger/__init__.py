"""The evidence ledger (EV-06).

An append-only, per-tenant-partitioned store whose immutability and tenant
isolation are properties of the **database**, not of this package. Nothing
here checks whether a caller is allowed to update or delete a record;
Postgres refuses because the privilege was never granted (AC-012, SE-012),
and a cross-tenant read is refused because the role that could name the
other partition does not exist (SE-011, AC-014).

The distinction matters: application-layer enforcement is defeated by any
code path that forgets to call it, and there is always one.

Entry points:

* `tenant_connection(TenantEngines(), tenant_id)` -- the only sanctioned way to
  read or append evidence;
* `evidence_partition(tenant_id)` -- a table handle scoped to one tenant;
* `migrator_engine()` -- the separately-credentialed schema path, used by
  `provision_tenant` and `rebuild_projection` and by nothing that serves
  traffic.
"""

from __future__ import annotations

from .config import (
    APP_LOGIN_ROLE,
    APP_PASSWORD_ENV,
    DEFAULT_APP_PASSWORD,
    LedgerConfig,
)
from .digests import (
    DIGEST_PREFIX,
    digest_bytes,
    digest_matches,
    digest_ref,
    parse_digest_ref,
)
from .engine import TenantEngines, app_engine, migrator_engine, tenant_connection
from .naming import (
    APP_GRANTS,
    EVIDENCE_PARENT_TABLE,
    REGISTRY_READER_ROLE,
    TENANT_ID_SQL_PATTERN,
    application_role,
    partition_name,
    validate_tenant_id,
)
from .projection import (
    ProjectionMismatch,
    drop_projection,
    projection_columns_present,
    rebuild_projection,
    verify_projection,
)
from .registry import (
    REGISTRY_TABLES,
    TENANT_ISOLATION_POLICY,
    assert_registry_isolated,
    registry_isolation_status,
)
from .schema import (
    CANONICAL_DERIVED_COLUMNS,
    PROJECTION_COLUMNS,
    REPAIRABLE_DERIVED_COLUMNS,
    VERIFIED_HEADER_COLUMNS,
    collectors,
    evidence_partition,
    keys,
    metadata,
    tenants,
)
from .tenancy import FORBIDDEN_GRANTS, deprovision_tenant, provision_tenant

__all__ = [
    "APP_GRANTS",
    "APP_LOGIN_ROLE",
    "APP_PASSWORD_ENV",
    "DEFAULT_APP_PASSWORD",
    "DIGEST_PREFIX",
    "EVIDENCE_PARENT_TABLE",
    "FORBIDDEN_GRANTS",
    "CANONICAL_DERIVED_COLUMNS",
    "PROJECTION_COLUMNS",
    "REPAIRABLE_DERIVED_COLUMNS",
    "REGISTRY_READER_ROLE",
    "REGISTRY_TABLES",
    "TENANT_ID_SQL_PATTERN",
    "TENANT_ISOLATION_POLICY",
    "VERIFIED_HEADER_COLUMNS",
    "LedgerConfig",
    "ProjectionMismatch",
    "TenantEngines",
    "app_engine",
    "application_role",
    "assert_registry_isolated",
    "collectors",
    "deprovision_tenant",
    "digest_bytes",
    "digest_matches",
    "digest_ref",
    "drop_projection",
    "evidence_partition",
    "keys",
    "metadata",
    "migrator_engine",
    "parse_digest_ref",
    "partition_name",
    "projection_columns_present",
    "provision_tenant",
    "rebuild_projection",
    "registry_isolation_status",
    "tenant_connection",
    "tenants",
    "validate_tenant_id",
    "verify_projection",
]
