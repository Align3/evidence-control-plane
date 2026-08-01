"""Registry tables and their row-level isolation (SE-011, DM-006 amendment 1).

`tenants`, `collectors` and `keys` are not partitioned. `evidence_records`
is, and the difference is deliberate rather than an inconsistency:

* Evidence is always read in a tenant's context, so partitioning costs the
  query nothing and buys the strongest possible statement -- the other
  tenant's rows are in a relation the role cannot name.
* The registry is read by **id**. Ingestion resolves a collector from the
  `collector_id` on an incoming record (SE-018); requiring it to determine
  the tenant first, in order to know which relation to name, would invert
  that dependency for no gain.

So the registry uses row-level security scoped to `current_user`. The rows
of other tenants are not returned to any tenant role, and the exclusion is
in the database rather than in a `WHERE` clause some future code path can
forget. Before this, a `SELECT` grant on `tenants` alone let any customer
enumerate every customer we have.

The owner bypasses these policies (they are `ENABLE`, not `FORCE`), which
is what keeps provisioning and cross-tenant administration possible through
the separately-credentialed path (SE-012 §6). Such operations are logged and
surfaced to the affected tenant under SE-013.
"""

from __future__ import annotations

from sqlalchemy import Connection, text

#: Tables carrying tenant-scoped registry data.
REGISTRY_TABLES: tuple[str, ...] = ("tenants", "collectors", "keys")

#: One policy name across all three, so a missing one is obvious.
TENANT_ISOLATION_POLICY = "tenant_isolation"


def registry_isolation_status(connection: Connection) -> dict[str, dict[str, object]]:
    """Report, per registry table, whether row-level isolation is in force.

    Introspection rather than trust: a table with a policy but with RLS left
    disabled reads exactly like a protected one until someone queries it.
    """
    rows = connection.execute(
        text(
            "SELECT c.relname AS table_name, c.relrowsecurity AS rls_enabled,"
            "       c.relforcerowsecurity AS rls_forced,"
            "       p.policyname, p.cmd, p.qual"
            " FROM pg_class c"
            " LEFT JOIN pg_policies p"
            "   ON p.tablename = c.relname AND p.policyname = :policy"
            " WHERE c.relname = ANY(:tables)"
        ),
        {"policy": TENANT_ISOLATION_POLICY, "tables": list(REGISTRY_TABLES)},
    )
    return {
        row.table_name: {
            "rls_enabled": row.rls_enabled,
            "rls_forced": row.rls_forced,
            "policy": row.policyname,
            "command": row.cmd,
            "predicate": row.qual,
        }
        for row in rows
    }


def assert_registry_isolated(connection: Connection) -> None:
    """Raise unless every registry table has RLS enabled and the policy present.

    Called after provisioning. A registry table that lost its policy is a
    customer list readable by every customer, and it should stop the system
    rather than be discovered later.
    """
    status = registry_isolation_status(connection)
    missing = [
        name
        for name in REGISTRY_TABLES
        if not status.get(name, {}).get("rls_enabled")
        or status.get(name, {}).get("policy") != TENANT_ISOLATION_POLICY
    ]
    if missing:
        raise RuntimeError(
            "registry tables without tenant row-level isolation: "
            f"{sorted(missing)} (SE-011, DM-006)"
        )


__all__ = [
    "REGISTRY_TABLES",
    "TENANT_ISOLATION_POLICY",
    "assert_registry_isolated",
    "registry_isolation_status",
]
