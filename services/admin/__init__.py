"""Administrative writes: assurance boundaries and denominator qualification.

Reached by the separately-credentialed schema path (SE-012 §6), not by the
ingestion role. Recording a boundary or a qualification is an administrative
act on a tenant's scope declaration, and a role that handles traffic must not
be able to perform it on itself.
"""

from __future__ import annotations

from sqlalchemy import Connection, text

from .boundary import (
    BoundaryError,
    BoundaryVersion,
    DeclaredFamily,
    EffectiveInterval,
    IntervalCoverage,
    UnattestedRecordingTimeError,
    UnqualifiedActionFamilyError,
    boundary_versions,
    effective_interval,
    interval_coverage,
    record_boundary,
)
from .console import AdminBackend, Authenticator, JsonObject, create_admin_app
from .qualification import (
    QUALIFICATION_POSTDATES_WINDOW,
    ClassNotQualifiedError,
    CoverageLevel,
    DenominatorClass,
    Qualification,
    QualificationError,
    QualificationPostdatesWindowError,
    UnqualifiedWindowError,
    assert_class_claimable,
    class_in_force,
    qualification_history,
    record_qualification,
)
from .rbac import (
    ROLE_CAPABILITIES,
    AdminPrincipal,
    AdminRole,
    AuthenticationError,
    AuthorizationError,
    Capability,
    authorize,
)
from .schema import (
    ADMIN_TABLES,
    IMMUTABILITY_TRIGGER_SUFFIX,
    TRUNCATE_TRIGGER_SUFFIX,
)

#: Same policy name the registry uses, so a missing one is obvious across
#: every tenant-scoped relation rather than only within one story's tables.
TENANT_ISOLATION_POLICY = "tenant_isolation"


def admin_isolation_status(connection: Connection) -> dict[str, dict[str, object]]:
    """Per table: row isolation and whether both mutation triggers are armed.

    Introspection rather than trust, following `services.ledger.registry`.
    This reports whether the defense-in-depth triggers are currently enabled;
    it does not make them owner-proof or establish TM-002.
    """
    rows = connection.execute(
        text(
            "SELECT c.relname AS table_name,"
            "       c.relrowsecurity AS rls_enabled,"
            "       p.policyname,"
            "       EXISTS ("
            "         SELECT 1 FROM pg_trigger t"
            "          WHERE t.tgrelid = c.oid"
            "            AND t.tgname = c.relname || :suffix"
            "            AND NOT t.tgisinternal"
            "            AND t.tgenabled <> 'D'"
            "       ) AS immutability_trigger,"
            "       EXISTS ("
            "         SELECT 1 FROM pg_trigger t"
            "          WHERE t.tgrelid = c.oid"
            "            AND t.tgname = c.relname || :truncate_suffix"
            "            AND NOT t.tgisinternal"
            "            AND t.tgenabled <> 'D'"
            "       ) AS truncate_trigger"
            "  FROM pg_class c"
            "  LEFT JOIN pg_policies p"
            "    ON p.tablename = c.relname AND p.policyname = :policy"
            " WHERE c.relname = ANY(:tables)"
        ),
        {
            "policy": TENANT_ISOLATION_POLICY,
            "tables": list(ADMIN_TABLES),
            "suffix": IMMUTABILITY_TRIGGER_SUFFIX,
            "truncate_suffix": TRUNCATE_TRIGGER_SUFFIX,
        },
    )
    return {
        row.table_name: {
            "rls_enabled": row.rls_enabled,
            "policy": row.policyname,
            "immutability_trigger": row.immutability_trigger,
            "truncate_trigger": row.truncate_trigger,
        }
        for row in rows
    }


def assert_admin_tables_protected(connection: Connection) -> None:
    """Raise unless every admin table has isolation and immutability in force."""
    status = admin_isolation_status(connection)
    faults: dict[str, list[str]] = {}
    for name in ADMIN_TABLES:
        table = status.get(name)
        problems: list[str] = []
        if table is None:
            problems.append("table absent")
        else:
            if not table.get("rls_enabled"):
                problems.append("row-level security disabled")
            if table.get("policy") != TENANT_ISOLATION_POLICY:
                problems.append("tenant isolation policy missing")
            if not table.get("immutability_trigger"):
                problems.append("immutability trigger absent or disabled")
            if not table.get("truncate_trigger"):
                problems.append("truncate trigger absent or disabled")
        if problems:
            faults[name] = problems
    if faults:
        raise RuntimeError(
            f"boundary and qualification tables are unprotected: {faults} "
            f"(DM-031, ES-010, SE-011)"
        )


__all__ = [
    "ADMIN_TABLES",
    "ROLE_CAPABILITIES",
    "QUALIFICATION_POSTDATES_WINDOW",
    "TENANT_ISOLATION_POLICY",
    "BoundaryError",
    "BoundaryVersion",
    "ClassNotQualifiedError",
    "AdminBackend",
    "AdminPrincipal",
    "AdminRole",
    "AuthenticationError",
    "Authenticator",
    "AuthorizationError",
    "Capability",
    "CoverageLevel",
    "DeclaredFamily",
    "DenominatorClass",
    "EffectiveInterval",
    "IntervalCoverage",
    "JsonObject",
    "Qualification",
    "QualificationError",
    "QualificationPostdatesWindowError",
    "UnqualifiedActionFamilyError",
    "UnattestedRecordingTimeError",
    "UnqualifiedWindowError",
    "admin_isolation_status",
    "assert_admin_tables_protected",
    "assert_class_claimable",
    "authorize",
    "boundary_versions",
    "class_in_force",
    "create_admin_app",
    "effective_interval",
    "interval_coverage",
    "qualification_history",
    "record_boundary",
    "record_qualification",
]
