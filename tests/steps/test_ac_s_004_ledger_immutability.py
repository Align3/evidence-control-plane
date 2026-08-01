"""AC-S-004 -- Ledger immutability enforced at the database (AC-012, SE-012).

The trap this file exists to avoid: an implementation that merely never
issues UPDATE or DELETE. Every statement below is raw SQL executed under
the real application login role. Nothing here passes through an ORM
mapper, a repository class, or any application-layer guard -- so a pass
means Postgres refused, and nothing else could have.
"""

from __future__ import annotations

from typing import Any

import pytest
from pytest_bdd import given, scenario, then, when
from sqlalchemy import Engine, text
from sqlalchemy.exc import ProgrammingError

from services.ledger import (
    EVIDENCE_PARENT_TABLE,
    TenantEngines,
    application_role,
    partition_name,
    tenant_connection,
)
from tests.ledger_support import INSUFFICIENT_PRIVILEGE, TENANT_A


@scenario("architecture.feature", "AC-S-004 Ledger immutability enforced at the database")
def test_ac_s_004() -> None:
    """Bound by pytest-bdd."""


@given("the application database role", target_fixture="app_role_context")
def _app_role_context(
    tenant_engines: TenantEngines,
    populated_ledger: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    """The role the ingestion service runs as, holding a populated ledger.

    Asserts up front that the role really is the application role and not
    a superuser or the table owner -- if it were, the refusals below would
    prove nothing.
    """
    with tenant_connection(tenant_engines, TENANT_A) as conn:
        current, is_super, owner = conn.execute(
            text(
                "SELECT current_user,"
                " (SELECT rolsuper FROM pg_roles WHERE rolname = current_user),"
                " pg_catalog.pg_get_userbyid(c.relowner)"
                " FROM pg_class c WHERE c.relname = :partition"
            ),
            {"partition": partition_name(TENANT_A)},
        ).one()
        assert current == application_role(TENANT_A)
        assert is_super is False, "the application role must not be a superuser"
        assert current != owner, "the application role must not own the evidence table"
        (visible,) = conn.execute(
            text(f'SELECT count(*) FROM "{partition_name(TENANT_A)}"')  # noqa: S608
        ).one()
        assert visible > 0, "SELECT must be granted -- immutability is not opacity"
    return {"tenant_id": TENANT_A, "rows_before": visible}


@when("an UPDATE or DELETE is attempted on the evidence table",
      target_fixture="mutation_attempts")
def _mutation_attempts(
    tenant_engines: TenantEngines, app_role_context: dict[str, Any]
) -> list[dict[str, Any]]:
    """Four raw attempts: UPDATE and DELETE, against the partition and the parent."""
    tenant_id = app_role_context["tenant_id"]
    partition = partition_name(tenant_id)
    statements = {
        "UPDATE partition": f'UPDATE "{partition}" SET body = \'{{}}\'::jsonb',  # noqa: S608
        "DELETE partition": f'DELETE FROM "{partition}"',  # noqa: S608
        "UPDATE parent": f'UPDATE "{EVIDENCE_PARENT_TABLE}" SET body = \'{{}}\'::jsonb',  # noqa: S608
        "DELETE parent": f'DELETE FROM "{EVIDENCE_PARENT_TABLE}"',  # noqa: S608
    }
    attempts: list[dict[str, Any]] = []
    for label, sql in statements.items():
        try:
            with tenant_connection(tenant_engines, tenant_id) as conn:
                conn.execute(text(sql))  # noqa: S608 -- identifiers are validated
        except ProgrammingError as exc:
            attempts.append({"label": label, "sql": sql, "error": exc})
        else:
            attempts.append({"label": label, "sql": sql, "error": None})
    return attempts


@then("the database rejects it")
def _database_rejects(mutation_attempts: list[dict[str, Any]]) -> None:
    for attempt in mutation_attempts:
        error = attempt["error"]
        assert error is not None, (
            f"{attempt['label']} succeeded -- the evidence ledger is mutable"
        )
        sqlstate = getattr(error.orig, "sqlstate", None)
        assert sqlstate == INSUFFICIENT_PRIVILEGE, (
            f"{attempt['label']} failed with SQLSTATE {sqlstate}, expected "
            f"{INSUFFICIENT_PRIVILEGE} (insufficient_privilege): {error.orig}"
        )


@then("the rejection is not dependent on application-layer checks")
def _not_application_layer(
    tenant_engines: TenantEngines,
    owner_engine: Engine, app_role_context: dict[str, Any]
) -> None:
    """The catalogue is the evidence: the privilege is absent, not intercepted.

    Read through the owner connection. `information_schema.table_privileges`
    only shows a grant to a role the *current* user inherits, and the
    application login role deliberately inherits nothing -- so asking it
    would return an empty set for the wrong reason.
    """
    tenant_id = app_role_context["tenant_id"]
    role = application_role(tenant_id)
    with owner_engine.connect() as conn:
        granted = {
            row.privilege_type
            for row in conn.execute(
                text(
                    "SELECT privilege_type FROM information_schema.table_privileges"
                    " WHERE grantee = :role AND table_name = :partition"
                ),
                {"role": role, "partition": partition_name(tenant_id)},
            )
        }
        assert granted == {"INSERT", "SELECT"}, (
            f"role {role} holds {sorted(granted)}; DM-004/SE-012 permit only "
            "INSERT and SELECT"
        )
        for privilege in ("UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"):
            for table in (partition_name(tenant_id), EVIDENCE_PARENT_TABLE):
                (has_privilege,) = conn.execute(
                    text("SELECT has_table_privilege(:role, :table, :privilege)"),
                    {"role": role, "table": table, "privilege": privilege},
                ).one()
                assert has_privilege is False, (
                    f"{role} holds {privilege} on {table}"
                )
    # And the row count is unchanged: nothing was quietly swallowed.
    with tenant_connection(tenant_engines, tenant_id) as conn:
        (rows_after,) = conn.execute(
            text(f'SELECT count(*) FROM "{partition_name(tenant_id)}"')  # noqa: S608
        ).one()
    assert rows_after == app_role_context["rows_before"]


# --- Beyond the scenario ----------------------------------------------------


def test_no_application_role_holds_update_or_delete_on_any_evidence_table(
    owner_engine: Engine, tenants: list[str]
) -> None:
    """SE-012: not merely 'the role under test' -- *no* application role.

    Scans every grant on every evidence relation, so a future migration that
    hands UPDATE to some new role fails here rather than in production.
    """
    with owner_engine.connect() as conn:
        offenders = conn.execute(
            text(
                "SELECT grantee, table_name, privilege_type"
                " FROM information_schema.table_privileges"
                " WHERE (table_name = :parent OR table_name LIKE :pattern)"
                "   AND privilege_type IN ('UPDATE', 'DELETE', 'TRUNCATE')"
                "   AND grantee <> (SELECT current_user)"
            ),
            {"parent": EVIDENCE_PARENT_TABLE, "pattern": f"{EVIDENCE_PARENT_TABLE}\\_%"},
        ).all()
    assert offenders == [], (
        "mutation privileges granted on evidence tables: "
        + ", ".join(f"{r.grantee} holds {r.privilege_type} on {r.table_name}"
                    for r in offenders)
    )
    assert tenants  # provisioned tenants are what make the scan non-vacuous


def test_truncate_is_refused(
    tenant_engines: TenantEngines, populated_ledger: dict[str, list[dict[str, Any]]]
) -> None:
    """TRUNCATE is neither UPDATE nor DELETE and erases just as much."""
    with pytest.raises(ProgrammingError) as caught:
        with tenant_connection(tenant_engines, TENANT_A) as conn:
            conn.execute(text(f'TRUNCATE "{partition_name(TENANT_A)}"'))  # noqa: S608
    assert getattr(caught.value.orig, "sqlstate", None) == INSUFFICIENT_PRIVILEGE


def test_ddl_disguised_mutation_is_refused(
    tenant_engines: TenantEngines, populated_ledger: dict[str, list[dict[str, Any]]]
) -> None:
    """Immutability that DROP or ALTER can undo is not immutability."""
    partition = partition_name(TENANT_A)
    for sql in (
        f'DROP TABLE "{partition}"',
        f'ALTER TABLE "{partition}" DROP COLUMN canonical_bytes',
        f'ALTER TABLE "{partition}" ALTER COLUMN body DROP NOT NULL',
    ):
        with pytest.raises(ProgrammingError) as caught:
            with tenant_connection(tenant_engines, TENANT_A) as conn:
                conn.execute(text(sql))
        assert getattr(caught.value.orig, "sqlstate", None) == INSUFFICIENT_PRIVILEGE, (
            f"{sql} was not refused"
        )


def test_canonical_bytes_cannot_be_rewritten_by_reinsert(
    tenant_engines: TenantEngines,
    populated_ledger: dict[str, list[dict[str, Any]]],
) -> None:
    """INSERT is granted; overwriting history through it must still fail.

    A role with INSERT but not UPDATE can still rewrite the ledger if the
    primary key does not stop it, or if ON CONFLICT DO UPDATE is reachable.
    """
    from services.ledger import evidence_partition

    original = populated_ledger[TENANT_A][0]
    partition = evidence_partition(TENANT_A)
    tampered = dict(original)
    tampered["canonical_bytes"] = b'{"tampered":true}'
    tampered["body"] = {}

    with pytest.raises(Exception) as caught:  # noqa: B017 -- integrity or privilege
        with tenant_connection(tenant_engines, TENANT_A) as conn:
            conn.execute(partition.insert(), tampered)
    sqlstate = getattr(caught.value.orig, "sqlstate", None)  # type: ignore[attr-defined]
    assert sqlstate == "23505", f"expected unique_violation, got {sqlstate}"

    with pytest.raises(ProgrammingError) as upsert:
        with tenant_connection(tenant_engines, TENANT_A) as conn:
            conn.execute(
                text(
                    f'INSERT INTO "{partition_name(TENANT_A)}" AS e'  # noqa: S608
                    " (record_id, tenant_id, record_type, schema_version, boundary_ref,"
                    "  stream_id, sequence, record_digest, collector_id, key_id,"
                    "  signature, source_time, ingest_time, clock_skew_ms,"
                    "  canonical_bytes, body)"
                    " SELECT record_id, tenant_id, record_type, schema_version,"
                    "  boundary_ref, stream_id, sequence, record_digest, collector_id,"
                    "  key_id, signature, source_time, ingest_time, clock_skew_ms,"
                    "  canonical_bytes, body FROM \"" + partition_name(TENANT_A) + '" '
                    " ON CONFLICT (tenant_id, record_id)"
                    " DO UPDATE SET canonical_bytes = '\\x00'::bytea"
                )
            )
    assert getattr(upsert.value.orig, "sqlstate", None) == INSUFFICIENT_PRIVILEGE, (
        "ON CONFLICT DO UPDATE reached the table -- INSERT alone must not "
        "permit an upsert"
    )
