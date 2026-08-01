"""Attacks on tenant isolation, kept as permanent regressions (SE-011, AC-014).

Every test here failed against an earlier revision of this story. They are
retained rather than deleted because the defects they describe are silent:
each one produced a correct-looking system that returned another tenant's
evidence, and none of them was visible in the acceptance suite.

Two of them are worth reading before changing anything in `engine.py` or
`tenancy.py`:

* the role-escape family. The original design authenticated as one shared
  login holding membership in every tenant role, and assumed a tenant with
  ``SET LOCAL ROLE``. Membership cannot be scoped to a connection, so any
  statement reaching the database could ``RESET ROLE`` and assume a
  different tenant -- including a statement introduced by SQL injection,
  which is the query-layer attack SE-011 requires be impossible rather than
  merely unused.

* the ownership family. Registry isolation is row-level security, and
  ``ENABLE ROW LEVEL SECURITY`` does not apply to the table owner. If any
  role the application can authenticate as ever owns a registry table, the
  isolation evaporates with no error and no failing query. The isolation
  tests do not catch it on their own, because they query as a tenant role
  which is not the owner either way -- so ownership is pinned directly.
"""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError, ProgrammingError

from services.ledger import (
    EVIDENCE_PARENT_TABLE,
    TenantEngines,
    application_role,
    partition_name,
    tenant_connection,
)
from services.ledger.naming import TENANT_ROLE_PREFIX
from tests.ledger_support import INSUFFICIENT_PRIVILEGE, TENANT_A, TENANT_B

REGISTRY_TABLES = ("tenants", "collectors", "keys")


# --- role escape -----------------------------------------------------------


def test_stacked_statements_cannot_change_role_mid_transaction(
    tenant_engines: TenantEngines,
    populated_ledger: dict[str, list[dict[str, Any]]],
) -> None:
    """One driver call carrying stacked statements must not cross tenants.

    This is the injection shape: the payload is not a second round trip the
    application chose to make, it rides along on a query the application
    already intended to issue. Against the shared-login design it succeeded
    and returned Globex's row count to an Acme session.
    """
    with tenant_connection(tenant_engines, TENANT_A) as conn:
        with pytest.raises(DBAPIError) as caught:
            conn.exec_driver_sql(
                f'SELECT 1; RESET ROLE; SET ROLE "{application_role(TENANT_B)}"; '  # noqa: S608 -- the injection IS the test
                f'SELECT count(*) FROM "{partition_name(TENANT_B)}"'
            )
        assert getattr(caught.value.orig, "sqlstate", None) == INSUFFICIENT_PRIVILEGE


@pytest.mark.parametrize(
    "statement",
    [
        'SET ROLE "{other}"',
        'SET LOCAL ROLE "{other}"',
        "RESET ROLE",
        'SET SESSION AUTHORIZATION "{other}"',
    ],
)
def test_a_tenant_session_cannot_become_another_role(
    tenant_engines: TenantEngines,
    populated_ledger: dict[str, list[dict[str, Any]]],
    statement: str,
) -> None:
    """Every way of spelling "become someone else" is refused by the server.

    ``RESET ROLE`` is included deliberately: it is a no-op for a session that
    authenticated as the tenant rather than assuming it, and it must stay a
    no-op rather than dropping the session to a wider identity.
    """
    sql = statement.format(other=application_role(TENANT_B))
    with tenant_connection(tenant_engines, TENANT_A) as conn:
        try:
            conn.exec_driver_sql(sql)
        except DBAPIError as exc:
            assert getattr(exc.orig, "sqlstate", None) == INSUFFICIENT_PRIVILEGE
            return
        # RESET ROLE is permitted, but must leave the tenant where it was.
        who = conn.execute(text("SELECT current_user")).scalar_one()
        assert who == application_role(TENANT_A), (
            f"{sql!r} moved the session to {who!r}"
        )


def test_no_role_holds_membership_in_any_tenant_role(owner_engine: Engine) -> None:
    """Membership is what makes a cross-tenant SET ROLE possible at all.

    Asserted against the catalogue rather than against the provisioning
    source, so a convenience grant added by a later story fails here.
    """
    with owner_engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT member.rolname AS member, granted.rolname AS granted"
                " FROM pg_auth_members am"
                " JOIN pg_roles member ON member.oid = am.member"
                " JOIN pg_roles granted ON granted.oid = am.roleid"
                " WHERE granted.rolname LIKE :prefix"
            ),
            {"prefix": f"{TENANT_ROLE_PREFIX}%"},
        ).all()
    assert rows == [], (
        "tenant roles are granted to other roles, which makes a cross-tenant "
        f"SET ROLE possible: {[(r.member, r.granted) for r in rows]}"
    )


def test_tenant_login_cannot_authenticate_as_another_tenant(
    tenant_engines: TenantEngines, tenants: list[str]
) -> None:
    """The credential is per tenant, so Acme's password is not Globex's."""
    from services.ledger import LedgerConfig

    config = LedgerConfig.from_env()
    assert config.tenant_password(TENANT_A) != config.tenant_password(TENANT_B)


# --- ownership -------------------------------------------------------------


def _login_roles(conn: Any) -> set[str]:
    """Every role an application could authenticate as."""
    return {
        row.rolname
        for row in conn.execute(
            text(
                "SELECT rolname FROM pg_roles"
                " WHERE rolcanlogin AND NOT rolsuper"
                "   AND (rolname LIKE :prefix OR rolname = 'evidence_app')"
            ),
            {"prefix": f"{TENANT_ROLE_PREFIX}%"},
        )
    }


def test_no_application_login_owns_a_registry_or_evidence_relation(
    owner_engine: Engine, tenants: list[str]
) -> None:
    """RLS is ENABLE, not FORCE, so the owner bypasses every policy.

    An application-reachable role owning `tenants` reads every customer's
    row with no error raised and no policy violated. The cross-tenant
    isolation tests do not catch it -- they query as a tenant role, which is
    not the owner in either case -- so ownership is pinned here directly.
    """
    with owner_engine.connect() as conn:
        logins = _login_roles(conn)
        owners = conn.execute(
            text(
                "SELECT c.relname, pg_get_userbyid(c.relowner) AS owner"
                " FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
                " WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')"
                "   AND (c.relname = ANY(:tables) OR c.relname LIKE :partitions)"
            ),
            {
                "tables": [*REGISTRY_TABLES, EVIDENCE_PARENT_TABLE],
                "partitions": f"{EVIDENCE_PARENT_TABLE}\\_%",
            },
        ).all()
    assert owners, "found no relations to check -- the query is wrong, not the schema"
    offenders = [(row.relname, row.owner) for row in owners if row.owner in logins]
    assert offenders == [], (
        "a role the application can log in as owns these relations and "
        f"therefore bypasses row-level security: {offenders}"
    )


def test_registry_row_level_security_is_enabled_on_every_registry_table(
    owner_engine: Engine, tenants: list[str]
) -> None:
    """A policy on a table with RLS disabled reads exactly like protection."""
    with owner_engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT relname, relrowsecurity FROM pg_class"
                " WHERE relname = ANY(:tables)"
            ),
            {"tables": list(REGISTRY_TABLES)},
        ).all()
    disabled = [row.relname for row in rows if not row.relrowsecurity]
    assert disabled == [], f"row-level security is off on {disabled}"


# --- the unscoped login ----------------------------------------------------


@pytest.mark.parametrize(
    "relation", [*REGISTRY_TABLES, EVIDENCE_PARENT_TABLE, "evidence_records_acme"]
)
def test_unscoped_login_is_refused_rather_than_returning_no_rows(
    application_engine: Engine,
    populated_ledger: dict[str, list[dict[str, Any]]],
    relation: str,
) -> None:
    """An authenticated connection with no tenant credential reaches nothing.

    It fails closed with insufficient privilege rather than succeeding and
    returning an empty result. The distinction matters: an empty result is
    indistinguishable from "this tenant has no evidence", and a caller that
    treats the two alike would report an absence it never established.
    """
    with application_engine.connect() as conn:
        assert conn.execute(text("SELECT current_user")).scalar_one() == "evidence_app"
        with pytest.raises(ProgrammingError) as caught:
            conn.execute(text(f'SELECT count(*) FROM "{relation}"'))  # noqa: S608
        assert getattr(caught.value.orig, "sqlstate", None) == INSUFFICIENT_PRIVILEGE


# --- session identity across transaction boundaries ------------------------


def test_tenant_identity_holds_across_commit_rollback_and_savepoints(
    tenant_engines: TenantEngines,
    populated_ledger: dict[str, list[dict[str, Any]]],
) -> None:
    """The session is its tenant on every path in and out of a transaction.

    Under the shared-login design this was a question about whether a role
    leaked into the pool. It is now a question about whether the connection
    is ever anything other than the tenant it authenticated as -- which it
    must not be, including after an error rolls a transaction back.
    """
    role = application_role(TENANT_A)

    with tenant_connection(tenant_engines, TENANT_A) as conn:
        assert conn.execute(text("SELECT current_user")).scalar_one() == role

    with pytest.raises(RuntimeError):
        with tenant_connection(tenant_engines, TENANT_A) as conn:
            raise RuntimeError("mid-transaction application exception")

    with tenant_connection(tenant_engines, TENANT_A) as conn:
        nested = conn.begin_nested()
        nested.rollback()
        assert conn.execute(text("SELECT current_user")).scalar_one() == role

    with tenant_connection(tenant_engines, TENANT_A) as conn:
        with pytest.raises(DBAPIError):
            with conn.begin_nested():
                conn.execute(text("SELECT 1 / 0"))
        assert conn.execute(text("SELECT current_user")).scalar_one() == role

    # And the next checkout from the pool is still, and only, this tenant.
    with tenant_connection(tenant_engines, TENANT_A) as conn:
        assert conn.execute(text("SELECT current_user")).scalar_one() == role
        with pytest.raises(ProgrammingError):
            conn.execute(text(f'SELECT 1 FROM "{partition_name(TENANT_B)}"'))  # noqa: S608
