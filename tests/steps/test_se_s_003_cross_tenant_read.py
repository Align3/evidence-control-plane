"""SE-S-003 -- Cross-tenant read not expressible (SE-011, AC-014, DM-006).

The requirement is structural, not filtered: a cross-tenant read must fail
because no application role can name more than one tenant's evidence, not
because a `WHERE tenant_id = ...` was appended somewhere.

The mechanism under test: `evidence_records` is LIST-partitioned by
`tenant_id`; no application role holds any privilege on the parent; each
tenant role holds INSERT/SELECT on its own partition only; and the login
role is NOINHERIT, so holding membership in two tenant roles still grants
nothing until one is explicitly assumed.

Not listed under EV-06's Acceptance field, which names only AC-S-004 and
AC-S-006 -- but EV-06 declares SE-011 under Satisfies and no other story
claims it, so it is carried here.
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
from tests.ledger_support import INSUFFICIENT_PRIVILEGE, TENANT_A, TENANT_B


@scenario("security.feature", "SE-S-003 Cross-tenant read not expressible")
def test_se_s_003() -> None:
    """Bound by pytest-bdd."""


@given("a query attempting to read records across two tenants",
       target_fixture="cross_tenant_queries")
def _cross_tenant_queries(
    populated_ledger: dict[str, list[dict[str, Any]]],
) -> dict[str, str]:
    """Every way of spelling it, none of which mentions a tenant filter."""
    a, b = partition_name(TENANT_A), partition_name(TENANT_B)
    queries = {
        "union of both partitions":
            f'SELECT record_id FROM "{a}" UNION ALL SELECT record_id FROM "{b}"',  # noqa: S608
        "join across partitions":
            f'SELECT x.record_id FROM "{a}" x JOIN "{b}" y ON x.sequence = y.sequence',  # noqa: S608
        "scan of the parent table":
            f'SELECT record_id FROM "{EVIDENCE_PARENT_TABLE}"',  # noqa: S608
        "subquery into the other tenant":
            f'SELECT record_id FROM "{a}" WHERE sequence IN'  # noqa: S608
            f' (SELECT sequence FROM "{b}")',
        "the other tenant alone":
            f'SELECT record_id FROM "{b}"',  # noqa: S608
    }
    for sql in queries.values():
        assert "tenant_id =" not in sql, (
            "the query must not carry a tenant filter -- filtering is the "
            "design SE-011 rejects"
        )
    return queries


@when("it is executed under any application role", target_fixture="cross_tenant_results")
def _execute_under_each_role(
    tenant_engines: TenantEngines,
    application_engine: Engine, cross_tenant_queries: dict[str, str]
) -> list[dict[str, Any]]:
    """'Any' means each tenant role in turn, and the bare login role."""
    results: list[dict[str, Any]] = []
    for role_label, tenant_id in (
        (application_role(TENANT_A), TENANT_A),
        (application_role(TENANT_B), TENANT_B),
        ("login role, no tenant assumed", None),
    ):
        for label, sql in cross_tenant_queries.items():
            if tenant_id == TENANT_B and label == "the other tenant alone":
                continue  # not cross-tenant for globex; covered by the A case
            try:
                if tenant_id is None:
                    with application_engine.connect() as conn:
                        conn.execute(text(sql)).all()
                else:
                    with tenant_connection(tenant_engines, tenant_id) as conn:
                        conn.execute(text(sql)).all()
            except ProgrammingError as exc:
                error: ProgrammingError | None = exc
            else:
                error = None
            results.append(
                {"role": role_label, "query": label, "sql": sql, "error": error}
            )
    return results


@then("it fails at the database layer")
def _fails_at_database(cross_tenant_results: list[dict[str, Any]]) -> None:
    for result in cross_tenant_results:
        error = result["error"]
        assert error is not None, (
            f"{result['role']} executed '{result['query']}' successfully -- "
            "a cross-tenant read is expressible"
        )
        sqlstate = getattr(error.orig, "sqlstate", None)
        assert sqlstate == INSUFFICIENT_PRIVILEGE, (
            f"{result['role']} / {result['query']}: SQLSTATE {sqlstate}, "
            f"expected {INSUFFICIENT_PRIVILEGE}: {error.orig}"
        )


@then("the failure does not depend on an application-layer filter")
def _no_application_filter(
    owner_engine: Engine, cross_tenant_results: list[dict[str, Any]]
) -> None:
    """Two independent confirmations.

    First: the queries themselves carried no tenant predicate, and were
    handed to the driver as raw SQL. Second: the catalogue shows the
    privilege is simply absent -- there is nothing to filter.
    """
    for result in cross_tenant_results:
        assert "tenant_id" not in result["sql"]

    with owner_engine.connect() as conn:
        for role in (application_role(TENANT_A), application_role(TENANT_B)):
            other = partition_name(
                TENANT_B if role == application_role(TENANT_A) else TENANT_A
            )
            for table in (other, EVIDENCE_PARENT_TABLE):
                (has_select,) = conn.execute(
                    text("SELECT has_table_privilege(:role, :table, 'SELECT')"),
                    {"role": role, "table": table},
                ).one()
                assert has_select is False, f"{role} can SELECT {table}"
        # No row-level policy is doing the work -- there is none to lean on.
        policies = conn.execute(
            text("SELECT policyname FROM pg_policies WHERE tablename LIKE :pattern"),
            {"pattern": f"{EVIDENCE_PARENT_TABLE}%"},
        ).all()
        assert policies == [], (
            "a row-level security policy is present on the evidence tables. "
            "Evidence is always read in a tenant's context, so partitioning "
            "costs nothing and gives the stronger guarantee -- the relation "
            "cannot be named at all. A policy here would be a weaker "
            "mechanism chosen for no reason. (The registry tables do use "
            "RLS, because they are read by id: DM-006, DM-022.)"
        )


# --- Beyond the scenario ----------------------------------------------------


def test_own_partition_remains_readable(
    tenant_engines: TenantEngines, populated_ledger: dict[str, list[dict[str, Any]]]
) -> None:
    """Isolation that also blocks the legitimate read proves nothing."""
    for tenant_id in (TENANT_A, TENANT_B):
        with tenant_connection(tenant_engines, tenant_id) as conn:
            rows = conn.execute(
                text(f'SELECT tenant_id FROM "{partition_name(tenant_id)}"')  # noqa: S608
            ).all()
        assert rows, f"{tenant_id} cannot read its own evidence"
        assert {r.tenant_id for r in rows} == {tenant_id}


def test_login_role_inherits_no_tenant_privileges(application_engine: Engine) -> None:
    """The login role is a member of every tenant role. NOINHERIT is what stops
    that membership becoming a cross-tenant read."""
    with application_engine.connect() as conn:
        (inherits,) = conn.execute(
            text("SELECT rolinherit FROM pg_roles WHERE rolname = current_user")
        ).one()
        assert inherits is False, (
            "the application login role inherits its tenant memberships; one "
            "session could then read every tenant"
        )


def test_tenant_role_does_not_survive_into_the_next_pooled_connection(
    tenant_engines: TenantEngines,
    application_engine: Engine, populated_ledger: dict[str, list[dict[str, Any]]]
) -> None:
    """Regression: a committed session-level SET ROLE outlives its transaction.

    The connection returns to the pool still wearing the tenant's identity,
    and the next checkout -- for a different tenant, or for none -- inherits
    it. Partitioning does not help; the session genuinely holds the other
    tenant's privileges. `tenant_connection` uses SET LOCAL ROLE for exactly
    this reason.
    """
    with tenant_connection(tenant_engines, TENANT_B) as conn:
        conn.execute(text(f'SELECT count(*) FROM "{partition_name(TENANT_B)}"'))  # noqa: S608

    for _ in range(4):
        with application_engine.connect() as conn:
            (who,) = conn.execute(text("SELECT current_user")).one()
            assert who == "evidence_app", (
                f"a pooled connection came back as {who}; a tenant role leaked "
                "out of its transaction"
            )
            with pytest.raises(ProgrammingError):
                conn.execute(
                    text(f'SELECT 1 FROM "{partition_name(TENANT_B)}"')  # noqa: S608
                )


def test_write_into_another_tenants_partition_is_impossible(
    tenant_engines: TenantEngines,
    record_factories: dict[str, Any],
) -> None:
    """Isolation must hold on the write side too.

    Two independent barriers: the role cannot name the other partition, and
    the partition constraint would reject the row even if it could.
    """
    from services.ledger import evidence_partition

    payload = dict(record_factories[TENANT_A].next_record())

    foreign = evidence_partition(TENANT_B)
    with pytest.raises(ProgrammingError) as caught:
        with tenant_connection(tenant_engines, TENANT_A) as conn:
            conn.execute(foreign.insert(), payload)
    assert getattr(caught.value.orig, "sqlstate", None) == INSUFFICIENT_PRIVILEGE

    # Even holding the privilege, the partition bound rejects the tenant.
    own = evidence_partition(TENANT_A)
    misrouted = dict(payload) | {"tenant_id": TENANT_B}
    with pytest.raises(Exception) as bound:  # noqa: B017
        with tenant_connection(tenant_engines, TENANT_A) as conn:
            conn.execute(own.insert(), misrouted)
    assert getattr(bound.value.orig, "sqlstate", None) == "23514", (  # type: ignore[attr-defined]
        "a row for another tenant landed in this tenant's partition"
    )


def test_unprovisioned_tenant_has_nowhere_to_land(owner_engine: Engine) -> None:
    """No DEFAULT partition: evidence for an unknown tenant is refused outright
    rather than pooled somewhere shared."""
    with owner_engine.connect() as conn:
        (default_partitions,) = conn.execute(
            text(
                "SELECT count(*) FROM pg_class c"
                " JOIN pg_inherits i ON i.inhrelid = c.oid"
                " JOIN pg_class p ON p.oid = i.inhparent"
                " WHERE p.relname = :parent"
                "   AND pg_get_expr(c.relpartbound, c.oid) = 'DEFAULT'"
            ),
            {"parent": EVIDENCE_PARENT_TABLE},
        ).one()
    assert default_partitions == 0
