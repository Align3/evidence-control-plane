"""Registry tenant isolation (SE-011, DM-006 amendment 1).

`tenants`, `collectors` and `keys` carry a `SELECT` grant that every tenant
role holds, because ingestion must resolve a collector and a key. Without
row-level security that grant lets any customer read the whole customer
list and every other customer's deployment topology.

Negative-first (AG-007): the invisibility of another tenant's rows is
asserted before anything about the happy path, and the "returns nothing"
cases come before the "still works" ones.

These tests do not use partitioning as the mechanism and should not be read
as contradicting SE-S-003. Evidence is partitioned because it is always read
in a tenant's context; the registry is read by id, so RLS is what keeps the
query shape while still making other tenants' rows structurally absent.
"""

from __future__ import annotations

import pytest
from sqlalchemy import Engine, text

from services.ledger import (
    REGISTRY_TABLES,
    TENANT_ISOLATION_POLICY,
    TenantEngines,
    assert_registry_isolated,
    registry_isolation_status,
    tenant_connection,
)
from tests.ledger_support import TENANT_A, TENANT_B, RecordFactory


@pytest.mark.parametrize("table", REGISTRY_TABLES)
def test_tenant_cannot_see_another_tenants_registry_rows(
    tenant_engines: TenantEngines,
    record_factories: dict[str, RecordFactory],
    table: str,
) -> None:
    """The headline failure: `SELECT * FROM tenants` as a customer.

    Before RLS this returned every customer we have.
    """
    with tenant_connection(tenant_engines, TENANT_A) as conn:
        visible = {
            row.tenant_id
            for row in conn.execute(text(f"SELECT tenant_id FROM {table}"))  # noqa: S608
        }
    assert TENANT_B not in visible, (
        f"{TENANT_A} can read {TENANT_B}'s rows in {table} -- a customer can "
        "enumerate other customers"
    )
    assert visible == {TENANT_A}


def test_targeted_lookup_of_another_tenants_collector_returns_nothing(
    tenant_engines: TenantEngines, record_factories: dict[str, RecordFactory]
) -> None:
    """Knowing the id must not be enough.

    An isolation that only hides rows from unqualified scans, but answers a
    direct lookup, confirms existence to anyone who can guess an identifier.
    """
    foreign_collector = record_factories[TENANT_B].collector_id
    foreign_key = record_factories[TENANT_B].key_id
    with tenant_connection(tenant_engines, TENANT_A) as conn:
        collectors = conn.execute(
            text("SELECT collector_id FROM collectors WHERE collector_id = :cid"),
            {"cid": foreign_collector},
        ).all()
        keys = conn.execute(
            text("SELECT key_id FROM keys WHERE key_id = :kid"),
            {"kid": foreign_key},
        ).all()
    assert collectors == [], "a direct lookup confirmed another tenant's collector"
    assert keys == [], "a direct lookup confirmed another tenant's key"


def test_aggregate_does_not_leak_the_customer_count(
    tenant_engines: TenantEngines, record_factories: dict[str, RecordFactory]
) -> None:
    """A count is a smaller leak than a list, and still a leak."""
    with tenant_connection(tenant_engines, TENANT_A) as conn:
        (count,) = conn.execute(text("SELECT count(*) FROM tenants")).one()
    assert count == 1, f"tenants count leaked {count} customers"


def test_ingestion_can_resolve_its_own_collector_by_id_alone(
    tenant_engines: TenantEngines, record_factories: dict[str, RecordFactory]
) -> None:
    """The query shape RLS was chosen to preserve (SE-018).

    Ingestion has a `collector_id` from the incoming record and no tenant
    context beyond the role it is already acting as. If it had to name a
    per-tenant relation, it would need the tenant before it could look up
    the row that tells it the tenant.
    """
    own = record_factories[TENANT_A].collector_id
    with tenant_connection(tenant_engines, TENANT_A) as conn:
        rows = conn.execute(
            text(
                "SELECT collector_id, tenant_id, mode FROM collectors"
                " WHERE collector_id = :cid AND revoked_at IS NULL"
            ),
            {"cid": own},
        ).all()
    assert len(rows) == 1
    assert rows[0].tenant_id == TENANT_A


def test_registry_isolation_is_enabled_not_merely_declared(
    owner_engine: Engine, tenants: list[str]
) -> None:
    """A policy on a table with RLS disabled reads exactly like a protected
    table right up until someone queries it."""
    with owner_engine.connect() as conn:
        status = registry_isolation_status(conn)
    assert set(status) == set(REGISTRY_TABLES)
    for table, detail in status.items():
        assert detail["rls_enabled"] is True, f"RLS not enabled on {table}"
        assert detail["policy"] == TENANT_ISOLATION_POLICY, f"no policy on {table}"
        assert detail["command"] == "SELECT"
        # The predicate must key off the role, not off a value the caller
        # supplies -- a session variable would be settable by the session.
        predicate = str(detail["predicate"])
        assert "current_user" in predicate.lower(), predicate
        assert "evidence_tenant_" in predicate, predicate


def test_owner_retains_cross_tenant_visibility_for_administration(
    owner_engine: Engine, record_factories: dict[str, RecordFactory]
) -> None:
    """ENABLE, not FORCE.

    The owner bypasses the policies, which is what leaves provisioning and
    cross-tenant administration possible through the separately-credentialed
    path (SE-012 §6). Those operations are logged and surfaced to the tenant
    under SE-013 -- built by EV-20, not here.
    """
    with owner_engine.connect() as conn:
        visible = {row.tenant_id for row in conn.execute(text("SELECT tenant_id FROM tenants"))}
        assert {TENANT_A, TENANT_B} <= visible
        forced = registry_isolation_status(conn)
    assert all(detail["rls_forced"] is False for detail in forced.values())


def test_assert_registry_isolated_refuses_when_a_policy_is_missing(
    owner_engine: Engine, tenants: list[str]
) -> None:
    """The guard must fail loudly, or provisioning would silently hand a new
    tenant a readable customer list.

    Drops the policy on `tenants`, checks the refusal, and restores it.
    """
    with owner_engine.connect() as conn:
        assert_registry_isolated(conn)  # baseline

    with owner_engine.begin() as conn:
        conn.execute(text(f"DROP POLICY {TENANT_ISOLATION_POLICY} ON tenants"))
    try:
        with owner_engine.connect() as conn:
            with pytest.raises(RuntimeError, match="row-level isolation"):
                assert_registry_isolated(conn)
    finally:
        with owner_engine.begin() as conn:
            conn.execute(
                text(
                    f"CREATE POLICY {TENANT_ISOLATION_POLICY} ON tenants"
                    " FOR SELECT USING (current_user = 'evidence_tenant_' || tenant_id)"
                )
            )
    with owner_engine.connect() as conn:
        assert_registry_isolated(conn)


def test_tenant_role_still_cannot_write_the_registry(
    tenant_engines: TenantEngines, record_factories: dict[str, RecordFactory]
) -> None:
    """RLS governs which rows are visible, not which statements are allowed.

    Registration remains an administrative write (SE-018): a collector that
    could register itself is not a registration check.
    """
    from sqlalchemy.exc import ProgrammingError

    from tests.ledger_support import INSUFFICIENT_PRIVILEGE

    for sql in (
        "INSERT INTO collectors (collector_id, tenant_id, implementation, version,"
        " mode, registered_at) VALUES ('rogue', 'acme', 'x', '1', 'checkpoint', now())",
        "UPDATE tenants SET name = 'x'",
        "DELETE FROM keys",
    ):
        with pytest.raises(ProgrammingError) as caught:
            with tenant_connection(tenant_engines, TENANT_A) as conn:
                conn.execute(text(sql))
        assert getattr(caught.value.orig, "sqlstate", None) == INSUFFICIENT_PRIVILEGE, (
            f"{sql} was not refused"
        )
