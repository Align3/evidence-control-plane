"""Tenant provisioning: the partition and the role are created together.

A tenant without a partition has nowhere to write (there is no DEFAULT
partition, so evidence for an unknown tenant is refused rather than pooled
somewhere shared). A partition without a role is unreachable. Doing both in
one transaction is what keeps `SE-011` from depending on an operator
remembering the second step.

This runs under the migrator credential (SE-012, §6): it is DDL and role
administration, not application traffic.
"""

from __future__ import annotations

from sqlalchemy import Connection, text

from .config import LedgerConfig, derive_tenant_password
from .naming import (
    APP_GRANTS,
    EVIDENCE_PARENT_TABLE,
    INTEGRITY_EVENT_PARENT_TABLE,
    POPULATION_PARENT_TABLE,
    REGISTRY_READER_ROLE,
    TENANT_ROLE_PREFIX,
    application_role,
    integrity_event_partition_name,
    partition_name,
    population_partition_name,
    validate_tenant_id,
)
from .registry import assert_registry_isolated

#: Privileges the tenant role must never hold on evidence, restated as an
#: explicit REVOKE. They are never granted; revoking as well means an
#: inherited or default grant introduced later cannot survive provisioning.
FORBIDDEN_GRANTS = ("UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")


def _database_name(connection: Connection) -> str:
    name = connection.engine.url.database
    if name is None:  # pragma: no cover -- malformed DSN
        raise RuntimeError("connection names no database")
    return name


def provision_tenant(
    connection: Connection,
    *,
    tenant_id: str,
    name: str,
    deployment_profile: str,
    key_custody: str,
    evidence_region: str,
    tenant_secret: str | None = None,
) -> None:
    """Register a tenant and create its partition and login role. Idempotent."""
    validate_tenant_id(tenant_id)
    if tenant_secret is None:
        tenant_secret = LedgerConfig.from_env().tenant_secret
    partition = partition_name(tenant_id)
    integrity_partition = integrity_event_partition_name(tenant_id)
    population_partition = population_partition_name(tenant_id)
    role = application_role(tenant_id)

    connection.execute(
        text(
            "INSERT INTO tenants (tenant_id, name, deployment_profile, key_custody,"
            " evidence_region, created_at)"
            " VALUES (:tenant_id, :name, CAST(:profile AS deployment_profile),"
            " CAST(:custody AS key_custody), :region, now())"
            " ON CONFLICT (tenant_id) DO NOTHING"
        ),
        {
            "tenant_id": tenant_id,
            "name": name,
            "profile": deployment_profile,
            "custody": key_custody,
            "region": evidence_region,
        },
    )
    connection.execute(
        text(  # noqa: S608 -- literal is constrained to [a-z0-9_] above
            f'CREATE TABLE IF NOT EXISTS "{integrity_partition}"'
            f' PARTITION OF "{INTEGRITY_EVENT_PARENT_TABLE}"'
            f" FOR VALUES IN ('{tenant_id}')"
        )
    )

    # DDL cannot take bind parameters, so the partition bound is a literal.
    # `validate_tenant_id` is anchored and admits only [a-z0-9_], so nothing
    # that could close the quote survives it -- and the CHECK constraint on
    # `tenants.tenant_id` enforces the same rule inside the database.
    connection.execute(
        text(  # noqa: S608 -- literal is constrained to [a-z0-9_] above
            f'CREATE TABLE IF NOT EXISTS "{partition}"'
            f' PARTITION OF "{EVIDENCE_PARENT_TABLE}"'
            f" FOR VALUES IN ('{tenant_id}')"
        )
    )
    connection.execute(
        text(  # noqa: S608 -- literal is constrained to [a-z0-9_] above
            f'CREATE TABLE IF NOT EXISTS "{population_partition}"'
            f' PARTITION OF "{POPULATION_PARENT_TABLE}"'
            f" FOR VALUES IN ('{tenant_id}')"
        )
    )

    # The tenant role is itself a LOGIN role with its own derived password
    # (SE-011). It is deliberately NOT granted to any shared login: a login
    # holding membership in two tenant roles can move between them mid-
    # session, including via a statement introduced by SQL injection, and
    # membership cannot be scoped to one connection. See config.py.
    password = derive_tenant_password(tenant_secret, tenant_id)
    connection.execute(
        text(
            "DO $$ BEGIN"  # noqa: S608 -- role name validated by application_role
            f"  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN"
            f"    CREATE ROLE \"{role}\" LOGIN PASSWORD '{password}';"
            "  ELSE"
            f"    ALTER ROLE \"{role}\" LOGIN PASSWORD '{password}';"
            "  END IF;"
            "END $$;"
        )
    )

    grants = ", ".join(APP_GRANTS)
    forbidden = ", ".join(FORBIDDEN_GRANTS)
    for statement in (
        f'GRANT CONNECT ON DATABASE "{_database_name(connection)}" TO "{role}"',
        f'GRANT USAGE ON SCHEMA public TO "{role}"',
        # INSERT and SELECT. Nothing else, ever (DM-004, AC-012, SE-012).
        f'GRANT {grants} ON TABLE "{partition}" TO "{role}"',
        f'REVOKE {forbidden} ON TABLE "{partition}" FROM "{role}"',
        f'GRANT {grants} ON TABLE "{integrity_partition}" TO "{role}"',
        f'REVOKE {forbidden} ON TABLE "{integrity_partition}" FROM "{role}"',
        f'GRANT {grants} ON TABLE "{population_partition}" TO "{role}"',
        f'REVOKE {forbidden} ON TABLE "{population_partition}" FROM "{role}"',
        # Registry reads (tenants, collectors, keys) for registration checks.
        # Row-level security scopes them to this tenant's own rows.
        f'GRANT "{REGISTRY_READER_ROLE}" TO "{role}"',
    ):
        connection.execute(text(statement))

    _assert_append_only(connection, role=role, partition=partition)
    _assert_append_only(connection, role=role, partition=integrity_partition)
    _assert_append_only(connection, role=role, partition=population_partition)
    _assert_no_cross_tenant_membership(connection, role=role)
    # The new tenant role gains SELECT on the registry through
    # REGISTRY_READER_ROLE. If row-level isolation were missing, that grant
    # would let it enumerate every other tenant (SE-011).
    assert_registry_isolated(connection)


def _assert_append_only(connection: Connection, *, role: str, partition: str) -> None:
    """Fail provisioning rather than create a mutable partition.

    A tenant provisioned with the wrong grants would be an append-only ledger
    everywhere except one tenant -- the kind of defect that is invisible until
    it matters.
    """
    held = {
        row.privilege_type
        for row in connection.execute(
            text(
                "SELECT privilege_type FROM information_schema.table_privileges"
                " WHERE grantee = :role AND table_name = :partition"
            ),
            {"role": role, "partition": partition},
        )
    }
    if held != set(APP_GRANTS):
        raise RuntimeError(
            f"refusing to provision {partition}: role {role} holds {sorted(held)}, "
            f"expected exactly {sorted(APP_GRANTS)} (DM-004, SE-012)"
        )


def _assert_no_cross_tenant_membership(connection: Connection, *, role: str) -> None:
    """Fail provisioning if anything holds membership in a tenant role.

    A tenant role is a login in its own right and is granted to nobody. The
    moment some other role is a member of one, that role can `SET ROLE` into
    the tenant -- and if it is a member of two, it can move between them
    inside a single statement, which is the cross-tenant read SE-011 says
    must not be expressible. Checking the catalogue rather than trusting
    that no grant was written: a later story adding a convenience grant
    would otherwise reopen this silently.
    """
    rows = connection.execute(
        text(
            "SELECT member.rolname AS member, granted.rolname AS granted"
            " FROM pg_auth_members am"
            " JOIN pg_roles member ON member.oid = am.member"
            " JOIN pg_roles granted ON granted.oid = am.roleid"
            " WHERE granted.rolname LIKE :prefix"
            " ORDER BY 1, 2"
        ),
        {"prefix": f"{TENANT_ROLE_PREFIX}%"},
    ).all()
    if rows:
        held = ", ".join(f"{row.member} -> {row.granted}" for row in rows)
        raise RuntimeError(
            f"refusing to provision {role}: tenant roles are granted to "
            f"other roles, which makes a cross-tenant SET ROLE possible "
            f"({held}) (SE-011)"
        )


def deprovision_tenant(connection: Connection, *, tenant_id: str) -> None:
    """Drop a tenant's role and partition.

    Present for test teardown and migration downgrade only. It deletes
    evidence, so it is not reachable from any application role. When the
    EV-18 lifecycle relation exists, deletion is refused while any live
    attestation remains effective (DM-012, and the first half of SE-017).

    SE-017 also sets a retention *floor* of the attestation validity period
    plus the dispute window, which DM-014 puts at a configurable 12 months
    by default. That half is not implemented here or anywhere else yet: the
    moment an attestation expires this guard stops refusing, so expiry --
    not the retention floor -- is currently what bounds deletion. EV-43
    owns closing it. Do not read this function as satisfying SE-017 whole.
    """
    validate_tenant_id(tenant_id)
    partition = partition_name(tenant_id)
    integrity_partition = integrity_event_partition_name(tenant_id)
    population_partition = population_partition_name(tenant_id)
    role = application_role(tenant_id)
    lifecycle_present = connection.execute(
        text("SELECT to_regclass('public.attestations') IS NOT NULL")
    ).scalar_one()
    if lifecycle_present:
        live_attestation = connection.execute(
            text(
                "SELECT attestation_id FROM attestations a"
                " WHERE a.tenant_id = :tenant_id"
                " AND a.validity_from <= clock_timestamp()"
                " AND a.validity_until > clock_timestamp()"
                " AND NOT EXISTS ("
                "   SELECT 1 FROM revocations r"
                "    WHERE r.tenant_id = a.tenant_id"
                "      AND r.attestation_id = a.attestation_id"
                "      AND r.effective_at <= clock_timestamp()"
                " ) LIMIT 1"
            ),
            {"tenant_id": tenant_id},
        ).scalar_one_or_none()
        if live_attestation is not None:
            raise RuntimeError(
                "evidence deletion refused: covering attestation must be "
                "revoked first (SE-017)"
            )
    connection.execute(text(f'DROP TABLE IF EXISTS "{partition}"'))
    connection.execute(text(f'DROP TABLE IF EXISTS "{integrity_partition}"'))
    connection.execute(text(f'DROP TABLE IF EXISTS "{population_partition}"'))
    connection.execute(
        text(
            "DO $$ BEGIN"  # noqa: S608 -- role name validated by application_role
            f"  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN"
            f'    DROP OWNED BY "{role}";'
            f'    DROP ROLE "{role}";'
            "  END IF;"
            "END $$;"
        )
    )
