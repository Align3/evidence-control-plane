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

from .config import APP_LOGIN_ROLE
from .naming import (
    APP_GRANTS,
    EVIDENCE_PARENT_TABLE,
    REGISTRY_READER_ROLE,
    application_role,
    partition_name,
    validate_tenant_id,
)
from .registry import assert_registry_isolated

#: Privileges the tenant role must never hold on evidence, restated as an
#: explicit REVOKE. They are never granted; revoking as well means an
#: inherited or default grant introduced later cannot survive provisioning.
FORBIDDEN_GRANTS = ("UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")


def provision_tenant(
    connection: Connection,
    *,
    tenant_id: str,
    name: str,
    deployment_profile: str,
    key_custody: str,
    evidence_region: str,
) -> None:
    """Register a tenant and create its partition and role. Idempotent."""
    validate_tenant_id(tenant_id)
    partition = partition_name(tenant_id)
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
        text(
            "DO $$ BEGIN"  # noqa: S608 -- role name validated by application_role
            f"  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN"
            f'    CREATE ROLE "{role}" NOLOGIN;'
            "  END IF;"
            "END $$;"
        )
    )

    grants = ", ".join(APP_GRANTS)
    forbidden = ", ".join(FORBIDDEN_GRANTS)
    for statement in (
        f'GRANT USAGE ON SCHEMA public TO "{role}"',
        # INSERT and SELECT. Nothing else, ever (DM-004, AC-012, SE-012).
        f'GRANT {grants} ON TABLE "{partition}" TO "{role}"',
        f'REVOKE {forbidden} ON TABLE "{partition}" FROM "{role}"',
        # Registry reads (tenants, collectors, keys) for registration checks.
        f'GRANT "{REGISTRY_READER_ROLE}" TO "{role}"',
        # The login role may assume this tenant. It is NOINHERIT, so
        # membership confers nothing until it does so explicitly.
        f'GRANT "{role}" TO "{APP_LOGIN_ROLE}"',
    ):
        connection.execute(text(statement))

    _assert_append_only(connection, role=role, partition=partition)
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


def deprovision_tenant(connection: Connection, *, tenant_id: str) -> None:
    """Drop a tenant's role and partition.

    Present for test teardown and migration downgrade only. It deletes
    evidence, so it is not reachable from any application role and must not
    be called on a tenant whose evidence is covered by a valid attestation
    (SE-017, DM-012). That check belongs to the deletion path built in a
    later story; this function does not implement it.
    """
    validate_tenant_id(tenant_id)
    partition = partition_name(tenant_id)
    role = application_role(tenant_id)
    connection.execute(text(f'DROP TABLE IF EXISTS "{partition}"'))
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
