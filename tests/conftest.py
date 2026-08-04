"""Database fixtures for the EV-06 ledger tests.

Everything here talks to the real Postgres named by `DATABASE_URL`. Role
grants are the thing under test in AC-S-004 and SE-S-003, and they cannot be
observed against sqlite or a mock -- a fake that "declines to issue UPDATE"
is precisely the implementation AC-012 rejects.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import Engine, text

from services.ledger import (
    LedgerConfig,
    TenantEngines,
    app_engine,
    evidence_partition,
    migrator_engine,
    provision_tenant,
    tenant_connection,
)
from tests.ledger_support import TENANT_A, TENANT_B, RecordFactory, run_alembic


@pytest.fixture(scope="session")
def ledger_config() -> LedgerConfig:
    return LedgerConfig.from_env()


@pytest.fixture(scope="session")
def migrated(ledger_config: LedgerConfig) -> LedgerConfig:
    """Rebuild the schema from zero, then apply every migration.

    Down and back up rather than upgrade-only: a downgrade leaving roles or
    partitions behind is a migration defect, and this is where it surfaces.
    The schema is left applied afterwards so the grants can be inspected by
    hand with psql.
    """
    run_alembic("downgrade", "base")
    run_alembic("upgrade", "head")
    return ledger_config


@pytest.fixture(scope="session")
def owner_engine(migrated: LedgerConfig) -> Iterator[Engine]:
    """The separately-credentialed schema path (SE-012 §6)."""
    engine = migrator_engine(migrated)
    yield engine
    engine.dispose()


@pytest.fixture(scope="session")
def application_engine(migrated: LedgerConfig) -> Iterator[Engine]:
    """The unscoped login: authenticated, a member of nothing, powerless.

    Kept as the negative control. Every statement it issues should be
    refused, and several tests assert exactly that.
    """
    engine = app_engine(migrated)
    yield engine
    engine.dispose()


@pytest.fixture(scope="session")
def tenant_engines(migrated: LedgerConfig, tenants: list[str]) -> Iterator[TenantEngines]:
    """Per-tenant logins -- each authenticates as its own role.

    Not the owner and not a shared login: testing grants from a superuser
    would prove nothing, and testing them from a login that may assume any
    tenant would prove less than it appears to.
    """
    engines = TenantEngines(migrated)
    yield engines
    engines.dispose()


@pytest.fixture(scope="session")
def tenants(owner_engine: Engine) -> list[str]:
    with owner_engine.begin() as conn:
        for tenant_id in (TENANT_A, TENANT_B):
            provision_tenant(
                conn,
                tenant_id=tenant_id,
                name=tenant_id.title(),
                deployment_profile="p1_hosted",
                key_custody="client_held",
                evidence_region="eu-west-1",
            )
    return [TENANT_A, TENANT_B]


@pytest.fixture(scope="session")
def record_factories(owner_engine: Engine, tenants: list[str]) -> dict[str, RecordFactory]:
    """Registers a collector and an evidence-namespace key per tenant."""
    factories: dict[str, RecordFactory] = {}
    with owner_engine.begin() as conn:
        for tenant_id in tenants:
            private_key = Ed25519PrivateKey.generate()
            receipt_private_key = Ed25519PrivateKey.generate()
            collector_id = f"{tenant_id}-collector-1"
            key_id = f"{tenant_id}-evidence-1"
            receipt_key_id = f"{tenant_id}-issuer-1"
            conn.execute(
                text(
                    "INSERT INTO collectors (collector_id, tenant_id, implementation,"
                    " version, mode, expected_cadence_s, registered_at)"
                    " VALUES (:cid, :tid, 'sdk-python', '0.1.0', 'checkpoint', 60, now())"
                    " ON CONFLICT (collector_id) DO NOTHING"
                ),
                {"cid": collector_id, "tid": tenant_id},
            )
            conn.execute(
                text(
                    "INSERT INTO keys (key_id, tenant_id, namespace, public_key,"
                    " custody, valid_from)"
                    " VALUES (:kid, :tid, 'evidence', :pk, 'client_held', now())"
                    " ON CONFLICT (key_id) DO NOTHING"
                ),
                {
                    "kid": key_id,
                    "tid": tenant_id,
                    "pk": private_key.public_key().public_bytes_raw(),
                },
            )
            conn.execute(
                text(
                    "INSERT INTO keys (key_id, tenant_id, namespace, public_key,"
                    " custody, valid_from)"
                    " VALUES (:kid, :tid, 'issuer', :pk, 'client_held', now())"
                    " ON CONFLICT (key_id) DO NOTHING"
                ),
                {
                    "kid": receipt_key_id,
                    "tid": tenant_id,
                    "pk": receipt_private_key.public_key().public_bytes_raw(),
                },
            )
            factories[tenant_id] = RecordFactory(
                tenant_id,
                collector_id,
                key_id,
                private_key,
                receipt_key_id,
                receipt_private_key,
            )
    return factories


@pytest.fixture(scope="session")
def populated_ledger(
    tenant_engines: TenantEngines,
    record_factories: dict[str, RecordFactory],
) -> dict[str, list[dict[str, Any]]]:
    """Appends records under each tenant's own role, into its own partition.

    Written using the only privilege the application role holds.
    """
    written: dict[str, list[dict[str, Any]]] = {}
    for tenant_id, factory in record_factories.items():
        rows = [
            factory.next_record(),
            factory.next_record(record_type="HumanReview"),
            factory.next_record(action_family=None),
        ]
        partition = evidence_partition(tenant_id)
        with tenant_connection(tenant_engines, tenant_id) as conn:
            for row in rows:
                conn.execute(partition.insert(), dict(row))
        written[tenant_id] = rows
    return written
