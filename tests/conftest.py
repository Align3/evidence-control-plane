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
                    "INSERT INTO keys (key_id, tenant_id, collector_id, namespace,"
                    " public_key, custody, valid_from)"
                    " VALUES (:kid, :tid, :cid, 'evidence', :pk, 'client_held', now())"
                    " ON CONFLICT (key_id) DO NOTHING"
                ),
                {
                    "kid": key_id,
                    "tid": tenant_id,
                    "cid": collector_id,
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
def admin_actors(record_factories: dict[str, RecordFactory]) -> dict[str, Any]:
    """Per-tenant administrative signing identity for EV-12's tables.

    Reuses each tenant's evidence key rather than minting a new one: DM-008
    puts boundaries and qualification records in the `evidence` namespace, and
    a fixture that quietly registered a second key would hide the fact that
    the namespace discriminator on those tables is doing anything.
    """
    from tests.admin_support import AdminActor

    return {
        tenant_id: AdminActor(
            tenant_id=tenant_id,
            collector_id=factory.collector_id,
            key_id=factory.key_id,
            private_key=factory.private_key,
        )
        for tenant_id, factory in record_factories.items()
    }


@pytest.fixture(scope="session")
def default_boundaries(
    owner_engine: Engine, record_factories: dict[str, RecordFactory]
) -> dict[str, str]:
    """The `{tenant}:default:1` boundary every `RecordFactory` record cites.

    Required from migration 0012 onward: DM-017's deferred foreign key on
    `evidence_records.boundary_ref` is enforced from that revision, so an
    evidence row can no longer name a scope declaration that was never
    recorded. Before 0012 the column was unvalidated and this fixture had
    nothing to create.

    Recorded through `record_boundary`, not by raw INSERT, so the qualified-
    family invariant ES-009 states is exercised by every test that writes
    evidence rather than only by the tests aimed at it.
    """
    from datetime import UTC, datetime

    from services.admin import record_boundary, record_qualification
    from tests.admin_support import (
        boundary_body,
        qualification_body,
        signed_boundary,
        signed_qualification,
    )

    qualified_at = datetime(2026, 1, 1, tzinfo=UTC)
    refs: dict[str, str] = {}
    with owner_engine.begin() as conn:
        for tenant_id, factory in record_factories.items():
            public_keys = {factory.key_id: factory.private_key.public_key()}
            qualification, canonical, signature = signed_qualification(
                tenant_id=tenant_id,
                collector_id=factory.collector_id,
                key_id=factory.key_id,
                private_key=factory.private_key,
                boundary_ref=f"{tenant_id}:default:1",
                body=qualification_body(
                    action_family="payment.transfer",
                    destination_system="ledger-sandbox",
                    assigned_class="C1",
                    qualified_at=qualified_at,
                ),
            )
            qualification_ref = record_qualification(
                conn,
                record=qualification,
                canonical_bytes=canonical,
                signature=signature,
                public_keys=public_keys,
            )
            boundary, canonical, signature = signed_boundary(
                tenant_id=tenant_id,
                collector_id=factory.collector_id,
                key_id=factory.key_id,
                private_key=factory.private_key,
                name="default",
                version=1,
                body=boundary_body(
                    tenant_id=tenant_id,
                    version=1,
                    window_start=datetime(2026, 1, 1, tzinfo=UTC),
                    window_end=datetime(2027, 1, 1, tzinfo=UTC),
                    families=[
                        {
                            "action_family": "payment.transfer",
                            "destination_system": "ledger-sandbox",
                            "qualification_ref": qualification_ref,
                        }
                    ],
                ),
            )
            refs[tenant_id] = record_boundary(
                conn,
                record=boundary,
                canonical_bytes=canonical,
                signature=signature,
                public_keys=public_keys,
                recorded_at=datetime(2026, 1, 1, tzinfo=UTC),
            )
    return refs


@pytest.fixture(scope="session")
def populated_ledger(
    tenant_engines: TenantEngines,
    record_factories: dict[str, RecordFactory],
    default_boundaries: dict[str, str],
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
