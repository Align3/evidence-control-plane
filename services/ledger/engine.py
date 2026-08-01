"""Engines and the tenant-scoped session.

`tenant_connection` is the only sanctioned way for application code to reach
evidence. It assumes the tenant's role for the life of the connection, which
is what turns partitioning into isolation: the session's privileges name one
partition, so no query it can issue reaches another tenant (SE-011).
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Connection, Engine, create_engine, text

from .config import LedgerConfig
from .naming import application_role


def migrator_engine(config: LedgerConfig | None = None) -> Engine:
    """Engine for the separately-credentialed schema path (SE-012, SE-024).

    Owns the tables. This is the only path that can run DDL, provision a
    tenant, or rebuild a projection. Nothing serving ingestion or query
    traffic should hold it.
    """
    config = config or LedgerConfig.from_env()
    return create_engine(config.migrator_url, future=True)


def app_engine(config: LedgerConfig | None = None) -> Engine:
    """Engine for the application login role.

    The role is NOINHERIT and holds no privilege on any evidence relation.
    Connections from it can do nothing until `tenant_connection` assumes a
    tenant role -- and can then do nothing outside that tenant.
    """
    config = config or LedgerConfig.from_env()
    return create_engine(config.app_url, future=True)


@contextmanager
def tenant_connection(engine: Engine, tenant_id: str) -> Iterator[Connection]:
    """Yield a connection acting as `tenant_id`'s role, for one transaction.

    The block owns the transaction: it commits on clean exit and rolls back
    on an exception. Callers must not commit themselves.

    ``SET LOCAL ROLE``, not ``SET ROLE``, and the difference is the whole
    point. A session-level ``SET ROLE`` survives a ``COMMIT``; the connection
    then returns to the pool still wearing that tenant's identity, and the
    next checkout -- possibly serving a different tenant -- inherits it. That
    is a cross-tenant read arriving through the front door, and no amount of
    partitioning stops it. ``SET LOCAL`` is scoped to the transaction, so the
    role cannot outlive the block that set it.
    """
    role = application_role(tenant_id)
    with engine.begin() as connection:
        # `role` is validated against an anchored identifier pattern by
        # `application_role`; DDL-adjacent statements take no bind parameters.
        connection.execute(text(f'SET LOCAL ROLE "{role}"'))
        yield connection
