"""Engines and the tenant-scoped session.

`tenant_connection` is the only sanctioned way for application code to reach
evidence. It assumes the tenant's role for the transaction, which is what
turns partitioning into isolation: while that role is current, the session's
privileges name one partition, so no *query* it issues reaches another
tenant (SE-011).

**Where that guarantee stops.** `APP_LOGIN_ROLE` holds membership in every
tenant role -- that is how it can assume any of them -- so a session that
has issued `RESET ROLE`, or `SET ROLE` naming another tenant, is acting as
that other tenant and can read its evidence. The database cannot prevent
this while one login role serves all tenants; membership is what makes the
`SET ROLE` possible in the first place.

So the isolation boundary is the application process, not the connection.
Code inside that process is trusted not to change role; code outside it
cannot reach a connection at all. What this does buy, and it is the point,
is that a *SQL injection confined to a query* cannot cross tenants: it would
have to inject a role change, which `SET LOCAL` inside an open transaction
does not make available to a `SELECT` payload.

Closing the gap entirely means one login role per tenant, so no session ever
holds the membership. That is a connection-pooling change well beyond this
story; recorded here rather than left implied (AG-015).
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
