"""Engines and the tenant-scoped session.

`tenant_connection` is the only sanctioned way for application code to reach
evidence. The session's privileges name one partition, so no query it issues
reaches another tenant (SE-011).

A session authenticates **as** the tenant. It does not authenticate as a
shared login and then assume the tenant, because membership in a role is
not scopeable to a connection: a login that may assume two tenants may
assume the second one at any point in any statement it executes, including
one introduced by SQL injection. Review demonstrated exactly that against
the earlier design -- a single stacked driver call moved an Acme session to
Globex and read its evidence. Per-tenant credentials remove the membership,
so the server refuses the switch instead of the application avoiding it.

The trust boundary is still the application process: code holding the
tenant secret can derive any tenant's credential and open a connection as
that tenant. What it can no longer do is cross tenants *on a connection it
already has*, which is what SE-011 requires be impossible in the query
layer rather than merely unused.
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
    """Engine for the unscoped login role -- a negative control, not a path.

    `APP_LOGIN_ROLE` is a member of no role and holds no privilege on any
    evidence or registry relation, so every statement it issues is refused.
    It is kept, and kept powerless, so that "an authenticated connection
    with no tenant credential can reach nothing" is a claim the suite can
    assert rather than a property of an absent role.
    """
    config = config or LedgerConfig.from_env()
    return create_engine(config.app_url, future=True)


class TenantEngines:
    """Per-tenant engines, each authenticating as that tenant's own role.

    One pool per tenant. Pools are not shared across tenants, so a pooled
    connection can never be handed to a different tenant than the one whose
    credential opened it -- the class of bug that `SET ROLE` on a shared
    login makes possible and that no amount of resetting fully closes.
    """

    def __init__(self, config: LedgerConfig | None = None) -> None:
        self._config = config or LedgerConfig.from_env()
        self._engines: dict[str, Engine] = {}

    def engine(self, tenant_id: str) -> Engine:
        role = application_role(tenant_id)  # validates before it reaches a DSN
        if role not in self._engines:
            self._engines[role] = create_engine(
                self._config.tenant_url(tenant_id), future=True
            )
        return self._engines[role]

    def dispose(self) -> None:
        for engine in self._engines.values():
            engine.dispose()
        self._engines.clear()


@contextmanager
def tenant_connection(
    engines: TenantEngines, tenant_id: str
) -> Iterator[Connection]:
    """Yield a connection authenticated as `tenant_id`'s role, for one transaction.

    The block owns the transaction: it commits on clean exit and rolls back
    on an exception. Callers must not commit themselves.

    The session **is** the tenant rather than assuming the tenant. Nothing is
    granted that would let it become another one: its role is a member of no
    other tenant role, so a `SET ROLE` naming one -- whether written by
    application code or smuggled in as a stacked statement by SQL injection
    -- is refused by the server rather than by convention.

    The identity is asserted rather than assumed. If the connection is not
    the expected role, the block refuses to yield: a misconfigured DSN that
    silently connected as something wider would otherwise look like working
    code right up until it read another tenant's evidence.
    """
    role = application_role(tenant_id)
    with engines.engine(tenant_id).begin() as connection:
        actual = connection.execute(text("SELECT current_user")).scalar_one()
        if actual != role:
            raise RuntimeError(
                f"refusing to act for {tenant_id!r}: connected as {actual!r}, "
                f"expected {role!r} (SE-011)"
            )
        yield connection
