"""Connection configuration for the credentialed paths into the ledger.

They are not interchangeable (SE-012):

* the **migrator** DSN owns the schema and is the only path that can run
  DDL, provision a tenant, or touch a projection;
* each **tenant** DSN authenticates *as that tenant's role*, which holds
  `INSERT` and `SELECT` on one partition and nothing else;
* the **unscoped application** DSN authenticates as a login that is a
  member of nothing and can do nothing. It exists as a negative control,
  not as a path to data.

Keeping them apart in configuration is what makes it visible in a review
when application code reaches for the wrong one.

**Why one login per tenant rather than one shared login that assumes a
role.** The shared-login design grants the login membership in every tenant
role so it can `SET ROLE` into any of them. Membership is not scopeable to a
connection, so any statement that reaches the database on that connection
can also `RESET ROLE` and `SET ROLE` into a different tenant -- including a
statement smuggled in by SQL injection, which is exactly the query-layer
attack SE-011 requires be impossible rather than merely unused. Review
demonstrated it: one stacked driver call escaped Acme to Globex. With a
distinct login per tenant and no cross-membership, that statement fails,
because the authenticated role is not a member of any other tenant's role
and `SET ROLE` to it is refused by the server.

The application process can still reach any tenant, by deriving that
tenant's credential -- the trust boundary is the process, and always was.
What changes is that reaching another tenant now requires opening a new
authenticated connection, which a SQL payload on an existing connection
cannot do.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import URL, make_url

from .naming import application_role

REPO_ROOT = Path(__file__).resolve().parents[2]

#: Login role used only to demonstrate that an authenticated connection with
#: no tenant credential can reach nothing. It is a member of no role and
#: holds no privilege on any evidence or registry relation.
APP_LOGIN_ROLE = "evidence_app"

#: Environment variable holding the unscoped login password. The default is
#: a development credential only; the compose stack is not reachable off the
#: host.
APP_PASSWORD_ENV = "LEDGER_APP_PASSWORD"  # noqa: S105 -- a variable name, not a secret
DEFAULT_APP_PASSWORD = "devonly-app"  # noqa: S105 -- local compose stack only

#: Secret from which each tenant's login password is derived. Provisioning
#: sets the role's password to the derived value and the application derives
#: the same value to connect, so no per-tenant secret has to be distributed
#: or stored. Rotating this secret re-passwords every tenant on the next
#: provisioning pass.
TENANT_SECRET_ENV = "LEDGER_TENANT_SECRET"  # noqa: S105 -- a variable name
DEFAULT_TENANT_SECRET = "devonly-tenant-secret"  # noqa: S105 -- local compose only


def derive_tenant_password(secret: str, tenant_id: str) -> str:
    """Password for `tenant_id`'s login role.

    HMAC rather than a plain hash so that knowing one tenant's password
    reveals nothing about the secret or about any other tenant's password.
    """
    return hmac.new(
        secret.encode("utf-8"),
        application_role(tenant_id).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _load_dotenv() -> dict[str, str]:
    """Minimal `.env` reader.

    Deliberately not a dependency: adding one would mean editing
    ``pyproject.toml``, which is outside this story's Touches set.
    """
    path = REPO_ROOT / ".env"
    if not path.is_file():
        return {}
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _env(name: str, dotenv: dict[str, str], default: str | None = None) -> str:
    value = os.environ.get(name) or dotenv.get(name) or default
    if value is None:
        raise RuntimeError(f"{name} is not set (checked environment and .env)")
    return value


@dataclass(frozen=True)
class LedgerConfig:
    """Where the ledger lives and how each role reaches it."""

    migrator_url: URL
    app_password: str
    tenant_secret: str

    @classmethod
    def from_env(cls) -> LedgerConfig:
        dotenv = _load_dotenv()
        url = make_url(_env("DATABASE_URL", dotenv))
        if url.drivername == "postgresql":
            # psycopg 3 is the installed driver; the bare scheme selects
            # psycopg2, which is not present.
            url = url.set(drivername="postgresql+psycopg")
        return cls(
            migrator_url=url,
            app_password=_env(APP_PASSWORD_ENV, dotenv, DEFAULT_APP_PASSWORD),
            tenant_secret=_env(TENANT_SECRET_ENV, dotenv, DEFAULT_TENANT_SECRET),
        )

    @property
    def app_url(self) -> URL:
        """DSN for the unscoped login. It can reach nothing; see module docs."""
        return self.migrator_url.set(
            username=APP_LOGIN_ROLE, password=self.app_password
        )

    def tenant_password(self, tenant_id: str) -> str:
        """The derived password for one tenant's login role."""
        return derive_tenant_password(self.tenant_secret, tenant_id)

    def tenant_url(self, tenant_id: str) -> URL:
        """DSN that authenticates *as* `tenant_id`, not as a role it assumes.

        `current_user` is the tenant role from the moment the connection is
        established, so there is no window in which the session holds
        anything wider, and no membership to `SET ROLE` back out of.
        """
        return self.migrator_url.set(
            username=application_role(tenant_id),
            password=self.tenant_password(tenant_id),
        )

    @property
    def database(self) -> str:
        name = self.migrator_url.database
        if name is None:  # pragma: no cover -- malformed DSN
            raise RuntimeError("DATABASE_URL names no database")
        return name
