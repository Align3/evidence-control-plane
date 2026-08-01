"""Connection configuration for the two credentialed paths into the ledger.

There are deliberately two, and they are not interchangeable (SE-012):

* the **migrator** DSN owns the schema and is the only path that can run
  DDL or touch a projection;
* the **application** DSN logs in as a role that holds `INSERT` and
  `SELECT` on one tenant's partition and nothing else.

Keeping them apart in configuration is what makes it visible in a review
when application code reaches for the wrong one.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import URL, make_url

REPO_ROOT = Path(__file__).resolve().parents[2]

#: Login role the services authenticate as. It holds no privilege on any
#: evidence relation; it is NOINHERIT and must `SET ROLE` to a tenant role
#: before it can read or write anything (SE-011).
APP_LOGIN_ROLE = "evidence_app"

#: Environment variable holding the application login password. The default
#: is a development credential only; the compose stack is not reachable off
#: the host.
APP_PASSWORD_ENV = "LEDGER_APP_PASSWORD"  # noqa: S105 -- a variable name, not a secret
DEFAULT_APP_PASSWORD = "devonly-app"  # noqa: S105 -- local compose stack only


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
        )

    @property
    def app_url(self) -> URL:
        """DSN for the application login role."""
        return self.migrator_url.set(
            username=APP_LOGIN_ROLE, password=self.app_password
        )

    @property
    def database(self) -> str:
        name = self.migrator_url.database
        if name is None:  # pragma: no cover -- malformed DSN
            raise RuntimeError("DATABASE_URL names no database")
        return name
