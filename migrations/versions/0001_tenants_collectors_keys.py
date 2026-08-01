"""EV-06 0001: tenants, collectors, keys, and the ledger roles.

Claimed in `docs/data-model.md` §3 before this file existed (DM-001).

Creates the registry tables (`data-model.md` §2.1-§2.3) and the two roles the
whole isolation design rests on:

``evidence_app``
    A login role that is a member of nothing and holds no privilege on any
    evidence or registry relation. It is **not** the path services use --
    each tenant has its own login role, created by `provision_tenant`, and a
    session authenticates *as* the tenant (SE-011).

    It is retained, and retained powerless, as a negative control: "an
    authenticated session holding no tenant credential can reach nothing" is
    then something the suite asserts rather than a property that follows from
    the role being absent. ``NOINHERIT`` is belt-and-braces on a role with no
    memberships to inherit.

    An earlier revision of this story made ``evidence_app`` the shared login
    for every service, holding membership in every tenant role and assuming a
    tenant with ``SET LOCAL ROLE``. Review broke it: membership is not
    scopeable to a connection, so any statement reaching the database --
    including one introduced by SQL injection -- could ``RESET ROLE`` and
    assume a different tenant. Per-tenant credentials remove the membership,
    so the server refuses the switch rather than the application avoiding it.

``evidence_registry_reader``
    Group role holding SELECT on the registry tables. Tenant roles are
    members, so they can resolve a collector or key during ingestion.

Revision ID: 0001
Revises:
"""

from __future__ import annotations

import os
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_LOGIN_ROLE = "evidence_app"
REGISTRY_READER_ROLE = "evidence_registry_reader"
REGISTRY_TABLES = ("tenants", "collectors", "keys")

# Mirrors services.ledger.naming. Every tenant role is named by prefixing
# the tenant id, which is what lets the RLS predicate below identify the
# row's tenant from `current_user` without a lookup.
TENANT_ROLE_PREFIX = "evidence_tenant_"
POLICY_NAME = "tenant_isolation"

# Mirrors services.ledger.naming.TENANT_ID_SQL_PATTERN, which is asserted by
# tests/unit/test_ledger_schema_invariants.py. Constraining the tenant id to
# characters that are already a legal SQL identifier makes the tenant ->
# partition-name mapping the identity function, so two tenants can never
# derive the same partition (SE-011).
#
# The length bound is part of that guarantee, not cosmetic. Postgres
# truncates identifiers at NAMEDATALEN-1 = 63 bytes silently. At the previous
# bound of 48, 'evidence_records_' + tenant_id was 65 bytes and
# 'evidence_tenant_' + tenant_id was 64, so two tenant ids agreeing on their
# first 47 characters truncated to one partition and one role -- a
# cross-tenant read requiring no attacker. 46 keeps every derived identifier
# under the limit.
TENANT_ID_PATTERN = "^[a-z0-9]([a-z0-9_]{0,44}[a-z0-9])?$"

ENUMS = {
    "deployment_profile": ("p1_hosted", "p2_vpc", "p3_sidecar"),
    "key_custody": ("client_held", "hosted_kms"),
    "collector_mode": ("checkpoint", "third_party", "observation_only"),
    "key_namespace": ("evidence", "issuer"),
}


def _app_password() -> str:
    # Development default; production supplies LEDGER_APP_PASSWORD out of
    # band (SE-023: environment-scoped, never in the repository).
    return os.environ.get("LEDGER_APP_PASSWORD", "devonly-app")


def upgrade() -> None:
    for name, labels in ENUMS.items():
        values = ", ".join(f"'{label}'" for label in labels)
        op.execute(
            f"DO $$ BEGIN"  # noqa: S608 -- names are module constants
            f"  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = '{name}') THEN"
            f"    CREATE TYPE {name} AS ENUM ({values});"
            f"  END IF;"
            f"END $$;"
        )

    op.create_table(
        "tenants",
        sa.Column("tenant_id", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column(
            "deployment_profile",
            postgresql.ENUM(*ENUMS["deployment_profile"],
                            name="deployment_profile", create_type=False),
            nullable=False,
        ),
        sa.Column(
            "key_custody",
            postgresql.ENUM(*ENUMS["key_custody"], name="key_custody",
                            create_type=False),
            nullable=False,
        ),
        sa.Column("evidence_region", sa.Text(), nullable=False),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("tenant_id", name="pk_tenants"),
        sa.CheckConstraint(
            f"tenant_id ~ '{TENANT_ID_PATTERN}'",
            name="ck_tenants_tenant_id_identifier",
        ),
    )

    op.create_table(
        "collectors",
        sa.Column("collector_id", sa.Text(), nullable=False),
        sa.Column("tenant_id", sa.Text(), nullable=False),
        sa.Column("implementation", sa.Text(), nullable=False),
        sa.Column("version", sa.Text(), nullable=False),
        sa.Column(
            "mode",
            postgresql.ENUM(*ENUMS["collector_mode"], name="collector_mode",
                            create_type=False),
            nullable=False,
        ),
        sa.Column("expected_cadence_s", sa.Integer(), nullable=True),
        sa.Column("registered_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("revoked_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("collector_id", name="pk_collectors"),
        # RESTRICT, not CASCADE (DM-007). Deleting a tenant row must not be
        # able to take evidence-bearing rows with it; SE-017's "no deletion
        # while a covering attestation is valid" is unenforceable if a
        # cascade can fire behind it.
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.tenant_id"],
            name="fk_collectors_tenant", ondelete="RESTRICT", onupdate="RESTRICT",
        ),
        # Referenced by evidence_records as a composite FK, so a record
        # cannot cite another tenant's collector.
        sa.UniqueConstraint("tenant_id", "collector_id",
                            name="uq_collectors_tenant_collector"),
    )

    op.create_table(
        "keys",
        sa.Column("key_id", sa.Text(), nullable=False),
        sa.Column("tenant_id", sa.Text(), nullable=False),
        sa.Column(
            "namespace",
            postgresql.ENUM(*ENUMS["key_namespace"], name="key_namespace",
                            create_type=False),
            nullable=False,
        ),
        sa.Column("public_key", sa.LargeBinary(), nullable=False),
        sa.Column(
            "custody",
            postgresql.ENUM(*ENUMS["key_custody"], name="key_custody",
                            create_type=False),
            nullable=False,
        ),
        sa.Column("valid_from", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("valid_until", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("continuity_signature", sa.LargeBinary(), nullable=True),
        sa.Column("predecessor_key_id", sa.Text(), nullable=True),
        sa.Column("compromised_from", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("key_id", name="pk_keys"),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.tenant_id"],
            name="fk_keys_tenant", ondelete="RESTRICT", onupdate="RESTRICT",
        ),
        # SE-008: a rotation chain. RESTRICT so a predecessor cannot be
        # deleted out from under the continuity signature that references it.
        sa.ForeignKeyConstraint(
            ["predecessor_key_id"], ["keys.key_id"],
            name="fk_keys_predecessor", ondelete="RESTRICT", onupdate="RESTRICT",
        ),
        sa.UniqueConstraint("tenant_id", "key_id", name="uq_keys_tenant_key"),
        # SE-008: continuity is the new key signed by its predecessor. One
        # without the other is a half-recorded rotation, which ES-024 treats
        # as a chain break -- so the row cannot exist in that state.
        sa.CheckConstraint(
            "(predecessor_key_id IS NULL) = (continuity_signature IS NULL)",
            name="ck_keys_continuity_paired",
        ),
    )
    op.create_index("ix_keys_tenant_namespace", "keys", ["tenant_id", "namespace"])
    op.create_index("ix_collectors_tenant", "collectors", ["tenant_id"])

    # --- roles ---------------------------------------------------------
    op.execute(
        f"DO $$ BEGIN"  # noqa: S608 -- names are module constants
        f"  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = "
        f"'{REGISTRY_READER_ROLE}') THEN"
        f'    CREATE ROLE "{REGISTRY_READER_ROLE}" NOLOGIN;'
        f"  END IF;"
        f"END $$;"
    )
    op.execute(
        f"DO $$ BEGIN"  # noqa: S608 -- names are module constants
        f"  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = "
        f"'{APP_LOGIN_ROLE}') THEN"
        f'    CREATE ROLE "{APP_LOGIN_ROLE}" LOGIN NOINHERIT '
        f"      PASSWORD '{_app_password()}';"
        f"  ELSE"
        f'    ALTER ROLE "{APP_LOGIN_ROLE}" LOGIN NOINHERIT '
        f"      PASSWORD '{_app_password()}';"
        f"  END IF;"
        f"END $$;"
    )

    op.execute(f'GRANT CONNECT ON DATABASE "{op.get_bind().engine.url.database}" '
               f'TO "{APP_LOGIN_ROLE}"')
    op.execute(f'GRANT USAGE ON SCHEMA public TO "{APP_LOGIN_ROLE}", '
               f'"{REGISTRY_READER_ROLE}"')

    for table in REGISTRY_TABLES:
        # SELECT only. Registration is an administrative write, not something
        # the ingestion path may do to itself.
        op.execute(f'GRANT SELECT ON TABLE {table} TO "{REGISTRY_READER_ROLE}"')
        op.execute(
            f"REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLE {table} "
            f'FROM "{REGISTRY_READER_ROLE}", "{APP_LOGIN_ROLE}"'
        )

    # --- registry row-level security (SE-011, DM-006 amendment 1) --------
    #
    # A SELECT grant on `tenants` alone lets any tenant enumerate every
    # customer we have; `collectors` exposes another customer's deployment
    # topology. Both are confidentiality failures on their face, and for a
    # product sold on trustworthiness they are the kind an enterprise
    # security reviewer finds in five minutes.
    #
    # RLS rather than partitioning, deliberately. Ingestion resolves a
    # collector by id (SE-018) and must not have to determine the tenant
    # first in order to know which relation to name -- partitioning would
    # invert that dependency. RLS keeps the query shape and still makes the
    # other tenant's rows structurally invisible rather than filtered by
    # application code.
    #
    # The predicate names the role directly instead of calling a helper
    # function: there is no function for a later migration to redefine, and
    # nothing to shadow.
    for table in REGISTRY_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY {POLICY_NAME} ON {table}"
            f"  FOR SELECT USING (current_user = '{TENANT_ROLE_PREFIX}' || tenant_id)"
        )
    # NOT FORCE ROW LEVEL SECURITY: the owner bypasses these policies, which
    # is what leaves provisioning and cross-tenant administration possible
    # through the separately-credentialed path (SE-012 §6, SE-013).


def downgrade() -> None:
    for table in REGISTRY_TABLES:
        op.execute(f"DROP POLICY IF EXISTS {POLICY_NAME} ON {table}")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
        op.execute(f'REVOKE ALL ON TABLE {table} FROM "{REGISTRY_READER_ROLE}"')
    op.drop_index("ix_collectors_tenant", table_name="collectors")
    op.drop_index("ix_keys_tenant_namespace", table_name="keys")
    op.drop_table("keys")
    op.drop_table("collectors")
    op.drop_table("tenants")
    for name in ENUMS:
        op.execute(f"DROP TYPE IF EXISTS {name}")
    for role in (APP_LOGIN_ROLE, REGISTRY_READER_ROLE):
        op.execute(
            f"DO $$ BEGIN"  # noqa: S608 -- names are module constants
            f"  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN"
            f'    DROP OWNED BY "{role}";'
            f'    DROP ROLE "{role}";'
            f"  END IF;"
            f"END $$;"
        )
