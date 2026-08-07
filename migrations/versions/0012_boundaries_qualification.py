"""EV-12 0012: boundaries, qualification records, and the boundary_ref FK.

Claimed in `docs/data-model.md` §3 before this file existed (DM-001, AG-004).

Three tables and one deferred foreign key:

``qualification_records``
    `evidence-spec.md` §5.2 / `data-model.md` §2.5. The output of the
    `coverage-methodology.md` §7 procedure -- the record that entitles a
    window to claim anything above `observed`.

``boundaries``
    `evidence-spec.md` §5.1 / `data-model.md` §2.4. Signed, versioned, and
    immutable (TM-002).

``boundary_action_families``
    A projection of `boundaries.body.action_families[]`, one row per declared
    family, carrying the family's `qualification_ref` as a **NOT NULL**
    composite foreign key. This is what makes ES-009 -- "a boundary declaring
    a family without qualification is invalid" -- a state the database cannot
    represent rather than a check some code path can skip.

``evidence_records.boundary_ref``
    DM-017 deferred this foreign key to EV-12's migration because
    ``boundaries`` did not exist when 0002 ran. It lands here. DM-017 names
    "migration 0003"; that reservation was voided and the number is now 0012
    (§3 amendment 1, DM-025).

Why triggers and not only grants
--------------------------------
AC-012's precedent is that immutability lives in the database as a role
grant, and grants are used here too. They are not sufficient on their own for
these two tables, because of *who* the adversary is.

`threat-model.md` §4.2 (boundary gerrymandering) and §4.10 (retroactive
qualification upgrade) both name the **vendor** as the actor. The vendor holds
the migrator credential, which owns these relations, and an owner is not
constrained by its own grants. A grant-only design would leave "the boundary
was never rewritten" resting on the honesty of the party the attestation is
about -- which is the one assurance the product cannot ask a relying party to
take on trust.

So both tables carry a `BEFORE UPDATE OR DELETE` trigger that raises
unconditionally. A trigger binds the owner. Disabling it requires
`ALTER TABLE ... DISABLE TRIGGER`, which is DDL through the audited schema
path (SE-012 §6, SE-024), or a superuser flipping `session_replication_role`
-- both of which are visible acts rather than an ordinary `UPDATE`.

Revision ID: 0012
Revises: 0011
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

BOUNDARIES = "boundaries"
QUALIFICATIONS = "qualification_records"
BOUNDARY_FAMILIES = "boundary_action_families"
EVIDENCE = "evidence_records"

REGISTRY_READER_ROLE = "evidence_registry_reader"
APP_LOGIN_ROLE = "evidence_app"
TENANT_ROLE_PREFIX = "evidence_tenant_"
POLICY_NAME = "tenant_isolation"

#: Declaration order is the class order. Postgres compares enum labels by the
#: order they were declared, so `'c1' < 'c2'` holds in SQL and "stronger than"
#: is expressible as a plain comparison in the retroactive-upgrade trigger.
#: `coverage-methodology.md` §3 lists the classes strongest first, so the two
#: orders agree by construction rather than by a mapping someone maintains.
DENOMINATOR_CLASS = ("c1", "c2", "c3", "c4", "c5")

KEY_NAMESPACE = postgresql.ENUM(
    "evidence", "issuer", name="key_namespace", create_type=False
)

#: `data-model.md` §2.4 gives `boundary_ref` the form `{tenant}:{name}:{version}`.
#: A name containing a colon would make that decomposition ambiguous, so the
#: alphabet excludes one.
BOUNDARY_NAME_PATTERN = "^[a-z0-9][a-z0-9._-]{0,62}$"

REFUSE_MUTATION_FUNCTION = "evidence_refuse_row_mutation"
REFUSE_UPGRADE_FUNCTION = "qualification_refuse_retroactive_upgrade"
REQUIRE_FAMILIES_FUNCTION = "boundary_require_declared_families"

#: `check_violation`. Reusing an existing SQLSTATE rather than minting a
#: `P0001` keeps the refusal indistinguishable, to a caller, from the CHECK
#: constraints alongside it: both mean "the database will not hold this".
REFUSAL_SQLSTATE = "23514"

_IMMUTABLE_TABLES = (BOUNDARIES, QUALIFICATIONS, BOUNDARY_FAMILIES)
_TENANT_SCOPED_TABLES = (BOUNDARIES, QUALIFICATIONS, BOUNDARY_FAMILIES)


def _create_denominator_class_enum() -> None:
    values = ", ".join(f"'{label}'" for label in DENOMINATOR_CLASS)
    op.execute(
        "DO $$ BEGIN"  # noqa: S608 -- labels are a module constant
        "  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'denominator_class')"
        "  THEN"
        f"    CREATE TYPE denominator_class AS ENUM ({values});"
        "  END IF;"
        "END $$;"
    )


def _create_refusal_functions() -> None:
    # TG_OP and TG_TABLE_NAME rather than a per-table function: one function
    # that names the relation it refused keeps the message accurate without
    # three near-identical bodies drifting apart.
    op.execute(
        f"""
        CREATE OR REPLACE FUNCTION {REFUSE_MUTATION_FUNCTION}()
        RETURNS trigger LANGUAGE plpgsql AS $fn$
        BEGIN
            RAISE EXCEPTION
                '% on % is refused: the relation is append-only '
                '(TM-002, ES-010, DM-009)', TG_OP, TG_TABLE_NAME
                USING ERRCODE = '{REFUSAL_SQLSTATE}';
        END;
        $fn$;
        """
    )

    # ES-010 / CM-004 / TM-013. A stronger class must arrive as a new record
    # whose `qualified_at` is later than every record already qualifying the
    # same (tenant, action family, destination system) triple. Enforcing the
    # ordering at write time means the resolver in
    # `services/admin/qualification.py` reads a history that is already
    # monotonic in the strengthening direction, and means an operator with a
    # psql prompt cannot install the backdated record the resolver would
    # otherwise have to notice.
    #
    # A *weaker* record may be backdated. CM-004 permits a mid-window
    # downgrade, and a downgrade can only reduce what may be claimed, so
    # accepting it is conservative. It invalidates attestations already issued
    # over the affected windows -- handling that is supersession (AR-011,
    # EV-18), not something this trigger can do.
    op.execute(
        f"""
        CREATE OR REPLACE FUNCTION {REFUSE_UPGRADE_FUNCTION}()
        RETURNS trigger LANGUAGE plpgsql AS $fn$
        DECLARE
            blocking {QUALIFICATIONS}%ROWTYPE;
        BEGIN
            SELECT * INTO blocking
              FROM {QUALIFICATIONS}
             WHERE tenant_id = NEW.tenant_id
               AND action_family = NEW.action_family
               AND destination_system = NEW.destination_system
               AND assigned_class > NEW.assigned_class
               AND qualified_at >= NEW.qualified_at
             ORDER BY qualified_at DESC
             LIMIT 1;

            IF FOUND THEN
                RAISE EXCEPTION
                    'qualification % assigns % to (%, %) at %, which is not '
                    'later than % holding the weaker class % -- a stronger '
                    'class may not be backdated (ES-010, CM-004, TM-013)',
                    NEW.qualification_ref, NEW.assigned_class,
                    NEW.action_family, NEW.destination_system,
                    NEW.qualified_at, blocking.qualification_ref,
                    blocking.assigned_class
                    USING ERRCODE = '{REFUSAL_SQLSTATE}';
            END IF;

            RETURN NEW;
        END;
        $fn$;
        """  # noqa: S608 -- every interpolation is a module constant
    )

    # The NOT NULL `qualification_ref` on `boundary_action_families` makes a
    # family without a qualification unrepresentable. It says nothing about a
    # boundary with no family rows at all, which is the same defect one step
    # further along: a scope declaration under which every family is
    # undeclared, and which evidence may nonetheless cite through the
    # `boundary_ref` foreign key. ES-009 calls such a boundary invalid, so it
    # is refused here too.
    #
    # DEFERRABLE INITIALLY DEFERRED because the boundary row necessarily
    # exists before its family rows can reference it -- the check is a
    # statement about the committed transaction, not about the moment of the
    # first INSERT.
    op.execute(
        f"""
        CREATE OR REPLACE FUNCTION {REQUIRE_FAMILIES_FUNCTION}()
        RETURNS trigger LANGUAGE plpgsql AS $fn$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM {BOUNDARY_FAMILIES}
                 WHERE tenant_id = NEW.tenant_id
                   AND boundary_ref = NEW.boundary_ref
            ) THEN
                RAISE EXCEPTION
                    'boundary % declares no action family; ES-009 makes a '
                    'boundary without a qualified family invalid',
                    NEW.boundary_ref
                    USING ERRCODE = '{REFUSAL_SQLSTATE}';
            END IF;
            RETURN NULL;
        END;
        $fn$;
        """  # noqa: S608 -- every interpolation is a module constant
    )


def _qualification_records() -> None:
    op.create_table(
        QUALIFICATIONS,
        sa.Column("qualification_ref", sa.Text(), nullable=False),
        sa.Column("tenant_id", sa.Text(), nullable=False),
        sa.Column("action_family", sa.Text(), nullable=False),
        sa.Column("destination_system", sa.Text(), nullable=False),
        sa.Column(
            "assigned_class",
            postgresql.ENUM(*DENOMINATOR_CLASS, name="denominator_class",
                            create_type=False),
            nullable=False,
        ),
        # CM-010 / AC-008: two capabilities, recorded separately. Nothing here
        # constrains one by the other, and that is the point -- confirmation
        # without enumeration is a valid, useful record.
        sa.Column("enumeration_capable", sa.Boolean(), nullable=False),
        sa.Column("confirmation_capable", sa.Boolean(), nullable=False),
        sa.Column("identity_isolation_attribute", sa.Text(), nullable=True),
        sa.Column("identity_vendor_settable", sa.Boolean(), nullable=False),
        sa.Column("authoritative_time_available", sa.Boolean(), nullable=False),
        sa.Column("settlement_lag_s", sa.Integer(), nullable=False),
        sa.Column("source_retention_days", sa.Integer(), nullable=False),
        sa.Column("deletion_traceless_possible", sa.Boolean(), nullable=False),
        # Authoritative: the JCS-canonical record excluding `signature`
        # (ES-021, DM-023). Every column above is a projection of it.
        sa.Column("canonical_bytes", sa.LargeBinary(), nullable=False),
        sa.Column("body", postgresql.JSONB(), nullable=False),
        sa.Column("key_id", sa.Text(), nullable=False),
        sa.Column(
            "key_namespace",
            KEY_NAMESPACE,
            nullable=False,
            server_default=sa.text("'evidence'::key_namespace"),
        ),
        sa.Column("signature", sa.LargeBinary(), nullable=False),
        sa.Column("qualified_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("revalidate_after", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("qualification_ref", name="pk_qualification_records"),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.tenant_id"],
            name="fk_qualification_records_tenant",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        # DM-008 / SE-003: a qualification record is customer evidence, so an
        # issuer key may not sign it. Same CHECK-pinned discriminator shape
        # migration 0010 uses on `evidence_records`, and it reuses 0010's
        # `uq_keys_tenant_key_namespace` rather than declaring another
        # uniqueness constraint over the same columns.
        sa.ForeignKeyConstraint(
            ["tenant_id", "key_id", "key_namespace"],
            ["keys.tenant_id", "keys.key_id", "keys.namespace"],
            name="fk_qualification_records_key",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.CheckConstraint(
            "key_namespace = 'evidence'::key_namespace",
            name="ck_qualification_records_key_namespace_evidence",
        ),
        sa.CheckConstraint(
            "octet_length(signature) = 64",
            name="ck_qualification_records_signature_ed25519",
        ),
        sa.CheckConstraint(
            "octet_length(canonical_bytes) > 0",
            name="ck_qualification_records_canonical_bytes_present",
        ),
        sa.CheckConstraint(
            "settlement_lag_s >= 0", name="ck_qualification_records_settlement_lag"
        ),
        sa.CheckConstraint(
            "source_retention_days >= 0",
            name="ck_qualification_records_retention_days",
        ),
        sa.CheckConstraint(
            "revalidate_after > qualified_at",
            name="ck_qualification_records_revalidation_forward",
        ),
        # CM-006: without identity isolation the class is C5 regardless of
        # enumeration capability. Stated as a requirement, so stated as a
        # constraint.
        sa.CheckConstraint(
            "identity_isolation_attribute IS NOT NULL "
            "OR assigned_class = 'c5'::denominator_class",
            name="ck_qualification_records_no_isolation_is_c5",
        ),
        sa.CheckConstraint(
            "identity_isolation_attribute IS NOT NULL "
            "OR identity_vendor_settable = false",
            name="ck_qualification_records_settable_needs_attribute",
        ),
        # CM-005: at C1 or C2 the isolating attribute must be one the vendor
        # cannot set arbitrarily per request.
        sa.CheckConstraint(
            "assigned_class NOT IN ('c1'::denominator_class, 'c2'::denominator_class) "
            "OR (identity_isolation_attribute IS NOT NULL "
            "    AND identity_vendor_settable = false)",
            name="ck_qualification_records_c1_c2_isolation",
        ),
        # C1, C2 and C3 are the classes that emit a coverage ratio
        # (`coverage-methodology.md` §6), and a ratio needs an enumerable
        # population. A confirmation-only source therefore cannot reach them.
        # This is the AC-008 direction that the *record* can express; the
        # window-level refusal is the coverage engine's (EV-16).
        sa.CheckConstraint(
            "assigned_class IN ('c4'::denominator_class, 'c5'::denominator_class) "
            "OR enumeration_capable = true",
            name="ck_qualification_records_ratio_class_enumerates",
        ),
        # Referenced compositely by `boundary_action_families` so a boundary
        # cannot attach a family to a record that qualified a different family
        # or a different destination system.
        sa.UniqueConstraint(
            "tenant_id",
            "qualification_ref",
            "action_family",
            "destination_system",
            name="uq_qualification_records_scope",
        ),
        # A total order on `qualified_at` per triple. Without it two records
        # could share an instant and "the class in force at T" would have no
        # answer.
        sa.UniqueConstraint(
            "tenant_id",
            "action_family",
            "destination_system",
            "qualified_at",
            name="uq_qualification_records_triple_instant",
        ),
    )
    op.create_index(
        "ix_qualification_records_triple",
        QUALIFICATIONS,
        ["tenant_id", "action_family", "destination_system", "qualified_at"],
    )


def _boundaries() -> None:
    op.create_table(
        BOUNDARIES,
        sa.Column("boundary_ref", sa.Text(), nullable=False),
        sa.Column("tenant_id", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("canonical_bytes", sa.LargeBinary(), nullable=False),
        sa.Column("body", postgresql.JSONB(), nullable=False),
        sa.Column("key_id", sa.Text(), nullable=False),
        sa.Column(
            "key_namespace",
            KEY_NAMESPACE,
            nullable=False,
            server_default=sa.text("'evidence'::key_namespace"),
        ),
        sa.Column("signature", sa.LargeBinary(), nullable=False),
        sa.Column("window_start", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("window_end", sa.TIMESTAMP(timezone=True), nullable=False),
        # The hosted service's observation of when this version was recorded.
        # AR-027 floors the effective interval at it so a boundary written
        # after the fact cannot be backdated into force. It is deliberately
        # not read from the customer-signed body: a self-declared recording
        # time is exactly the value the rule exists to distrust (cf. ES-019,
        # which keeps `ingest_time` out of the customer record for the same
        # reason).
        sa.Column("recorded_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("boundary_ref", name="pk_boundaries"),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.tenant_id"],
            name="fk_boundaries_tenant",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "key_id", "key_namespace"],
            ["keys.tenant_id", "keys.key_id", "keys.namespace"],
            name="fk_boundaries_key",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.CheckConstraint(
            "key_namespace = 'evidence'::key_namespace",
            name="ck_boundaries_key_namespace_evidence",
        ),
        sa.CheckConstraint(
            "octet_length(signature) = 64", name="ck_boundaries_signature_ed25519"
        ),
        sa.CheckConstraint(
            "octet_length(canonical_bytes) > 0", name="ck_boundaries_canonical_present"
        ),
        sa.CheckConstraint("version >= 1", name="ck_boundaries_version_positive"),
        sa.CheckConstraint(
            f"name ~ '{BOUNDARY_NAME_PATTERN}'", name="ck_boundaries_name_alphabet"
        ),
        sa.CheckConstraint(
            "window_end > window_start", name="ck_boundaries_window_ordered"
        ),
        # DM-024's composite-reference reasoning, applied to the ref format:
        # making `{tenant}:{name}:{version}` a CHECK rather than a convention
        # means a boundary_ref parsed anywhere in the system decomposes to the
        # row it names, and a row cannot claim a ref belonging to another
        # tenant's namespace.
        sa.CheckConstraint(
            "boundary_ref = tenant_id || ':' || name || ':' || version::text",
            name="ck_boundaries_ref_composition",
        ),
        sa.UniqueConstraint("tenant_id", "name", "version", name="uq_boundaries_version"),
        # Target of the composite FK from `evidence_records` and from
        # `boundary_action_families`: a single-column reference would let a
        # record attribute itself to another tenant's boundary (DM-016).
        sa.UniqueConstraint("tenant_id", "boundary_ref", name="uq_boundaries_tenant_ref"),
    )
    op.create_index(
        "ix_boundaries_tenant_name_version",
        BOUNDARIES,
        ["tenant_id", "name", "version"],
    )


def _boundary_action_families() -> None:
    op.create_table(
        BOUNDARY_FAMILIES,
        sa.Column("tenant_id", sa.Text(), nullable=False),
        sa.Column("boundary_ref", sa.Text(), nullable=False),
        sa.Column("action_family", sa.Text(), nullable=False),
        # ES-009 in one word: NOT NULL. A boundary declaring a family without
        # a qualification reference has no row it could insert.
        sa.Column("qualification_ref", sa.Text(), nullable=False),
        # CM-003: the boundary declares, per family, the denominator source.
        # Carried here and tied to the qualification record by the composite
        # FK below, so the two cannot name different destination systems.
        sa.Column("destination_system", sa.Text(), nullable=False),
        sa.Column("fail_behaviour", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint(
            "tenant_id", "boundary_ref", "action_family",
            name="pk_boundary_action_families",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "boundary_ref"],
            ["boundaries.tenant_id", "boundaries.boundary_ref"],
            name="fk_boundary_action_families_boundary",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        # Four columns, not one. `(tenant_id, qualification_ref)` alone would
        # let a boundary cite a record that qualified `ticket.resolve` as the
        # qualification for `refund.issue` -- a well-formed boundary asserting
        # a class it was never granted, which is the overclaim ES-009 and
        # CM-003 exist to prevent.
        sa.ForeignKeyConstraint(
            ["tenant_id", "qualification_ref", "action_family", "destination_system"],
            [
                "qualification_records.tenant_id",
                "qualification_records.qualification_ref",
                "qualification_records.action_family",
                "qualification_records.destination_system",
            ],
            name="fk_boundary_action_families_qualification",
            ondelete="RESTRICT",
            onupdate="RESTRICT",
        ),
        sa.CheckConstraint(
            "fail_behaviour IN ('fail_closed', 'fail_open')",
            name="ck_boundary_action_families_fail_behaviour",
        ),
    )
    op.create_index(
        "ix_boundary_action_families_qualification",
        BOUNDARY_FAMILIES,
        ["tenant_id", "qualification_ref"],
    )


def _attach_triggers() -> None:
    for table in _IMMUTABLE_TABLES:
        op.execute(
            f"CREATE TRIGGER {table}_refuse_mutation"
            f" BEFORE UPDATE OR DELETE ON {table}"
            f" FOR EACH ROW EXECUTE FUNCTION {REFUSE_MUTATION_FUNCTION}()"
        )
    op.execute(
        f"CREATE TRIGGER {QUALIFICATIONS}_refuse_retroactive_upgrade"
        f" BEFORE INSERT ON {QUALIFICATIONS}"
        f" FOR EACH ROW EXECUTE FUNCTION {REFUSE_UPGRADE_FUNCTION}()"
    )
    op.execute(
        f"CREATE CONSTRAINT TRIGGER {BOUNDARIES}_require_declared_families"
        f" AFTER INSERT ON {BOUNDARIES}"
        f" DEFERRABLE INITIALLY DEFERRED"
        f" FOR EACH ROW EXECUTE FUNCTION {REQUIRE_FAMILIES_FUNCTION}()"
    )


def _grants_and_isolation() -> None:
    for table in _TENANT_SCOPED_TABLES:
        op.execute(f"REVOKE ALL ON TABLE {table} FROM PUBLIC")
        # SELECT only, as with the other registry relations: recording a
        # boundary or a qualification is an administrative write through the
        # separately-credentialed path (SE-012 §6), not something a traffic-
        # handling role may do to its own scope declaration.
        op.execute(f'GRANT SELECT ON TABLE {table} TO "{REGISTRY_READER_ROLE}"')
        op.execute(
            f"REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLE {table} "
            f'FROM "{REGISTRY_READER_ROLE}", "{APP_LOGIN_ROLE}"'
        )
        # Same reasoning as DM-022 on the registry: tenant roles reach these
        # rows through REGISTRY_READER_ROLE, and without a policy that grant
        # would let any customer read every other customer's declared scope
        # and denominator classes.
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY {POLICY_NAME} ON {table}"
            f"  FOR SELECT USING (current_user = '{TENANT_ROLE_PREFIX}' || tenant_id)"
        )


def upgrade() -> None:
    bind = op.get_bind()

    # DM-017's deferral is discharged below by adding the foreign key that
    # 0002 could not. Existing rows cite boundaries that were never recorded
    # anywhere, so there is no honest way to validate them: inventing a
    # `boundaries` row per distinct `boundary_ref` would fabricate a signed
    # scope declaration, which is the same class of act migration 0010 refused
    # for receipts (DM-024).
    if bind.execute(
        sa.text(f'SELECT EXISTS (SELECT 1 FROM "{EVIDENCE}")')  # noqa: S608 -- constant
    ).scalar_one():
        raise RuntimeError(
            "migration 0012 refuses a non-empty ledger: existing rows carry an "
            "unvalidated boundary_ref (DM-017) and the boundaries they name "
            "were never recorded, so the deferred foreign key cannot be "
            "validated without fabricating scope declarations"
        )

    _create_denominator_class_enum()
    _qualification_records()
    _boundaries()
    _boundary_action_families()
    # After the tables: the upgrade guard declares a `%ROWTYPE` variable, so
    # the relation has to exist before the function body will compile.
    _create_refusal_functions()

    # DM-017, discharged. Composite rather than single-column for DM-016's
    # reason: a record must not be able to declare itself in scope of another
    # tenant's boundary.
    op.create_foreign_key(
        "fk_evidence_records_boundary",
        EVIDENCE,
        BOUNDARIES,
        ["tenant_id", "boundary_ref"],
        ["tenant_id", "boundary_ref"],
        ondelete="RESTRICT",
        onupdate="RESTRICT",
    )

    _attach_triggers()
    _grants_and_isolation()


def downgrade() -> None:
    op.drop_constraint("fk_evidence_records_boundary", EVIDENCE, type_="foreignkey")
    for table in _TENANT_SCOPED_TABLES:
        op.execute(f"DROP POLICY IF EXISTS {POLICY_NAME} ON {table}")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
        op.execute(f'REVOKE ALL ON TABLE {table} FROM "{REGISTRY_READER_ROLE}"')
    op.drop_table(BOUNDARY_FAMILIES)
    op.drop_table(BOUNDARIES)
    op.drop_table(QUALIFICATIONS)
    op.execute(f"DROP FUNCTION IF EXISTS {REQUIRE_FAMILIES_FUNCTION}()")
    op.execute(f"DROP FUNCTION IF EXISTS {REFUSE_UPGRADE_FUNCTION}()")
    op.execute(f"DROP FUNCTION IF EXISTS {REFUSE_MUTATION_FUNCTION}()")
    op.execute("DROP TYPE IF EXISTS denominator_class")
