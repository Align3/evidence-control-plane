"""The active database guards refuse unsupported administrative mutations.

Negative-first, per AG-007. Every test here asks "under what conditions must
this refuse?" and none of them asserts that a correct boundary can be
recorded -- that is demonstrated incidentally by every other test in the
suite, since `default_boundaries` records one through the real entry point.

Asserted against a live Postgres and against the *owner* connection so the
tests exercise the triggers rather than merely the grants. This is not an
owner-proof retention test: an owner can disable user triggers before issuing
the same DML. The migration and data-model documentation record that trust
boundary explicitly.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import Engine, text

from sdk_python.evidence.signing import UnknownKeyError
from services.admin import assert_admin_tables_protected
from tests.admin_support import AdminActor, boundary_body, signed_boundary
from tests.ledger_support import CHECK_VIOLATION, TENANT_A, TENANT_B

WINDOW_START = datetime(2026, 3, 1, tzinfo=UTC)
WINDOW_END = datetime(2026, 4, 1, tzinfo=UTC)


def _sqlstate(error: Exception) -> str | None:
    return getattr(getattr(error, "orig", None), "sqlstate", None)


@pytest.fixture
def actor(admin_actors: dict[str, AdminActor]) -> AdminActor:
    return admin_actors[TENANT_A]


@pytest.fixture
def recorded(
    owner_engine: Engine, actor: AdminActor, default_boundaries: dict[str, str]
) -> str:
    """A boundary with one qualified family, committed. Left behind on purpose.

    Rolling it back would leave nothing for the mutation attempts below to
    aim at, and a refused `UPDATE` against zero rows succeeds vacuously.
    """
    name = "immutability-probe"
    with owner_engine.begin() as conn:
        existing = conn.execute(
            text("SELECT boundary_ref FROM boundaries WHERE name = :name"),
            {"name": name},
        ).scalar()
        if existing is not None:
            return str(existing)
        qualification_ref = actor.write_qualification(
            conn,
            action_family="refund.issue",
            destination_system="payments-core",
            assigned_class="C1",
            qualified_at=datetime(2026, 1, 15, tzinfo=UTC),
        )
        return actor.write_boundary(
            conn,
            name=name,
            version=1,
            window_start=WINDOW_START,
            window_end=WINDOW_END,
            families=[
                {
                    "action_family": "refund.issue",
                    "destination_system": "payments-core",
                    "qualification_ref": qualification_ref,
                }
            ],
            recorded_at=datetime(2026, 2, 1, tzinfo=UTC),
        )


# --- TM-002: boundaries never mutate -----------------------------------


@pytest.mark.parametrize(
    "statement",
    [
        pytest.param(
            "UPDATE boundaries SET window_end = window_end - interval '1 day'"
            " WHERE boundary_ref = :ref",
            id="narrow-the-window",
        ),
        pytest.param(
            "UPDATE boundaries SET body = body || '{\"deployment\": \"other\"}'::jsonb"
            " WHERE boundary_ref = :ref",
            id="rewrite-the-signed-body",
        ),
        pytest.param(
            "UPDATE boundaries SET signature = signature WHERE boundary_ref = :ref",
            id="no-op-update",
        ),
        pytest.param(
            "DELETE FROM boundaries WHERE boundary_ref = :ref",
            id="delete",
        ),
    ],
)
def test_active_triggers_refuse_owner_dml_on_a_recorded_boundary(
    owner_engine: Engine, recorded: str, statement: str
) -> None:
    """TM-002. Including the no-op update.

    A statement that changes nothing is refused for the same reason as one
    that changes everything: the guarantee is that no `UPDATE` path exists,
    and a trigger that inspected the new row to decide would be a trigger with
    a case that permits `UPDATE`.
    """
    with owner_engine.connect() as conn:
        transaction = conn.begin()
        try:
            with pytest.raises(Exception) as caught:  # noqa: B017 -- SQLSTATE asserted
                conn.execute(text(statement), {"ref": recorded})
            assert _sqlstate(caught.value) == CHECK_VIOLATION
            assert "append-only" in str(caught.value)
        finally:
            transaction.rollback()


@pytest.mark.parametrize(
    "table",
    ["boundaries", "qualification_records", "boundary_action_families"],
)
def test_active_triggers_refuse_owner_truncate_of_admin_history(
    owner_engine: Engine, recorded: str, table: str
) -> None:
    """A row trigger alone does not protect an append-only table from TRUNCATE."""
    with owner_engine.connect() as conn:
        transaction = conn.begin()
        try:
            with pytest.raises(Exception) as caught:  # noqa: B017 -- SQLSTATE asserted
                conn.execute(text(f"TRUNCATE TABLE {table} CASCADE"))  # noqa: S608
            assert _sqlstate(caught.value) == CHECK_VIOLATION
            assert "append-only" in str(caught.value)
        finally:
            transaction.rollback()


def test_a_change_to_a_boundary_is_a_new_version_not_an_edit(
    owner_engine: Engine, actor: AdminActor, recorded: str
) -> None:
    """The supported path, asserted for what it leaves behind.

    Version 1 must still read exactly as signed after version 2 exists.
    `data-model.md` §2.4's `superseded_by` column is deliberately absent, so
    there is no field on version 1 that recording version 2 could have
    touched -- see §2.4 amendment 1.
    """
    from services.admin import boundary_versions

    with owner_engine.connect() as conn:
        transaction = conn.begin()
        try:
            before = conn.execute(
                text(
                    "SELECT canonical_bytes, signature, window_end"
                    "  FROM boundaries WHERE boundary_ref = :ref"
                ),
                {"ref": recorded},
            ).mappings().one()

            qualification_ref = conn.execute(
                text(
                    "SELECT qualification_ref FROM boundary_action_families"
                    " WHERE boundary_ref = :ref"
                ),
                {"ref": recorded},
            ).scalar_one()
            actor.write_boundary(
                conn,
                name="immutability-probe",
                version=2,
                window_start=WINDOW_START,
                # Narrower than version 1: the gerrymandering TM-002 makes
                # visible rather than impossible.
                window_end=WINDOW_END - timedelta(days=10),
                families=[
                    {
                        "action_family": "refund.issue",
                        "destination_system": "payments-core",
                        "qualification_ref": str(qualification_ref),
                    }
                ],
                recorded_at=datetime(2026, 2, 20, tzinfo=UTC),
            )

            after = conn.execute(
                text(
                    "SELECT canonical_bytes, signature, window_end"
                    "  FROM boundaries WHERE boundary_ref = :ref"
                ),
                {"ref": recorded},
            ).mappings().one()
            assert dict(after) == dict(before), (
                "recording a new version altered the version it supersedes"
            )

            versions = boundary_versions(
                conn, tenant_id=TENANT_A, name="immutability-probe"
            )
            assert [item.version for item in versions] == [1, 2]
        finally:
            transaction.rollback()


# --- ES-009: no declared family without a qualification ----------------


def test_a_family_row_without_a_qualification_is_unrepresentable(
    owner_engine: Engine, recorded: str
) -> None:
    """ES-009 as a NOT NULL, tested at the database rather than in Python."""
    with owner_engine.connect() as conn:
        transaction = conn.begin()
        try:
            with pytest.raises(Exception) as caught:  # noqa: B017 -- SQLSTATE asserted
                conn.execute(
                    text(
                        "INSERT INTO boundary_action_families"
                        " (tenant_id, boundary_ref, action_family,"
                        "  qualification_ref, destination_system, fail_behaviour)"
                        " VALUES (:tid, :ref, 'ticket.resolve', NULL,"
                        "         'payments-core', 'fail_closed')"
                    ),
                    {"tid": TENANT_A, "ref": recorded},
                )
            assert _sqlstate(caught.value) == "23502"  # not_null_violation
        finally:
            transaction.rollback()


def test_a_family_cannot_cite_a_qualification_for_a_different_family(
    owner_engine: Engine, actor: AdminActor, recorded: str
) -> None:
    """The overclaim a single-column reference would have permitted.

    A qualification record earns a class for one *(family, destination)*
    triple. Attaching it to another family would let a boundary declare
    `ticket.resolve` at a class nothing ever assessed it at, which is exactly
    the well-formed-but-false declaration ES-009 and CM-003 exist to stop.
    """
    with owner_engine.connect() as conn:
        transaction = conn.begin()
        try:
            refund_qualification = conn.execute(
                text(
                    "SELECT qualification_ref FROM boundary_action_families"
                    " WHERE boundary_ref = :ref"
                ),
                {"ref": recorded},
            ).scalar_one()
            with pytest.raises(Exception) as caught:  # noqa: B017 -- SQLSTATE asserted
                conn.execute(
                    text(
                        "INSERT INTO boundary_action_families"
                        " (tenant_id, boundary_ref, action_family,"
                        "  qualification_ref, destination_system, fail_behaviour)"
                        " VALUES (:tid, :ref, 'ticket.resolve', :qual,"
                        "         'payments-core', 'fail_closed')"
                    ),
                    {"tid": TENANT_A, "ref": recorded, "qual": refund_qualification},
                )
            assert _sqlstate(caught.value) == "23503"  # foreign_key_violation
            assert "fk_boundary_action_families_qualification" in str(caught.value)
        finally:
            transaction.rollback()


def test_a_boundary_declaring_no_family_at_all_is_refused(
    owner_engine: Engine, recorded: str
) -> None:
    """The degenerate case the NOT NULL alone does not reach.

    `SET CONSTRAINTS ALL IMMEDIATE` forces the deferred check without a
    commit, so the transaction can be rolled back afterwards.
    """
    with owner_engine.connect() as conn:
        transaction = conn.begin()
        try:
            source = conn.execute(
                text("SELECT * FROM boundaries WHERE boundary_ref = :ref"),
                {"ref": recorded},
            ).mappings().one()
            conn.execute(
                text(
                    "INSERT INTO boundaries (boundary_ref, tenant_id, name, version,"
                    " canonical_bytes, body, key_id, key_namespace, signature,"
                    " window_start, window_end, recorded_at)"
                    " VALUES (:tid || ':familyless:1', :tid, 'familyless', 1,"
                    "  :bytes, :body, :key_id, 'evidence', :sig,"
                    "  :ws, :we, now())"
                ),
                {
                    "tid": TENANT_A,
                    "bytes": source["canonical_bytes"],
                    "body": "{}",
                    "key_id": source["key_id"],
                    "sig": source["signature"],
                    "ws": WINDOW_START,
                    "we": WINDOW_END,
                },
            )
            with pytest.raises(Exception) as caught:  # noqa: B017 -- SQLSTATE asserted
                conn.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))
            assert _sqlstate(caught.value) == CHECK_VIOLATION
            assert "declares no action family" in str(caught.value)
        finally:
            transaction.rollback()


# --- DM-009 / ES-010: no retroactive upgrade ---------------------------


def test_a_qualification_record_cannot_be_amended_to_a_stronger_class(
    owner_engine: Engine, recorded: str
) -> None:
    """DM-009 exactly: no `UPDATE` on `assigned_class`.

    The whole row is immutable, which is stronger than DM-009 asks. Every
    projected column is derived from `canonical_bytes`, so an `UPDATE` to any
    of them puts the row into a state the signature does not cover -- and
    permitting the harmless columns would leave a trigger with a case that
    allows `UPDATE`, which the class column would then be one predicate away
    from.
    """
    with owner_engine.connect() as conn:
        transaction = conn.begin()
        try:
            with pytest.raises(Exception) as caught:  # noqa: B017 -- SQLSTATE asserted
                conn.execute(
                    text(
                        "UPDATE qualification_records SET assigned_class = 'c1'"
                        " WHERE action_family = 'refund.issue'"
                    )
                )
            assert _sqlstate(caught.value) == CHECK_VIOLATION
            assert "append-only" in str(caught.value)
        finally:
            transaction.rollback()


def test_a_stronger_class_cannot_be_backdated_behind_an_existing_record(
    owner_engine: Engine, admin_actors: dict[str, AdminActor], recorded: str
) -> None:
    """ES-010 / CM-004 / TM-013, refused at the point of writing.

    The attack the resolver would otherwise have to notice: rather than
    amending the C4 record, insert a *new* C1 record dated before it, so that
    a resolver picking "the latest record before the window" finds C1 and
    believes it was in force all along.
    """
    actor = admin_actors[TENANT_A]
    with owner_engine.connect() as conn:
        transaction = conn.begin()
        try:
            actor.write_qualification(
                conn,
                action_family="backdate.probe",
                destination_system="payments-core",
                assigned_class="C4",
                qualified_at=datetime(2026, 6, 1, tzinfo=UTC),
            )
            with pytest.raises(Exception) as caught:  # noqa: B017 -- SQLSTATE asserted
                actor.write_qualification(
                    conn,
                    action_family="backdate.probe",
                    destination_system="payments-core",
                    assigned_class="C1",
                    qualified_at=datetime(2026, 5, 1, tzinfo=UTC),
                )
            assert _sqlstate(caught.value) == CHECK_VIOLATION
            assert "may not be backdated" in str(caught.value)
        finally:
            transaction.rollback()


def test_a_stronger_class_at_the_same_instant_is_refused(
    owner_engine: Engine, admin_actors: dict[str, AdminActor], recorded: str
) -> None:
    """The boundary case of the same rule.

    Two records for one triple at one instant leave "the class in force at T"
    without an answer, and the tie would be broken by insertion order -- which
    is to say, by whichever the vendor wrote second.
    """
    actor = admin_actors[TENANT_A]
    instant = datetime(2026, 6, 1, tzinfo=UTC)
    with owner_engine.connect() as conn:
        transaction = conn.begin()
        try:
            actor.write_qualification(
                conn,
                action_family="tie.probe",
                destination_system="payments-core",
                assigned_class="C4",
                qualified_at=instant,
            )
            with pytest.raises(Exception) as caught:  # noqa: B017 -- SQLSTATE asserted
                actor.write_qualification(
                    conn,
                    action_family="tie.probe",
                    destination_system="payments-core",
                    assigned_class="C1",
                    qualified_at=instant,
                )
            assert _sqlstate(caught.value) == CHECK_VIOLATION
        finally:
            transaction.rollback()


def test_a_weaker_class_may_be_recorded_at_any_date(
    owner_engine: Engine, admin_actors: dict[str, AdminActor], recorded: str
) -> None:
    """CM-004 permits a mid-window downgrade, so the guard is directional.

    A rule that refused every out-of-order record would also refuse the
    downgrade, and a downgrade the system will not accept is a system that
    keeps claiming a class it has learned it does not have.
    """
    actor = admin_actors[TENANT_A]
    with owner_engine.connect() as conn:
        transaction = conn.begin()
        try:
            actor.write_qualification(
                conn,
                action_family="downgrade.probe",
                destination_system="payments-core",
                assigned_class="C1",
                qualified_at=datetime(2026, 6, 1, tzinfo=UTC),
            )
            actor.write_qualification(
                conn,
                action_family="downgrade.probe",
                destination_system="payments-core",
                assigned_class="C4",
                qualified_at=datetime(2026, 5, 1, tzinfo=UTC),
                enumeration_capable=False,
            )
        finally:
            transaction.rollback()


# --- CM-005 / CM-006: the qualifying constraints -----------------------


@pytest.mark.parametrize(
    ("assigned_class", "body_kwargs", "requirement"),
    [
        pytest.param(
            "C1",
            {"identity_isolation_attribute": None},
            "CM-006",
            id="no-isolation-must-be-c5",
        ),
        pytest.param(
            "C2",
            {"identity_vendor_settable": True},
            "CM-005",
            id="vendor-settable-attribute-cannot-reach-c2",
        ),
        pytest.param(
            "C1",
            {"enumeration_capable": False},
            "CM-009",
            id="ratio-class-without-enumeration",
        ),
    ],
)
def test_the_qualifying_constraints_are_enforced_by_the_database(
    owner_engine: Engine,
    admin_actors: dict[str, AdminActor],
    recorded: str,
    assigned_class: str,
    body_kwargs: dict[str, Any],
    requirement: str,
) -> None:
    """§4 and §6 of the methodology, as CHECK constraints.

    Each of these is a numbered requirement that caps a class, and each is a
    row the system must be unable to hold: a C1 record with no isolating
    attribute is a denominator that cannot separate agent activity from human
    activity while claiming the strongest class available.
    """
    actor = admin_actors[TENANT_A]
    with owner_engine.connect() as conn:
        transaction = conn.begin()
        try:
            with pytest.raises(Exception) as caught:  # noqa: B017 -- SQLSTATE asserted
                actor.write_qualification(
                    conn,
                    action_family=f"constraint.probe.{requirement.lower()}",
                    destination_system="payments-core",
                    assigned_class=assigned_class,
                    qualified_at=datetime(2026, 6, 1, tzinfo=UTC),
                    **body_kwargs,
                )
            assert _sqlstate(caught.value) == CHECK_VIOLATION
        finally:
            transaction.rollback()


def test_confirmation_without_enumeration_is_a_valid_record(
    owner_engine: Engine, admin_actors: dict[str, AdminActor], recorded: str
) -> None:
    """AC-008: the two capabilities are independent.

    The constraint above caps such a record at C4/C5. It must not reject it:
    a connector that can confirm an individual action and cannot enumerate
    the population supports per-action reconciliation, which is useful and
    which the record has to be able to say. What it must not support is a
    window-level coverage claim, and `supports_window_coverage_claim` answers
    that separately.
    """
    from services.admin import qualification_history

    actor = admin_actors[TENANT_A]
    with owner_engine.connect() as conn:
        transaction = conn.begin()
        try:
            actor.write_qualification(
                conn,
                action_family="confirm.only",
                destination_system="payments-core",
                assigned_class="C5",
                qualified_at=datetime(2026, 6, 1, tzinfo=UTC),
                enumeration_capable=False,
                confirmation_capable=True,
            )
            history = qualification_history(
                conn,
                tenant_id=TENANT_A,
                action_family="confirm.only",
                destination_system="payments-core",
            )
            assert len(history) == 1
            record = history[0]
            assert record.confirmation_capable is True
            assert record.enumeration_capable is False
            assert record.supports_window_coverage_claim is False
        finally:
            transaction.rollback()


# --- SE-011: tenant scoping --------------------------------------------


def test_a_boundary_cannot_use_another_tenants_key(
    owner_engine: Engine, admin_actors: dict[str, AdminActor], recorded: str
) -> None:
    """DM-016's composite-key reasoning, applied to the boundary tables."""
    actor = admin_actors[TENANT_A]
    other = admin_actors[TENANT_B]
    with owner_engine.connect() as conn:
        transaction = conn.begin()
        try:
            qualification_ref = actor.write_qualification(
                conn,
                action_family="crosskey.probe",
                destination_system="payments-core",
                assigned_class="C1",
                qualified_at=datetime(2026, 1, 1, tzinfo=UTC),
            )
            record, canonical, signature = signed_boundary(
                tenant_id=TENANT_A,
                collector_id=actor.collector_id,
                key_id=other.key_id,
                private_key=other.private_key,
                name="crosskey",
                version=1,
                body=boundary_body(
                    tenant_id=TENANT_A,
                    version=1,
                    window_start=WINDOW_START,
                    window_end=WINDOW_END,
                    families=[
                        {
                            "action_family": "crosskey.probe",
                            "destination_system": "payments-core",
                            "qualification_ref": qualification_ref,
                        }
                    ],
                ),
            )
            from services.admin import record_boundary

            with pytest.raises(UnknownKeyError, match="unknown evidence signing key"):
                record_boundary(
                    conn,
                    record=record,
                    canonical_bytes=canonical,
                    signature=signature,
                    recorded_at=datetime(2026, 2, 1, tzinfo=UTC),
                )
        finally:
            transaction.rollback()


def test_a_tenant_cannot_read_another_tenants_boundaries(
    tenant_engines: Any, default_boundaries: dict[str, str]
) -> None:
    """SE-011 / DM-022, extended to the scope declarations.

    A boundary names a tenant's agents, action families, destination systems
    and enforcement points -- their whole deployment topology. The `SELECT`
    grant tenant roles inherit through `evidence_registry_reader` reaches
    these tables, so without a policy it would reach every tenant's.
    """
    from services.ledger import tenant_connection

    with tenant_connection(tenant_engines, TENANT_A) as conn:
        visible = {
            row[0]
            for row in conn.execute(text("SELECT tenant_id FROM boundaries"))
        }
    assert visible == {TENANT_A}, f"tenant {TENANT_A} sees boundaries of {visible}"


def test_the_protections_are_reported_as_in_force(owner_engine: Engine) -> None:
    """Introspection, not trust.

    A dropped trigger or a disabled policy reads exactly like a protected
    table until someone issues the statement it was there to refuse.
    """
    with owner_engine.connect() as conn:
        assert_admin_tables_protected(conn)
