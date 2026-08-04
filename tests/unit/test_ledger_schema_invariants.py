"""Schema invariants the acceptance scenarios do not reach.

AC-S-004 and AC-S-006 exercise grants and the projection. These cover the
structural rules stated in `data-model.md` that nothing else would notice
being broken: DM-007 (no cascades), ES-006 (fork detection as a database
constraint), and the correspondence between `services/ledger/schema.py` and
what the migrations actually built.

Negative-first (AG-007): each one asserts a refusal.
"""

from __future__ import annotations

import importlib
from typing import Any

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import IntegrityError

from services.ledger import (
    APP_GRANTS,
    EVIDENCE_PARENT_TABLE,
    TenantEngines,
    evidence_partition,
    provision_tenant,
    tenant_connection,
    verify_projection,
)
from services.ledger.naming import MAX_TENANT_ID_LENGTH
from tests.ledger_support import (
    CHECK_VIOLATION,
    TENANT_A,
    UNIQUE_VIOLATION,
    RecordFactory,
)

EVIDENCE_TABLES = ("evidence_records", "collectors", "keys", "tenants")


def test_no_cascade_on_any_constraint_touching_evidence(owner_engine: Engine) -> None:
    """DM-007: a cascade makes SE-017 unenforceable.

    "Evidence within the window of a valid attestation cannot be deleted"
    is a check that runs in the deletion path. A cascade fires *underneath*
    that path, from a delete on some other table, and no check in the
    deletion path can see it coming. So there must be none -- not "none we
    rely on", none at all.
    """
    with owner_engine.connect() as conn:
        offenders = conn.execute(
            text(
                "SELECT c.conname, t.relname AS on_table, r.relname AS references_table,"
                "       c.confdeltype, c.confupdtype"
                " FROM pg_constraint c"
                " JOIN pg_class t ON t.oid = c.conrelid"
                " JOIN pg_class r ON r.oid = c.confrelid"
                " WHERE c.contype = 'f'"
                "   AND (c.confdeltype <> 'r' OR c.confupdtype <> 'r')"
                "   AND (t.relname = ANY(:tables) OR r.relname = ANY(:tables)"
                "        OR t.relname LIKE :partitions)"
            ),
            {
                "tables": list(EVIDENCE_TABLES),
                "partitions": f"{EVIDENCE_PARENT_TABLE}\\_%",
            },
        ).all()
    assert offenders == [], (
        "foreign keys touching evidence must be ON DELETE/UPDATE RESTRICT: "
        + ", ".join(
            f"{o.conname} on {o.on_table} -> {o.references_table} "
            f"(del={o.confdeltype}, upd={o.confupdtype})"
            for o in offenders
        )
    )


def test_fork_is_refused_by_the_database_not_by_ingestion(
    tenant_engines: TenantEngines, record_factories: dict[str, RecordFactory]
) -> None:
    """ES-006: two records sharing (stream_id, sequence) are a fatal integrity
    failure that must be *reported*, never resolved.

    Enforced by the unique constraint, so an ingestion path that forgets to
    check cannot admit a fork. It is refused before any application code runs.
    """
    factory = record_factories[TENANT_A]
    first = factory.next_record()
    partition = evidence_partition(TENANT_A)
    with tenant_connection(tenant_engines, TENANT_A) as conn:
        conn.execute(partition.insert(), dict(first))

    # Same stream and sequence, different record_id: a fork, not a duplicate.
    forked = factory.next_record(sequence=first["sequence"])
    assert forked["record_id"] != first["record_id"]
    assert (forked["stream_id"], forked["sequence"]) == (
        first["stream_id"], first["sequence"]
    )

    with pytest.raises(IntegrityError) as caught:
        with tenant_connection(tenant_engines, TENANT_A) as conn:
            conn.execute(partition.insert(), dict(forked))
    assert getattr(caught.value.orig, "sqlstate", None) == UNIQUE_VIOLATION
    # The partition's copy of the constraint carries a generated name, so
    # match on the key it refused rather than on the name.
    assert "(tenant_id, stream_id, sequence)" in str(caught.value.orig)


def test_sequence_zero_is_refused(
    tenant_engines: TenantEngines, record_factories: dict[str, RecordFactory]
) -> None:
    """ES-006: sequence is monotonic within a stream, starting at 1."""
    row = dict(record_factories[TENANT_A].next_record(sequence=0))
    with pytest.raises(IntegrityError) as caught:
        with tenant_connection(tenant_engines, TENANT_A) as conn:
            conn.execute(evidence_partition(TENANT_A).insert(), row)
    assert getattr(caught.value.orig, "sqlstate", None) == CHECK_VIOLATION


def test_short_digest_is_refused(
    tenant_engines: TenantEngines, record_factories: dict[str, RecordFactory]
) -> None:
    """ES-003 fixes SHA-256. A 16-byte digest in the column is a weaker
    algorithm smuggled past a schema that only said `bytea`."""
    row = dict(record_factories[TENANT_A].next_record())
    row["record_digest"] = row["record_digest"][:16]
    with pytest.raises(IntegrityError) as caught:
        with tenant_connection(tenant_engines, TENANT_A) as conn:
            conn.execute(evidence_partition(TENANT_A).insert(), row)
    assert getattr(caught.value.orig, "sqlstate", None) == CHECK_VIOLATION


def test_unreceipted_record_is_refused(
    tenant_engines: TenantEngines, record_factories: dict[str, RecordFactory]
) -> None:
    """DM-024: record and issuer receipt are one append, never two phases."""
    row = dict(record_factories[TENANT_A].next_record())
    for field in ("receipt_key_id", "receipt_signature", "receipt_canonical_bytes"):
        row.pop(field)
    with pytest.raises(IntegrityError) as caught:
        with tenant_connection(tenant_engines, TENANT_A) as conn:
            conn.execute(evidence_partition(TENANT_A).insert(), row)
    assert getattr(caught.value.orig, "sqlstate", None) == "23502"


def test_non_ed25519_length_receipt_signature_is_refused(
    tenant_engines: TenantEngines, record_factories: dict[str, RecordFactory]
) -> None:
    row = dict(record_factories[TENANT_A].next_record())
    row["receipt_signature"] = b"short"
    with pytest.raises(IntegrityError) as caught:
        with tenant_connection(tenant_engines, TENANT_A) as conn:
            conn.execute(evidence_partition(TENANT_A).insert(), row)
    assert getattr(caught.value.orig, "sqlstate", None) == CHECK_VIOLATION


def test_evidence_record_cannot_reference_an_issuer_namespace_key(
    tenant_engines: TenantEngines, record_factories: dict[str, RecordFactory]
) -> None:
    """SE-003: the customer-proof FK includes namespace = evidence."""
    factory = record_factories[TENANT_A]
    row = dict(factory.next_record())
    row["key_id"] = factory.receipt_key_id

    with pytest.raises(IntegrityError) as caught:
        with tenant_connection(tenant_engines, TENANT_A) as conn:
            conn.execute(evidence_partition(TENANT_A).insert(), row)
    assert getattr(caught.value.orig, "sqlstate", None) == "23503"


def test_ingestion_receipt_cannot_reference_an_evidence_namespace_key(
    tenant_engines: TenantEngines, record_factories: dict[str, RecordFactory]
) -> None:
    """SE-003: the hosted-receipt FK includes namespace = issuer."""
    factory = record_factories[TENANT_A]
    row = dict(factory.next_record())
    row["receipt_key_id"] = factory.key_id

    with pytest.raises(IntegrityError) as caught:
        with tenant_connection(tenant_engines, TENANT_A) as conn:
            conn.execute(evidence_partition(TENANT_A).insert(), row)
    assert getattr(caught.value.orig, "sqlstate", None) == "23503"


def test_receipt_migration_refuses_to_fabricate_history(
    owner_engine: Engine,
    populated_ledger: dict[str, list[dict[str, Any]]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration = importlib.import_module("migrations.versions.0010_ingestion_receipts")
    with owner_engine.connect() as conn:
        monkeypatch.setattr(migration.op, "get_bind", lambda: conn)
        with pytest.raises(RuntimeError, match="refuses a non-empty ledger"):
            migration.upgrade()


def test_record_citing_another_tenants_collector_is_refused(
    tenant_engines: TenantEngines, record_factories: dict[str, RecordFactory]
) -> None:
    """The collector FK is composite on (tenant_id, collector_id).

    A record that names another tenant's collector would attribute evidence
    to a collection source outside its own boundary.
    """
    from tests.ledger_support import TENANT_B

    row = dict(record_factories[TENANT_A].next_record())
    row["collector_id"] = record_factories[TENANT_B].collector_id
    with pytest.raises(IntegrityError) as caught:
        with tenant_connection(tenant_engines, TENANT_A) as conn:
            conn.execute(evidence_partition(TENANT_A).insert(), row)
    assert getattr(caught.value.orig, "sqlstate", None) == "23503"


def test_key_continuity_must_be_recorded_in_full(owner_engine: Engine) -> None:
    """SE-008/ES-024: a predecessor without a continuity signature is a
    rotation with no proof, which is a chain break rather than a rotation."""
    with pytest.raises(IntegrityError) as caught:
        with owner_engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO keys (key_id, tenant_id, namespace, public_key,"
                    " custody, valid_from, predecessor_key_id)"
                    " VALUES ('acme-evidence-2', :tid, 'evidence', '\\x00'::bytea,"
                    " 'client_held', now(), :pred)"
                ),
                {"tid": TENANT_A, "pred": "acme-evidence-1"},
            )
    assert "ck_keys_continuity_paired" in str(caught.value.orig)


def test_tenant_id_outside_the_identifier_alphabet_is_refused(
    owner_engine: Engine,
) -> None:
    """The tenant id reaches a SQL identifier. The database enforces the same
    rule `validate_tenant_id` does, so neither can be bypassed alone."""
    with pytest.raises(IntegrityError) as caught:
        with owner_engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO tenants (tenant_id, name, deployment_profile,"
                    " key_custody, evidence_region, created_at)"
                    " VALUES ('Acme-Corp\"; DROP TABLE evidence_records; --', 'x',"
                    " 'p1_hosted', 'client_held', 'eu-west-1', now())"
                )
            )
    assert "ck_tenants_tenant_id_identifier" in str(caught.value.orig)


def test_tenant_id_long_enough_to_truncate_an_identifier_is_refused(
    owner_engine: Engine,
) -> None:
    """Postgres truncates identifiers over 63 bytes silently rather than
    erroring, so the length bound is an isolation boundary (SE-011).

    Regression: the bound was 48, which made 'evidence_records_' + tenant_id
    65 bytes and 'evidence_tenant_' + tenant_id 64. Two tenant ids agreeing
    on their first 47 characters therefore truncated to one partition and one
    role, and one tenant's session could read the other's evidence.
    """
    with pytest.raises(IntegrityError) as caught:
        with owner_engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO tenants (tenant_id, name, deployment_profile,"
                    " key_custody, evidence_region, created_at)"
                    " VALUES (:tenant_id, 'x', 'p1_hosted', 'client_held',"
                    " 'eu-west-1', now())"
                ),
                {"tenant_id": "a" * (MAX_TENANT_ID_LENGTH + 1)},
            )
    assert "ck_tenants_tenant_id_identifier" in str(caught.value.orig)


def test_two_tenants_sharing_a_long_prefix_cannot_be_provisioned_onto_one_role(
    owner_engine: Engine,
) -> None:
    """The end-to-end form of the same defect.

    Provisioning must refuse before it creates anything, rather than letting
    the second tenant silently adopt the first tenant's role and partition.
    """
    first = "a" * (MAX_TENANT_ID_LENGTH - 1) + "b"
    second = "a" * (MAX_TENANT_ID_LENGTH - 1) + "c"
    assert first != second
    # Identical once Postgres truncates -- the collision the bound prevents.
    over_long = f"{first}{'z' * 8}", f"{second}{'z' * 8}"

    for tenant_id in over_long:
        with pytest.raises(ValueError, match="invalid tenant_id"):
            with owner_engine.begin() as conn:
                provision_tenant(
                    conn,
                    tenant_id=tenant_id,
                    name="x",
                    deployment_profile="p1_hosted",
                    key_custody="client_held",
                    evidence_region="eu-west-1",
                )

    with owner_engine.connect() as conn:
        leaked = conn.execute(
            text(
                "SELECT rolname FROM pg_roles WHERE rolname LIKE :pattern"
                " UNION ALL"
                " SELECT relname FROM pg_class WHERE relname LIKE :pattern"
            ),
            {"pattern": f"%{'a' * 20}%"},
        ).all()
    assert leaked == [], f"a refused tenant left objects behind: {leaked}"


def test_runtime_schema_matches_the_migrated_database(
    owner_engine: Engine, tenants: list[str]
) -> None:
    """`schema.py` describes what the migrations built.

    The migrations are frozen snapshots and the runtime `Table` objects are
    written separately, so nothing but this test stops them drifting -- and
    a drifted projection column list would make `rebuild_projection` silently
    incomplete.
    """
    declared = {column.name for column in evidence_partition(TENANT_A).columns}
    with owner_engine.connect() as conn:
        actual = {
            row.column_name
            for row in conn.execute(
                text(
                    "SELECT column_name FROM information_schema.columns"
                    " WHERE table_name = :table"
                ),
                {"table": EVIDENCE_PARENT_TABLE},
            )
        }
    assert declared == actual, (
        f"schema.py declares {sorted(declared - actual)} the database lacks; "
        f"database has {sorted(actual - declared)} schema.py omits"
    )


def test_partition_is_attached_to_the_parent(
    owner_engine: Engine, tenants: list[str]
) -> None:
    """A partition detached from the parent still holds evidence, but no
    longer inherits the parent's constraints."""
    with owner_engine.connect() as conn:
        attached = {
            row.relname
            for row in conn.execute(
                text(
                    "SELECT c.relname FROM pg_class c"
                    " JOIN pg_inherits i ON i.inhrelid = c.oid"
                    " JOIN pg_class p ON p.oid = i.inhparent"
                    " WHERE p.relname = :parent"
                ),
                {"parent": EVIDENCE_PARENT_TABLE},
            )
        }
    assert attached == {f"{EVIDENCE_PARENT_TABLE}_{t}" for t in tenants}


def test_parent_table_grants_nothing_to_anyone(owner_engine: Engine) -> None:
    """The one grant that would undo the whole design.

    A SELECT on the parent is a cross-tenant read with no further steps
    required (SE-011).
    """
    with owner_engine.connect() as conn:
        grants = conn.execute(
            text(
                "SELECT grantee, privilege_type"
                " FROM information_schema.table_privileges"
                " WHERE table_name = :parent AND grantee <> (SELECT current_user)"
            ),
            {"parent": EVIDENCE_PARENT_TABLE},
        ).all()
    assert grants == [], (
        "privileges granted on the parent evidence table: "
        + ", ".join(f"{g.grantee}:{g.privilege_type}" for g in grants)
    )
    assert APP_GRANTS == ("INSERT", "SELECT")


def test_verify_projection_detects_a_tampered_projection(
    owner_engine: Engine, populated_ledger: dict[str, list[dict[str, Any]]]
) -> None:
    """The projection is a cache, so a wrong value is not caught by any
    constraint. `verify_projection` is what notices, and it must.

    Written as the withholding case first: if this returned an empty list on
    tampered data, the rebuild path would look healthy while serving values
    the canonical bytes never contained.
    """
    with owner_engine.connect() as conn:
        assert verify_projection(conn) == [], "clean ledger reported mismatches"

    with owner_engine.begin() as conn:
        conn.execute(
            text(
                f'UPDATE "{EVIDENCE_PARENT_TABLE}"'  # noqa: S608
                " SET action_family = 'not.what.was.signed'"
                " WHERE tenant_id = :tid"
            ),
            {"tid": TENANT_A},
        )
    try:
        with owner_engine.connect() as conn:
            mismatches = verify_projection(conn)
        assert mismatches, "a rewritten projection column went unreported"
        assert {m.column for m in mismatches} == {"action_family"}
        assert all(m.derived != "not.what.was.signed" for m in mismatches)
    finally:
        with owner_engine.begin() as conn:
            from services.ledger import rebuild_projection

            rebuild_projection(conn)

    with owner_engine.connect() as conn:
        assert verify_projection(conn) == []
