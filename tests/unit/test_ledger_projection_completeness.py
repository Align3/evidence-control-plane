"""DM-005: every column either signed byte string determines is checked.

Review found `verify_projection` checking eight of sixteen derived columns.
A transactional edit to `source_time`, leaving `canonical_bytes` untouched,
was neither detected nor undone by a drop-and-rebuild -- the stored value
and the authoritative bytes disagreed and the ledger said nothing. The
tampered column was one nobody had thought to list, which is the whole
difficulty: the defect is in the *absence* of a check, so no existing test
covers it and no failure points at it.

Receipt-derived columns are subject to the same rule against the independent
`receipt_canonical_bytes` authority. These tests are therefore written against
the column list rather than
against a chosen example. Every column in `CANONICAL_DERIVED_COLUMNS` is
tampered with in turn and must be reported, so adding a derived column to
the schema without adding it to the projection maps fails here.
"""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import Engine, text

from services.ledger import (
    CANONICAL_DERIVED_COLUMNS,
    PROJECTION_COLUMNS,
    RECEIPT_DERIVED_COLUMNS,
    REPAIRABLE_DERIVED_COLUMNS,
    VERIFIED_HEADER_COLUMNS,
    drop_projection,
    rebuild_projection,
    verify_projection,
)
from services.ledger.projection import (
    _HEADER_SQL,
    _PROJECTION_SQL,
    _RECEIPT_SQL,
    _REPAIRABLE_SQL,
)

#: How to make each column disagree with the canonical bytes.
#:
#: Most are edited in place. `tenant_id` and `collector_id` cannot be: the
#: first is the partition key, so changing it relocates the row rather than
#: leaving a mismatch, and the second is a composite foreign key to
#: `collectors`. For those two the *bytes* are edited instead, which moves
#: the derived value while the stored one stays valid -- the same divergence
#: approached from the other side.
_TAMPER: dict[str, str] = {
    "record_id": "record_id = gen_random_uuid()",
    "record_type": "record_type = record_type || 'X'",
    "schema_version": "schema_version = schema_version || 'X'",
    "boundary_ref": "boundary_ref = boundary_ref || 'X'",
    "stream_id": "stream_id = stream_id || 'X'",
    "sequence": "sequence = sequence + 1000",
    "prev_digest": "prev_digest = decode(repeat('cd', 32), 'hex')",
    "record_digest": "record_digest = decode(repeat('ab', 32), 'hex')",
    "source_time": "source_time = source_time + interval '1 day'",
    "authoritative_time": "authoritative_time = now()",
    "ingest_time": "ingest_time = ingest_time + interval '1 day'",
    "clock_skew_ms": "clock_skew_ms = clock_skew_ms + 1",
    "body": "body = body || '{\"tampered\": true}'::jsonb",
    "action_id": "action_id = gen_random_uuid()",
    "action_family": "action_family = coalesce(action_family, '') || 'X'",
    "tenant_id": (
        "canonical_bytes = convert_to("
        "  replace(convert_from(canonical_bytes, 'UTF8'),"
        "          '\"tenant_id\":\"', '\"tenant_id\":\"x'), 'UTF8')"
    ),
    "collector_id": (
        "canonical_bytes = convert_to("
        "  replace(convert_from(canonical_bytes, 'UTF8'),"
        "          '\"collector_id\":\"', '\"collector_id\":\"x'), 'UTF8')"
    ),
}


def test_the_projection_maps_cover_exactly_the_derived_columns() -> None:
    """A derived column missing from the maps is a hole, not an omission.

    Stated as an equality in both directions: a column in the maps that is
    not declared derived is just as wrong, because it would be rebuilt from
    bytes that do not determine it.
    """
    mapped = (
        set(_PROJECTION_SQL)
        | set(_REPAIRABLE_SQL)
        | set(_RECEIPT_SQL)
        | set(_HEADER_SQL)
    )
    assert mapped == set(CANONICAL_DERIVED_COLUMNS)
    assert set(PROJECTION_COLUMNS) == set(_PROJECTION_SQL)
    assert set(REPAIRABLE_DERIVED_COLUMNS) == set(_REPAIRABLE_SQL)
    assert set(RECEIPT_DERIVED_COLUMNS) == set(_RECEIPT_SQL)
    assert set(VERIFIED_HEADER_COLUMNS) == set(_HEADER_SQL)


def test_every_derived_column_has_a_tamper_case() -> None:
    """Keeps the table below honest as the schema grows."""
    assert set(_TAMPER) == set(CANONICAL_DERIVED_COLUMNS)


def test_signature_and_authoritative_bytes_are_not_claimed_as_derived() -> None:
    """Proofs and the signed bytes themselves are authorities, not projections."""
    for column in (
        "key_id",
        "signature",
        "canonical_bytes",
        "receipt_key_id",
        "receipt_signature",
        "receipt_canonical_bytes",
    ):
        assert column not in CANONICAL_DERIVED_COLUMNS


@pytest.mark.parametrize("column", sorted(_TAMPER))
def test_tampering_a_derived_column_is_detected(
    owner_engine: Engine,
    populated_ledger: dict[str, list[dict[str, Any]]],
    column: str,
) -> None:
    """Each derived column, disagreeing with the bytes, must be reported."""
    with owner_engine.connect() as conn:
        transaction = conn.begin()
        try:
            assert verify_projection(conn) == [], "ledger dirty before the probe"
            target = conn.execute(
                text(
                    "SELECT tenant_id, record_id FROM evidence_records"
                    " ORDER BY tenant_id, record_id LIMIT 1"
                )
            ).mappings().one()
            conn.execute(
                text(
                    f"UPDATE evidence_records SET {_TAMPER[column]}"  # noqa: S608 -- tamper clause is a module constant
                    " WHERE tenant_id = :tenant_id AND record_id = :record_id"
                ),
                dict(target),
            )
            reported = {m.column for m in verify_projection(conn)}
            assert column in reported, (
                f"{column} was tampered with and verify_projection reported "
                f"{sorted(reported) or 'nothing'} -- the ledger's columns and "
                "its authoritative bytes can disagree undetected"
            )
        finally:
            transaction.rollback()


#: Setup needed before a repair case, where the plain tamper would make the
#: canonical value itself unwritable. `collector_id` is a composite foreign
#: key, so repairing it requires a *valid* wrong value to repair away from.
_REPAIR_SETUP: dict[str, str] = {
    "collector_id": (
        "INSERT INTO collectors (collector_id, tenant_id, implementation,"
        " version, mode, registered_at)"
        " VALUES ('decoy-collector', :tenant_id, 'x', '1', 'checkpoint', now())"
        " ON CONFLICT DO NOTHING"
    ),
}

#: In-place tampers for the repair pass; falls back to `_TAMPER`.
_REPAIR_TAMPER: dict[str, str] = {
    "collector_id": "collector_id = 'decoy-collector'",
}


@pytest.mark.parametrize(
    "column", sorted((*REPAIRABLE_DERIVED_COLUMNS, *RECEIPT_DERIVED_COLUMNS))
)
def test_rebuild_repairs_every_repairable_column(
    owner_engine: Engine,
    populated_ledger: dict[str, list[dict[str, Any]]],
    column: str,
) -> None:
    """Detection is not enough for the columns AC-015 says are a cache."""
    with owner_engine.connect() as conn:
        transaction = conn.begin()
        try:
            target = conn.execute(
                text(
                    "SELECT tenant_id, record_id FROM evidence_records"
                    " ORDER BY tenant_id, record_id LIMIT 1"
                )
            ).mappings().one()
            if column in _REPAIR_SETUP:
                conn.execute(text(_REPAIR_SETUP[column]), dict(target))
            conn.execute(
                text(
                    f"UPDATE evidence_records SET {_REPAIR_TAMPER.get(column, _TAMPER[column])}"  # noqa: S608 -- tamper clause is a module constant
                    " WHERE tenant_id = :tenant_id AND record_id = :record_id"
                ),
                dict(target),
            )
            assert verify_projection(conn) != []

            drop_projection(conn)
            rebuild_projection(conn)

            assert verify_projection(conn) == [], (
                f"{column} survived a drop and rebuild still disagreeing with "
                "the canonical bytes"
            )
        finally:
            transaction.rollback()


def test_rebuild_refuses_rather_than_writing_a_value_the_schema_rejects(
    owner_engine: Engine,
    populated_ledger: dict[str, list[dict[str, Any]]],
) -> None:
    """If the bytes themselves are wrong, the rebuild must fail loudly.

    Canonical bytes naming a collector that does not exist cannot be
    projected without violating the composite foreign key. The rebuild has
    to raise rather than skip the row, leave the stale value in place, or
    drop the constraint to make room: any of those would turn corrupted
    bytes into a ledger that looks consistent.
    """
    from sqlalchemy.exc import IntegrityError

    with owner_engine.connect() as conn:
        transaction = conn.begin()
        try:
            target = conn.execute(
                text(
                    "SELECT tenant_id, record_id FROM evidence_records"
                    " ORDER BY tenant_id, record_id LIMIT 1"
                )
            ).mappings().one()
            conn.execute(
                text(
                    f"UPDATE evidence_records SET {_TAMPER['collector_id']}"  # noqa: S608 -- tamper clause is a module constant
                    " WHERE tenant_id = :tenant_id AND record_id = :record_id"
                ),
                dict(target),
            )
            drop_projection(conn)
            with pytest.raises(IntegrityError) as caught:
                rebuild_projection(conn)
            assert "fk_evidence_records_collector" in str(caught.value.orig)
        finally:
            transaction.rollback()
