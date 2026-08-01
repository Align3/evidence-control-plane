"""Dropping and rebuilding the parsed projection (AC-015, DM-005, DM-013).

`canonical_bytes` is authoritative. Every other column the bytes determine
is a cache over them, and DM-005 requires *every* such column to be
reproducible -- not merely the three that happen to be droppable. The claim
AC-S-006 makes is falsifiable only if the rebuild path actually exists and
is exercised, so it is built here and now rather than assumed to be
possible later.

The columns split three ways, and the split is the design:

* **droppable** (`PROJECTION_COLUMNS`) -- dropped and rebuilt outright;
* **repairable** (`REPAIRABLE_DERIVED_COLUMNS`) -- recomputed in place,
  because no identity or uniqueness guarantee hangs off them;
* **verified only** (`VERIFIED_HEADER_COLUMNS`) -- checked but never
  rewritten. Rewriting the partition key would move rows between
  partitions, and rewriting `(stream_id, sequence)` could silently resolve
  a fork that ES-006 says must be reported rather than resolved.

Review found the earlier version verifying five header columns and
rebuilding three projection columns, which left `source_time` and its
neighbours derived-but-unchecked: a transactional edit to `source_time`
with `canonical_bytes` untouched went undetected and survived a rebuild.
Anything the bytes determine is now in one of the three groups, and a test
asserts the groups cover exactly `CANONICAL_DERIVED_COLUMNS`.

Two properties this module is responsible for:

* the rebuild reads **only** `canonical_bytes` -- if it consulted the columns
  it is rebuilding, the test would pass for the wrong reason;
* the rebuild never writes `canonical_bytes` or `signature`.

It requires `UPDATE`/DDL and therefore runs under the migrator credential.
No application role can reach it, which is the point: if the rebuild were
reachable from the ingestion role, that role would hold `UPDATE` and
AC-S-004 would be false.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import Connection, text

from .naming import EVIDENCE_PARENT_TABLE
from .schema import (
    CANONICAL_DERIVED_COLUMNS,
    PROJECTION_COLUMNS,
    REPAIRABLE_DERIVED_COLUMNS,
    VERIFIED_HEADER_COLUMNS,
)

#: The record as JSON, decoded from the authoritative bytes. Every derived
#: expression below starts here and nowhere else.
_PARSED = f'convert_from({EVIDENCE_PARENT_TABLE}.canonical_bytes, \'UTF8\')::jsonb'

#: SQL expression per droppable projection column, in terms of `_PARSED`.
_PROJECTION_SQL: dict[str, str] = {
    "body": f"({_PARSED}) -> 'body'",
    "action_id": f"nullif(({_PARSED}) -> 'body' ->> 'action_id', '')::uuid",
    "action_family": f"({_PARSED}) -> 'body' ->> 'action_family'",
}

#: Derived columns that are safe to recompute in place: no identity, no
#: partition key, no uniqueness constraint hangs off any of them.
#:
#: `record_digest` is derived from the bytes themselves rather than from
#: their contents, which makes it the check that notices `canonical_bytes`
#: and the stored digest disagreeing at all. It does not establish that the
#: bytes are the ones the customer signed -- only the signature does that,
#: and verifying it is EV-03's job, not the ledger's.
_REPAIRABLE_SQL: dict[str, str] = {
    "prev_digest": (
        f"CASE WHEN (({_PARSED}) ->> 'prev_digest') IS NULL THEN NULL"
        f" ELSE decode(substring(({_PARSED}) ->> 'prev_digest' from 8), 'hex')"
        f" END"
    ),
    "record_digest": f"sha256({EVIDENCE_PARENT_TABLE}.canonical_bytes)",
    "collector_id": f"({_PARSED}) -> 'source' ->> 'collector_id'",
    "source_time": f"(({_PARSED}) -> 'clocks' ->> 'source_time')::timestamptz",
    "authoritative_time": (
        f"(({_PARSED}) -> 'clocks' ->> 'authoritative_time')::timestamptz"
    ),
    "clock_skew_ms": f"(({_PARSED}) -> 'clocks' ->> 'clock_skew_ms')::integer",
}

#: Header columns are not dropped and not rewritten -- the partition key,
#: the record identity and the fork-detection unique constraint (ES-006)
#: hang off them -- but they are still parsed, so DM-005 applies and
#: `verify_projection` checks them.
_HEADER_SQL: dict[str, str] = {
    "record_id": f"(({_PARSED}) ->> 'record_id')::uuid",
    "tenant_id": f"({_PARSED}) ->> 'tenant_id'",
    "record_type": f"({_PARSED}) ->> 'record_type'",
    "schema_version": f"({_PARSED}) ->> 'schema_version'",
    "boundary_ref": f"({_PARSED}) ->> 'boundary_ref'",
    "stream_id": f"({_PARSED}) ->> 'stream_id'",
    "sequence": f"(({_PARSED}) ->> 'sequence')::bigint",
}

_COLUMN_TYPES: dict[str, str] = {
    "body": "jsonb",
    "action_id": "uuid",
    "action_family": "text",
}

#: Indexes over projection columns. Dropping a column drops its indexes, so
#: the rebuild has to put them back or it quietly changes query behaviour.
_PROJECTION_INDEXES: dict[str, str] = {
    "ix_evidence_records_tenant_action": "(tenant_id, action_id)",
    "ix_evidence_records_tenant_family_time": "(tenant_id, action_family, source_time)",
}


@dataclass(frozen=True)
class ProjectionMismatch:
    """A stored projection value that disagrees with the canonical bytes."""

    tenant_id: str
    record_id: str
    column: str
    stored: str | None
    derived: str | None


def projection_columns_present(connection: Connection) -> set[str]:
    """Which projection columns currently exist on the parent table."""
    rows = connection.execute(
        text(
            "SELECT column_name FROM information_schema.columns"
            " WHERE table_name = :table AND column_name = ANY(:columns)"
        ),
        {"table": EVIDENCE_PARENT_TABLE, "columns": list(PROJECTION_COLUMNS)},
    )
    return {row.column_name for row in rows}


def drop_projection(connection: Connection) -> None:
    """Physically drop the projection columns from every partition.

    Dropped, not nulled: a rebuild that only overwrites values could be
    reading the old ones. Dropping the column removes that possibility.
    """
    drops = ", ".join(f"DROP COLUMN IF EXISTS {column}" for column in PROJECTION_COLUMNS)
    connection.execute(text(f'ALTER TABLE "{EVIDENCE_PARENT_TABLE}" {drops}'))


def rebuild_projection(connection: Connection) -> int:
    """Recreate and repopulate the projection from `canonical_bytes`.

    Returns the number of records reprojected.
    """
    adds = ", ".join(
        f"ADD COLUMN IF NOT EXISTS {column} {_COLUMN_TYPES[column]}"
        for column in PROJECTION_COLUMNS
    )
    connection.execute(text(f'ALTER TABLE "{EVIDENCE_PARENT_TABLE}" {adds}'))

    assignments = ", ".join(
        f"{column} = {expression}"
        for column, expression in {**_PROJECTION_SQL, **_REPAIRABLE_SQL}.items()
    )
    result = connection.execute(
        text(f'UPDATE "{EVIDENCE_PARENT_TABLE}" SET {assignments}')  # noqa: S608 -- assignments built from module constants
    )

    # `body` is NOT NULL in the schema; restoring the constraint after the
    # backfill is what proves every record actually projected.
    connection.execute(
        text(f'ALTER TABLE "{EVIDENCE_PARENT_TABLE}" ALTER COLUMN body SET NOT NULL')
    )

    for index, columns in _PROJECTION_INDEXES.items():
        connection.execute(
            text(
                f'CREATE INDEX IF NOT EXISTS {index}'
                f' ON "{EVIDENCE_PARENT_TABLE}" {columns}'
            )
        )
    return result.rowcount


def verify_projection(connection: Connection) -> list[ProjectionMismatch]:
    """Report every stored value that the canonical bytes do not reproduce.

    Covers the header columns as well as the droppable projection: DM-005
    says *every* parsed column must be rebuildable, and the header columns
    are parsed even though the fork-detection constraint means they cannot
    be dropped.

    An empty list is the invariant. A non-empty list means the ledger's
    columns and its authoritative bytes disagree, which is a tampering or
    corruption signal, not a cache miss.
    """
    checks = {**_PROJECTION_SQL, **_REPAIRABLE_SQL, **_HEADER_SQL}
    present = projection_columns_present(connection)
    mismatches: list[ProjectionMismatch] = []
    for column, expression in checks.items():
        if column in PROJECTION_COLUMNS and column not in present:
            continue
        rows = connection.execute(
            text(
                # noqa on the first fragment: column and expression are keys
                # and values of module-level constants, never caller input.
                "SELECT tenant_id, record_id::text AS record_id,"  # noqa: S608
                f" {column}::text AS stored, ({expression})::text AS derived"
                f' FROM "{EVIDENCE_PARENT_TABLE}"'
                f" WHERE {column} IS DISTINCT FROM ({expression})"
            )
        )
        mismatches.extend(
            ProjectionMismatch(
                tenant_id=row.tenant_id,
                record_id=row.record_id,
                column=column,
                stored=row.stored,
                derived=row.derived,
            )
            for row in rows
        )
    return mismatches


__all__ = [
    "CANONICAL_DERIVED_COLUMNS",
    "PROJECTION_COLUMNS",
    "REPAIRABLE_DERIVED_COLUMNS",
    "VERIFIED_HEADER_COLUMNS",
    "ProjectionMismatch",
    "drop_projection",
    "projection_columns_present",
    "rebuild_projection",
    "verify_projection",
]
