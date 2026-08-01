"""AC-S-006 -- Projection rebuildable from canonical bytes (AC-015, DM-005).

`canonical_bytes` is authoritative. `body`, `action_id` and `action_family`
are a cache. The test physically DROPs those columns and rebuilds them from
the canonical bytes alone, then requires byte-identical reproduction and
unbroken signatures.

The rebuild runs under the migrator role, not the application role: writing
a projection requires UPDATE, which SE-012 forbids any application role from
holding. Projection maintenance is therefore a separately-credentialed
operation, and that is the design, not a workaround.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pytest_bdd import given, scenario, then, when
from sqlalchemy import Engine, text

from services.ledger import (
    EVIDENCE_PARENT_TABLE,
    PROJECTION_COLUMNS,
    drop_projection,
    projection_columns_present,
    rebuild_projection,
)


@scenario("architecture.feature", "AC-S-006 Projection rebuildable from canonical bytes")
def test_ac_s_006() -> None:
    """Bound by pytest-bdd."""


def _snapshot(engine: Engine) -> dict[tuple[str, str], dict[str, Any]]:
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT tenant_id, record_id, record_digest, canonical_bytes,"  # noqa: S608
                " signature, key_id, body, action_id, action_family"
                f' FROM "{EVIDENCE_PARENT_TABLE}" ORDER BY tenant_id, stream_id, sequence'
            )
        ).mappings().all()
    return {(r["tenant_id"], str(r["record_id"])): dict(r) for r in rows}


@given("a populated evidence ledger", target_fixture="ledger_before")
def _ledger_before(
    owner_engine: Engine,
    populated_ledger: dict[str, list[dict[str, Any]]],
) -> dict[tuple[str, str], dict[str, Any]]:
    snapshot = _snapshot(owner_engine)
    assert len(snapshot) == sum(len(v) for v in populated_ledger.values())
    assert snapshot, "an empty ledger would make this scenario vacuous"
    # The projection must actually be populated beforehand, or "reproduces
    # identically" would be satisfied by null equals null.
    assert any(row["body"] for row in snapshot.values())
    assert any(row["action_id"] for row in snapshot.values())
    return snapshot


@when("the parsed projection is dropped and rebuilt", target_fixture="rebuild_evidence")
def _drop_and_rebuild(owner_engine: Engine) -> dict[str, Any]:
    with owner_engine.begin() as conn:
        drop_projection(conn)
    with owner_engine.connect() as conn:
        remaining = projection_columns_present(conn)
    assert remaining == set(), (
        f"projection columns survived the drop: {sorted(remaining)} -- "
        "the columns must really be gone, not merely nulled"
    )
    with owner_engine.begin() as conn:
        rebuilt = rebuild_projection(conn)
    with owner_engine.connect() as conn:
        restored = projection_columns_present(conn)
    assert restored == set(PROJECTION_COLUMNS)
    return {"rows_rebuilt": rebuilt, "after": _snapshot(owner_engine)}


@then("every record reproduces identically")
def _reproduces_identically(
    ledger_before: dict[tuple[str, str], dict[str, Any]],
    rebuild_evidence: dict[str, Any],
) -> None:
    after: dict[tuple[str, str], dict[str, Any]] = rebuild_evidence["after"]
    assert set(after) == set(ledger_before), "record set changed across the rebuild"
    assert rebuild_evidence["rows_rebuilt"] == len(ledger_before)
    for key, before in ledger_before.items():
        now = after[key]
        for column in PROJECTION_COLUMNS:
            assert now[column] == before[column], (
                f"projection column {column} differs for {key}: "
                f"{before[column]!r} -> {now[column]!r}"
            )
        # The authoritative bytes must not have been touched by the rebuild.
        assert now["canonical_bytes"] == before["canonical_bytes"], (
            "the rebuild rewrote canonical_bytes -- DM-005 forbids it"
        )
        assert now["record_digest"] == before["record_digest"]
        assert now["signature"] == before["signature"]


@then("all digests and signatures still verify")
def _digests_and_signatures_verify(
    owner_engine: Engine, rebuild_evidence: dict[str, Any]
) -> None:
    with owner_engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT e.tenant_id, e.record_id, e.canonical_bytes, e.record_digest,"  # noqa: S608
                " e.signature, k.public_key, e.body"
                f' FROM "{EVIDENCE_PARENT_TABLE}" e'
                " JOIN keys k ON k.key_id = e.key_id AND k.tenant_id = e.tenant_id"
            )
        ).mappings().all()
    assert rows, "no records to verify"
    for row in rows:
        canonical = bytes(row["canonical_bytes"])
        assert hashlib.sha256(canonical).digest() == bytes(row["record_digest"]), (
            f"record_digest no longer matches canonical_bytes for {row['record_id']}"
        )
        public_key = Ed25519PublicKey.from_public_bytes(bytes(row["public_key"]))
        try:
            public_key.verify(bytes(row["signature"]), canonical)
        except InvalidSignature:  # pragma: no cover -- failure path
            raise AssertionError(
                f"signature no longer verifies for {row['record_id']}"
            ) from None
        # And the rebuilt projection is genuinely derived from those bytes.
        assert row["body"] == json.loads(canonical)["body"]


# --- Beyond the scenario ----------------------------------------------------


def test_rebuild_is_idempotent(
    owner_engine: Engine, populated_ledger: dict[str, list[dict[str, Any]]]
) -> None:
    """Rebuilding twice must not drift (DM-011's rule, applied to projections)."""
    first = _snapshot(owner_engine)
    with owner_engine.begin() as conn:
        drop_projection(conn)
        rebuild_projection(conn)
    second = _snapshot(owner_engine)
    with owner_engine.begin() as conn:
        drop_projection(conn)
        rebuild_projection(conn)
    third = _snapshot(owner_engine)
    assert first == second == third


def test_projection_indexes_return_after_rebuild(
    owner_engine: Engine, populated_ledger: dict[str, list[dict[str, Any]]]
) -> None:
    """Dropping a projection column drops its indexes; the rebuild must restore them.

    A rebuild that silently leaves the ledger without the (tenant_id, action_id)
    index is a rebuild that quietly changes query behaviour.
    """
    def index_names() -> set[str]:
        with owner_engine.connect() as conn:
            return {
                r.indexname
                for r in conn.execute(
                    text(
                        "SELECT indexname FROM pg_indexes"
                        " WHERE tablename = :parent"
                    ),
                    {"parent": EVIDENCE_PARENT_TABLE},
                )
            }

    before = index_names()
    assert {
        "ix_evidence_records_tenant_action",
        "ix_evidence_records_tenant_family_time",
    } <= before, f"projection indexes missing before the rebuild: {sorted(before)}"
    with owner_engine.begin() as conn:
        drop_projection(conn)
        rebuild_projection(conn)
    assert index_names() == before


def test_projection_rebuild_needs_no_application_privileges(
    application_engine: Engine, populated_ledger: dict[str, list[dict[str, Any]]]
) -> None:
    """The application role must not be able to run the rebuild path.

    If it could, it would hold UPDATE, and AC-S-004 would be a fiction.
    """
    from sqlalchemy.exc import ProgrammingError

    from services.ledger import partition_name, tenant_connection
    from tests.ledger_support import TENANT_A

    try:
        with tenant_connection(application_engine, TENANT_A) as conn:
            conn.execute(
                text(
                    f'UPDATE "{partition_name(TENANT_A)}"'  # noqa: S608
                    " SET body = canonical_bytes::text::jsonb"
                )
            )
    except ProgrammingError as exc:
        assert getattr(exc.orig, "sqlstate", None) == "42501"
    else:  # pragma: no cover -- failure path
        raise AssertionError("the application role rebuilt the projection")
