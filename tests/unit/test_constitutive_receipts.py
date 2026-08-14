"""EV-31 fails closed when constitutive recording time is unattested."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from sqlalchemy import Engine, text

from sdk_python.evidence.canonical import canonicalize
from services.admin import boundary_versions, interval_coverage, record_qualification
from services.attestation import A02BoundaryInForce, assemble_attestation
from services.ingestion.receipts import KeyNamespaceError, ReceiptSignatureError
from tests.admin_support import (
    AdminActor,
    constitutive_receipt,
    qualification_body,
    signed_qualification,
)
from tests.attestation_support import attestation_request, boundary_version
from tests.coverage_support import at
from tests.ledger_support import CHECK_VIOLATION, TENANT_A


def test_unattested_stored_time_cannot_support_a02() -> None:
    request = attestation_request(
        version=boundary_version(recording_time_attested=False)
    )

    assembly = assemble_attestation(request)

    assert assembly.boundary_coverage.effective is None
    assert not any(
        isinstance(assertion, A02BoundaryInForce)
        for assertion in assembly.assertions
    )


def _qualification(
    actor: AdminActor, *, action_family: str
):
    observed_at = datetime(2026, 2, 1, tzinfo=UTC)
    record, signing_bytes, signature = signed_qualification(
        tenant_id=actor.tenant_id,
        collector_id=actor.collector_id,
        key_id=actor.key_id,
        private_key=actor.private_key,
        boundary_ref=f"{actor.tenant_id}:default:1",
        body=qualification_body(
            action_family=action_family,
            destination_system="payments-core",
            assigned_class="C4",
            qualified_at=datetime(2026, 1, 1, tzinfo=UTC),
        ),
        source_time=observed_at,
    )
    receipt = constitutive_receipt(
        record,
        issuer_key_id=actor.issuer_key_id,
        issuer_private_key=actor.issuer_private_key,
        recorded_at=observed_at,
    )
    return record, signing_bytes, signature, receipt


def test_receipt_time_is_the_only_recorded_time(
    owner_engine: Engine,
    admin_actors: dict[str, AdminActor],
    default_boundaries: dict[str, str],
) -> None:
    actor = admin_actors[TENANT_A]
    observed_at = datetime(2026, 2, 3, 4, 5, 6, 789000, tzinfo=UTC)
    with owner_engine.connect() as connection:
        transaction = connection.begin()
        try:
            ref = actor.write_qualification(
                connection,
                action_family="receipt.time",
                destination_system="payments-core",
                assigned_class="C4",
                qualified_at=datetime(2025, 1, 1, tzinfo=UTC),
                recorded_at=observed_at,
            )
            row = connection.execute(
                text(
                    "SELECT recorded_at, receipt_key_id, receipt_key_namespace,"
                    " receipt_canonical_bytes FROM qualification_records"
                    " WHERE qualification_ref = :ref"
                ),
                {"ref": ref},
            ).mappings().one()
            payload = json.loads(bytes(row["receipt_canonical_bytes"]))
            assert row["recorded_at"] == observed_at
            assert payload["ingest_time"] == "2026-02-03T04:05:06.789Z"
            assert row["receipt_key_id"] == actor.issuer_key_id
            assert row["receipt_key_namespace"] == "issuer"

            boundary_observed_at = datetime(
                2026, 2, 4, 5, 6, 7, 890000, tzinfo=UTC
            )
            boundary_ref = actor.write_boundary(
                connection,
                name="receipt-time",
                version=1,
                window_start=datetime(2026, 3, 1, tzinfo=UTC),
                window_end=datetime(2026, 4, 1, tzinfo=UTC),
                families=[
                    {
                        "action_family": "receipt.time",
                        "destination_system": "payments-core",
                        "qualification_ref": ref,
                    }
                ],
                recorded_at=boundary_observed_at,
            )
            boundary_row = connection.execute(
                text(
                    "SELECT recorded_at, receipt_key_id, receipt_key_namespace,"
                    " receipt_canonical_bytes FROM boundaries"
                    " WHERE boundary_ref = :ref"
                ),
                {"ref": boundary_ref},
            ).mappings().one()
            boundary_payload = json.loads(
                bytes(boundary_row["receipt_canonical_bytes"])
            )
            assert boundary_row["recorded_at"] == boundary_observed_at
            assert boundary_payload["ingest_time"] == "2026-02-04T05:06:07.890Z"
            assert boundary_row["receipt_key_id"] == actor.issuer_key_id
            assert boundary_row["receipt_key_namespace"] == "issuer"
            [loaded] = boundary_versions(
                connection, tenant_id=TENANT_A, name="receipt-time"
            )
            assert loaded.recording_time_attested
        finally:
            transaction.rollback()


def test_receipt_tampering_is_refused_before_insert(
    owner_engine: Engine,
    admin_actors: dict[str, AdminActor],
) -> None:
    actor = admin_actors[TENANT_A]
    record, signing_bytes, signature, receipt = _qualification(
        actor, action_family="receipt.tamper"
    )
    payload = receipt.payload.model_dump(mode="json")
    payload["clock_skew_ms"] += 1
    forged = replace(receipt, canonical_bytes=canonicalize(payload))

    with owner_engine.connect() as connection:
        transaction = connection.begin()
        try:
            with pytest.raises(ReceiptSignatureError, match="signature verification"):
                record_qualification(
                    connection,
                    record=record,
                    canonical_bytes=signing_bytes,
                    signature=signature,
                    receipt=forged,
                )
            assert connection.execute(
                text(
                    "SELECT count(*) FROM qualification_records"
                    " WHERE qualification_ref = :ref"
                ),
                {"ref": record.record_id},
            ).scalar_one() == 0
        finally:
            transaction.rollback()


def test_receipt_for_another_constitutive_record_is_refused(
    owner_engine: Engine,
    admin_actors: dict[str, AdminActor],
) -> None:
    actor = admin_actors[TENANT_A]
    record, signing_bytes, signature, _ = _qualification(
        actor, action_family="receipt.subject"
    )
    other, _, _, other_receipt = _qualification(
        actor, action_family="receipt.other"
    )
    assert other.record_id != record.record_id

    with owner_engine.connect() as connection:
        transaction = connection.begin()
        try:
            with pytest.raises(ReceiptSignatureError, match="different customer record"):
                record_qualification(
                    connection,
                    record=record,
                    canonical_bytes=signing_bytes,
                    signature=signature,
                    receipt=other_receipt,
                )
        finally:
            transaction.rollback()


def test_evidence_namespace_key_cannot_sign_constitutive_receipt(
    owner_engine: Engine,
    admin_actors: dict[str, AdminActor],
) -> None:
    actor = admin_actors[TENANT_A]
    record, signing_bytes, signature, _ = _qualification(
        actor, action_family="receipt.namespace"
    )
    wrong_role = constitutive_receipt(
        record,
        issuer_key_id=actor.key_id,
        issuer_private_key=actor.private_key,
        recorded_at=datetime(2026, 2, 1, tzinfo=UTC),
    )

    with owner_engine.connect() as connection:
        transaction = connection.begin()
        try:
            with pytest.raises(KeyNamespaceError, match="require an issuer key"):
                record_qualification(
                    connection,
                    record=record,
                    canonical_bytes=signing_bytes,
                    signature=signature,
                    receipt=wrong_role,
                )
        finally:
            transaction.rollback()


def test_new_database_rows_cannot_omit_receipts(
    owner_engine: Engine, default_boundaries: dict[str, str]
) -> None:
    with owner_engine.connect() as connection:
        transaction = connection.begin()
        try:
            source = connection.execute(
                text("SELECT * FROM boundaries WHERE tenant_id = :tenant LIMIT 1"),
                {"tenant": TENANT_A},
            ).mappings().one()
            with pytest.raises(Exception) as caught:  # noqa: B017 - SQLSTATE asserted
                connection.execute(
                    text(
                        "INSERT INTO boundaries (boundary_ref, tenant_id, name, version,"
                        " canonical_bytes, body, key_id, key_namespace, signature,"
                        " window_start, window_end, recorded_at) VALUES ("
                        " :tenant || chr(58) || 'missing-receipt' || chr(58) || '1',"
                        " :tenant, 'missing-receipt', 1,"
                        " :canonical, CAST(:body AS jsonb), :key, 'evidence', :signature,"
                        " :start, :end, :recorded)"
                    ),
                    {
                        "tenant": TENANT_A,
                        "canonical": source["canonical_bytes"],
                        "body": json.dumps(source["body"]),
                        "key": source["key_id"],
                        "signature": source["signature"],
                        "start": source["window_start"],
                        "end": source["window_end"],
                        "recorded": source["recorded_at"],
                    },
                )
            assert getattr(caught.value.orig, "sqlstate", None) == CHECK_VIOLATION
            assert "receipt_required" in str(caught.value)
        finally:
            transaction.rollback()


def test_legacy_receipt_absence_is_preserved_by_unvalidated_checks(
    owner_engine: Engine,
) -> None:
    with owner_engine.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT conname, convalidated FROM pg_constraint"
                " WHERE conname IN ('ck_boundaries_receipt_required',"
                " 'ck_qualification_records_receipt_required')"
            )
        ).all()
    assert {name for name, _ in rows} == {
        "ck_boundaries_receipt_required",
        "ck_qualification_records_receipt_required",
    }
    assert all(not validated for _, validated in rows)


def test_invalid_stored_receipt_cannot_make_recording_time_attested(
    owner_engine: Engine, default_boundaries: dict[str, str]
) -> None:
    source_ref = default_boundaries[TENANT_A]
    forged_ref = f"{TENANT_A}:invalid-receipt:1"
    with owner_engine.connect() as connection:
        transaction = connection.begin()
        try:
            source = connection.execute(
                text("SELECT * FROM boundaries WHERE boundary_ref = :ref"),
                {"ref": source_ref},
            ).mappings().one()
            family = connection.execute(
                text(
                    "SELECT * FROM boundary_action_families"
                    " WHERE boundary_ref = :ref"
                ),
                {"ref": source_ref},
            ).mappings().one()
            connection.execute(
                text(
                    "INSERT INTO boundaries (boundary_ref, tenant_id, name, version,"
                    " canonical_bytes, body, key_id, key_namespace, signature,"
                    " window_start, window_end, recorded_at, receipt_key_id,"
                    " receipt_key_namespace, receipt_signature,"
                    " receipt_canonical_bytes, received_wire_bytes) VALUES ("
                    " :ref, :tenant, 'invalid-receipt', 1, :canonical,"
                    " CAST(:body AS jsonb), :key, 'evidence', :signature,"
                    " :start, :end, :recorded, :receipt_key, 'issuer',"
                    " :receipt_signature, :receipt_bytes, :received_wire)"
                ),
                {
                    "ref": forged_ref,
                    "tenant": TENANT_A,
                    "canonical": source["canonical_bytes"],
                    "body": json.dumps(source["body"]),
                    "key": source["key_id"],
                    "signature": source["signature"],
                    "start": source["window_start"],
                    "end": source["window_end"],
                    "recorded": source["recorded_at"],
                    "receipt_key": source["receipt_key_id"],
                    "receipt_signature": b"\x00" * 64,
                    "receipt_bytes": source["receipt_canonical_bytes"],
                    "received_wire": source["received_wire_bytes"],
                },
            )
            connection.execute(
                text(
                    "INSERT INTO boundary_action_families"
                    " (tenant_id, boundary_ref, action_family, qualification_ref,"
                    " destination_system, fail_behaviour) VALUES"
                    " (:tenant, :ref, :family, :qualification, :destination, :failure)"
                ),
                {
                    "tenant": TENANT_A,
                    "ref": forged_ref,
                    "family": family["action_family"],
                    "qualification": family["qualification_ref"],
                    "destination": family["destination_system"],
                    "failure": family["fail_behaviour"],
                },
            )
            connection.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))

            [loaded] = boundary_versions(
                connection, tenant_id=TENANT_A, name="invalid-receipt"
            )
            assert not loaded.recording_time_attested
            result = interval_coverage(
                (loaded,),
                boundary_ref=forged_ref,
                window_start=at(9),
                window_end=at(10),
            )
            assert result.effective is None
            assert result.uncovered == ((at(9), at(10)),)
        finally:
            transaction.rollback()
