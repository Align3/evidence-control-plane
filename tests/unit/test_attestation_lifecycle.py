"""Negative-first EV-18 lifecycle and retention invariants."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import Engine, select, text
from sqlalchemy.exc import DBAPIError

from services.attestation import IssuerSigner
from services.attestation.lifecycle import (
    AttestationLifecycleError,
    LifecycleStatus,
    RevocationGround,
    attestation_status,
    record_attestation,
    revoke_attestation,
    supersede_attestation,
)
from services.attestation.schema import attestations, revocations
from services.ledger import (
    TenantEngines,
    deprovision_tenant,
    evidence_partition,
    tenant_connection,
)
from tests.ledger_support import TENANT_A, TENANT_B, RecordFactory
from tests.lifecycle_support import signed_attestation


def _attestation(
    factory: RecordFactory,
    boundary_ref: str,
    *,
    suffix: str,
    sequence: int,
    validity_from: datetime | None = None,
    validity_until: datetime | None = None,
) -> object:
    return signed_attestation(
        factory,
        record_id=f"01890f47-2f58-7cc0-98c4-000000000{suffix}",
        boundary_ref=boundary_ref,
        sequence=sequence,
        window_start=datetime(2026, 7, 31, 11, 0, tzinfo=UTC),
        window_end=datetime(2026, 7, 31, 13, 0, tzinfo=UTC),
        validity_from=validity_from,
        validity_until=validity_until,
    )


def test_expired_attestation_is_never_reported_valid(
    owner_engine: Engine,
    record_factories: dict[str, RecordFactory],
    default_boundaries: dict[str, str],
) -> None:
    now = datetime.now(UTC)
    record = _attestation(
        record_factories[TENANT_A],
        default_boundaries[TENANT_A],
        suffix="601",
        sequence=601,
        validity_from=now - timedelta(days=2),
        validity_until=now - timedelta(days=1),
    )
    with owner_engine.begin() as connection:
        record_attestation(connection, record)
        assert attestation_status(
            connection,
            tenant_id=TENANT_A,
            attestation_id=record.record_id,
            as_of=now,
        ) is LifecycleStatus.EXPIRED


def test_tampered_counter_signature_is_refused_before_storage(
    owner_engine: Engine,
    record_factories: dict[str, RecordFactory],
    default_boundaries: dict[str, str],
) -> None:
    record = _attestation(
        record_factories[TENANT_A],
        default_boundaries[TENANT_A],
        suffix="602",
        sequence=602,
    )
    signature = record.signature.copy()
    issuer = dict(signature["issuer"])
    issuer["sig"] = "A" * 86
    signature["issuer"] = issuer
    tampered = record.model_copy(update={"signature": signature})

    with owner_engine.begin() as connection:
        with pytest.raises(AttestationLifecycleError, match="signature"):
            record_attestation(connection, tampered)
        assert connection.execute(
            select(attestations.c.attestation_id).where(
                attestations.c.attestation_id == record.record_id
            )
        ).first() is None


def test_invalid_revocation_signer_cannot_notify_relying_parties(
    owner_engine: Engine,
    record_factories: dict[str, RecordFactory],
    default_boundaries: dict[str, str],
) -> None:
    factory = record_factories[TENANT_A]
    record = _attestation(
        factory, default_boundaries[TENANT_A], suffix="612", sequence=612
    )
    notified: list[str] = []
    with owner_engine.begin() as connection:
        record_attestation(connection, record)

    with pytest.raises(AttestationLifecycleError, match="revocation signature"):
        revoke_attestation(
            owner_engine,
            tenant_id=TENANT_A,
            attestation_id=record.record_id,
            ground=RevocationGround.CUSTOMER_MISREPRESENTATION,
            effective_at=datetime.now(UTC),
            signer=IssuerSigner(
                factory.receipt_key_id, Ed25519PrivateKey.generate()
            ),
            notify=lambda party: notified.append(str(party["name"])),
        )

    assert notified == []
    with owner_engine.connect() as connection:
        assert connection.execute(
            select(revocations.c.revocation_id).where(
                revocations.c.attestation_id == record.record_id
            )
        ).first() is None


def test_notification_runs_only_after_pending_transition_is_committed(
    owner_engine: Engine,
    record_factories: dict[str, RecordFactory],
    default_boundaries: dict[str, str],
) -> None:
    factory = record_factories[TENANT_A]
    record = _attestation(
        factory, default_boundaries[TENANT_A], suffix="613", sequence=613
    )
    with owner_engine.begin() as connection:
        record_attestation(connection, record)

    statuses_seen_by_notifier: list[list[str]] = []

    def notify(_party: object) -> None:
        with owner_engine.connect() as connection:
            statuses_seen_by_notifier.append(
                list(
                    connection.execute(
                        select(revocations.c.notification_status)
                        .where(revocations.c.attestation_id == record.record_id)
                        .order_by(revocations.c.sequence)
                    ).scalars()
                )
            )

    transition = revoke_attestation(
        owner_engine,
        tenant_id=TENANT_A,
        attestation_id=record.record_id,
        ground=RevocationGround.CUSTOMER_MISREPRESENTATION,
        effective_at=datetime.now(UTC),
        signer=IssuerSigner(factory.receipt_key_id, factory.receipt_private_key),
        notify=notify,
    )

    assert statuses_seen_by_notifier == [["pending"]]
    assert transition.record.body.relying_party_notification_status == "notified"
    with owner_engine.connect() as connection:
        assert list(
            connection.execute(
                select(revocations.c.notification_status)
                .where(revocations.c.attestation_id == record.record_id)
                .order_by(revocations.c.sequence)
            ).scalars()
        ) == ["pending", "notified"]


def test_supersession_preserves_original_and_notifies_named_parties(
    owner_engine: Engine,
    record_factories: dict[str, RecordFactory],
    default_boundaries: dict[str, str],
) -> None:
    factory = record_factories[TENANT_A]
    original = _attestation(
        factory, default_boundaries[TENANT_A], suffix="603", sequence=603
    )
    replacement = _attestation(
        factory, default_boundaries[TENANT_A], suffix="604", sequence=604
    )
    notified: list[str] = []

    with owner_engine.begin() as connection:
        record_attestation(connection, original)
        before = connection.execute(
            select(attestations.c.canonical_bytes).where(
                attestations.c.attestation_id == original.record_id
            )
        ).scalar_one()
    transition = supersede_attestation(
        owner_engine,
        tenant_id=TENANT_A,
        original_attestation_id=original.record_id,
        superseding_attestation=replacement,
        effective_at=datetime.now(UTC),
        signer=IssuerSigner(factory.receipt_key_id, factory.receipt_private_key),
        notify=lambda party: notified.append(str(party["name"])),
    )
    with owner_engine.connect() as connection:
        after = connection.execute(
            select(attestations.c.canonical_bytes).where(
                attestations.c.attestation_id == original.record_id
            )
        ).scalar_one()

        assert before == after
        assert transition.record.body.attestation_ref == original.record_id
        assert transition.record.body.superseding_ref == replacement.record_id
        assert transition.record.body.relying_party_notification_status == "notified"
        assert notified == ["buyer"]
        assert attestation_status(
            connection,
            tenant_id=TENANT_A,
            attestation_id=original.record_id,
            as_of=datetime.now(UTC),
        ) is LifecycleStatus.SUPERSEDED
        assert attestation_status(
            connection,
            tenant_id=TENANT_A,
            attestation_id=replacement.record_id,
            as_of=datetime.now(UTC),
        ) is LifecycleStatus.VALID


def test_cross_boundary_supersession_is_refused(
    owner_engine: Engine,
    record_factories: dict[str, RecordFactory],
    default_boundaries: dict[str, str],
) -> None:
    factory = record_factories[TENANT_A]
    original = _attestation(
        factory, default_boundaries[TENANT_A], suffix="605", sequence=605
    )
    replacement = _attestation(
        factory, "acme:other:1", suffix="606", sequence=606
    )
    with owner_engine.begin() as connection:
        record_attestation(connection, original)
    with pytest.raises(AttestationLifecycleError, match="same boundary"):
        supersede_attestation(
            owner_engine,
            tenant_id=TENANT_A,
            original_attestation_id=original.record_id,
            superseding_attestation=replacement,
            effective_at=datetime.now(UTC),
            signer=IssuerSigner(factory.receipt_key_id, factory.receipt_private_key),
        )


def test_future_revocation_does_not_retroactively_change_status(
    owner_engine: Engine,
    record_factories: dict[str, RecordFactory],
    default_boundaries: dict[str, str],
) -> None:
    factory = record_factories[TENANT_A]
    now = datetime.now(UTC)
    record = _attestation(
        factory, default_boundaries[TENANT_A], suffix="607", sequence=607
    )
    with owner_engine.begin() as connection:
        record_attestation(connection, record)
    revoke_attestation(
        owner_engine,
        tenant_id=TENANT_A,
        attestation_id=record.record_id,
        ground=RevocationGround.DISCOVERED_COMPUTATION_DEFECT,
        effective_at=now + timedelta(days=1),
        signer=IssuerSigner(factory.receipt_key_id, factory.receipt_private_key),
    )
    with owner_engine.connect() as connection:
        assert attestation_status(
            connection,
            tenant_id=TENANT_A,
            attestation_id=record.record_id,
            as_of=now,
        ) is LifecycleStatus.VALID
        assert attestation_status(
            connection,
            tenant_id=TENANT_A,
            attestation_id=record.record_id,
            as_of=now + timedelta(days=2),
        ) is LifecycleStatus.REVOKED


def test_database_blocks_deletion_until_covering_attestation_is_revoked(
    owner_engine: Engine,
    tenant_engines: TenantEngines,
    record_factories: dict[str, RecordFactory],
    default_boundaries: dict[str, str],
) -> None:
    factory = record_factories[TENANT_B]
    row = factory.next_record()
    partition = evidence_partition(TENANT_B)
    with tenant_connection(tenant_engines, TENANT_B) as connection:
        connection.execute(partition.insert(), row)

    attestation = _attestation(
        factory, default_boundaries[TENANT_B], suffix="608", sequence=608
    )
    with owner_engine.begin() as connection:
        record_attestation(connection, attestation)

    with pytest.raises(DBAPIError) as caught:
        with owner_engine.begin() as connection:
            connection.execute(
                text(
                    "DELETE FROM evidence_records "
                    "WHERE tenant_id = :tenant_id AND record_id = :record_id"
                ),
                    {"tenant_id": TENANT_B, "record_id": row["record_id"]},
            )
    assert "covering attestation must be revoked first" in str(caught.value.orig)

    revoke_attestation(
        owner_engine,
        tenant_id=TENANT_B,
        attestation_id=attestation.record_id,
        ground=RevocationGround.EVIDENCE_INTEGRITY_FAILURE,
        effective_at=datetime.now(UTC) - timedelta(seconds=1),
        signer=IssuerSigner(factory.receipt_key_id, factory.receipt_private_key),
    )
    with owner_engine.begin() as connection:
        deleted = connection.execute(
            text(
                "DELETE FROM evidence_records "
                "WHERE tenant_id = :tenant_id AND record_id = :record_id"
            ),
            {"tenant_id": TENANT_B, "record_id": row["record_id"]},
        )
        assert deleted.rowcount == 1


def test_tenant_deprovision_cannot_bypass_live_attestation_guard(
    owner_engine: Engine,
    record_factories: dict[str, RecordFactory],
    default_boundaries: dict[str, str],
) -> None:
    factory = record_factories[TENANT_A]
    record = _attestation(
        factory, default_boundaries[TENANT_A], suffix="611", sequence=611
    )
    with owner_engine.begin() as connection:
        record_attestation(connection, record)
        with pytest.raises(RuntimeError, match="covering attestation must be revoked"):
            deprovision_tenant(connection, tenant_id=TENANT_A)


@pytest.mark.parametrize("table", ["attestations", "revocations"])
def test_lifecycle_relations_refuse_update_and_delete(
    owner_engine: Engine,
    record_factories: dict[str, RecordFactory],
    default_boundaries: dict[str, str],
    table: str,
) -> None:
    factory = record_factories[TENANT_A]
    suffix = "609" if table == "attestations" else "610"
    sequence = 609 if table == "attestations" else 610
    record = _attestation(
        factory, default_boundaries[TENANT_A], suffix=suffix, sequence=sequence
    )
    with owner_engine.begin() as connection:
        record_attestation(connection, record)
    revoke_attestation(
        owner_engine,
        tenant_id=TENANT_A,
        attestation_id=record.record_id,
        ground=RevocationGround.CUSTOMER_MISREPRESENTATION,
        effective_at=datetime.now(UTC),
        signer=IssuerSigner(factory.receipt_key_id, factory.receipt_private_key),
    )
    identifier = record.record_id
    if table == "revocations":
        with owner_engine.connect() as connection:
            identifier = str(
                connection.execute(
                    select(revocations.c.revocation_id).where(
                        revocations.c.attestation_id == record.record_id
                    )
                ).scalar_one()
            )
    statements = {
        ("attestations", "UPDATE"): (
            "UPDATE attestations SET tenant_id = tenant_id "
            "WHERE attestation_id = :identifier"
        ),
        ("attestations", "DELETE"): (
            "DELETE FROM attestations WHERE attestation_id = :identifier"
        ),
        ("revocations", "UPDATE"): (
            "UPDATE revocations SET tenant_id = tenant_id "
            "WHERE revocation_id = :identifier"
        ),
        ("revocations", "DELETE"): (
            "DELETE FROM revocations WHERE revocation_id = :identifier"
        ),
    }
    for operation in ("UPDATE", "DELETE"):
        statement = statements[(table, operation)]
        with pytest.raises(DBAPIError, match="append-only"):
            with owner_engine.begin() as connection:
                connection.execute(text(statement), {"identifier": identifier})
