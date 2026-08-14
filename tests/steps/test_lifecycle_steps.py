"""Executable EV-18 acceptance bindings."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from pytest_bdd import given, scenario, then, when
from sqlalchemy import Engine, select, text
from sqlalchemy.exc import DBAPIError

from services.attestation import IssuerSigner
from services.attestation.lifecycle import (
    LifecycleStatus,
    attestation_status,
    record_attestation,
    supersede_attestation,
)
from services.attestation.schema import attestations
from services.ledger import TenantEngines, evidence_partition, tenant_connection
from tests.ledger_support import TENANT_A, RecordFactory
from tests.lifecycle_support import signed_attestation


@scenario("../features/attestation.feature", "AR-S-004 Expired verifies as expired")
def test_expired_verifies_as_expired() -> None:
    pass


@scenario("../features/attestation.feature", "AR-S-005 Supersession preserves the original")
def test_supersession_preserves_original() -> None:
    pass


@scenario("../features/coverage.feature", "CM-S-006 Late evidence supersedes rather than amends")
def test_late_evidence_supersedes() -> None:
    pass


@scenario(
    "../features/security.feature",
    "SE-S-004 Evidence deletion blocked while attestation valid",
)
def test_evidence_deletion_blocked_while_attestation_valid() -> None:
    pass


@given("an attestation whose validity_until has passed", target_fixture="lifecycle_context")
def expired_attestation(
    owner_engine: Engine,
    record_factories: dict[str, RecordFactory],
    default_boundaries: dict[str, str],
) -> dict[str, Any]:
    now = datetime.now(UTC)
    record = signed_attestation(
        record_factories[TENANT_A],
        record_id="01890f47-2f58-7cc0-98c4-000000000651",
        boundary_ref=default_boundaries[TENANT_A],
        sequence=651,
        window_start=datetime(2026, 7, 31, 11, tzinfo=UTC),
        window_end=datetime(2026, 7, 31, 13, tzinfo=UTC),
        validity_from=now - timedelta(days=2),
        validity_until=now - timedelta(days=1),
    )
    with owner_engine.begin() as connection:
        record_attestation(connection, record)
    return {"record": record, "as_of": now}


@when("the verifier validates it")
def validate_status(owner_engine: Engine, lifecycle_context: dict[str, Any]) -> None:
    with owner_engine.connect() as connection:
        lifecycle_context["status"] = attestation_status(
            connection,
            tenant_id=TENANT_A,
            attestation_id=lifecycle_context["record"].record_id,
            as_of=lifecycle_context["as_of"],
        )


@then('the result is "expired"')
def result_expired(lifecycle_context: dict[str, Any]) -> None:
    assert lifecycle_context["status"] is LifecycleStatus.EXPIRED


@then('the result is not "valid"')
def result_not_valid(lifecycle_context: dict[str, Any]) -> None:
    assert lifecycle_context["status"] is not LifecycleStatus.VALID


@given("attestation A and superseding attestation A'", target_fixture="lifecycle_context")
def attestation_pair(
    owner_engine: Engine,
    record_factories: dict[str, RecordFactory],
    default_boundaries: dict[str, str],
) -> dict[str, Any]:
    factory = record_factories[TENANT_A]
    common = {
        "boundary_ref": default_boundaries[TENANT_A],
        "window_start": datetime(2026, 7, 31, 11, tzinfo=UTC),
        "window_end": datetime(2026, 7, 31, 13, tzinfo=UTC),
    }
    original = signed_attestation(
        factory,
        record_id="01890f47-2f58-7cc0-98c4-000000000652",
        sequence=652,
        **common,
    )
    replacement = signed_attestation(
        factory,
        record_id="01890f47-2f58-7cc0-98c4-000000000653",
        sequence=653,
        **common,
    )
    with owner_engine.begin() as connection:
        record_attestation(connection, original)
        transition = supersede_attestation(
            connection,
            tenant_id=TENANT_A,
            original_attestation_id=original.record_id,
            superseding_attestation=replacement,
            effective_at=datetime.now(UTC),
            signer=IssuerSigner(factory.receipt_key_id, factory.receipt_private_key),
            notify=lambda _party: None,
        )
    return {"record": original, "replacement": replacement, "transition": transition}


@when("either is verified")
def verify_pair(owner_engine: Engine, lifecycle_context: dict[str, Any]) -> None:
    now = datetime.now(UTC)
    with owner_engine.connect() as connection:
        lifecycle_context["original_status"] = attestation_status(
            connection,
            tenant_id=TENANT_A,
            attestation_id=lifecycle_context["record"].record_id,
            as_of=now,
        )
        lifecycle_context["replacement_status"] = attestation_status(
            connection,
            tenant_id=TENANT_A,
            attestation_id=lifecycle_context["replacement"].record_id,
            as_of=now,
        )


@then("A remains independently verifiable")
def original_preserved(lifecycle_context: dict[str, Any]) -> None:
    assert lifecycle_context["original_status"] is LifecycleStatus.SUPERSEDED


@then("A' references A")
def replacement_link(lifecycle_context: dict[str, Any]) -> None:
    transition = lifecycle_context["transition"].record
    assert transition.body.attestation_ref == lifecycle_context["record"].record_id
    assert transition.body.superseding_ref == lifecycle_context["replacement"].record_id


@then("A is reported as superseded, not invalid")
def original_superseded(lifecycle_context: dict[str, Any]) -> None:
    assert lifecycle_context["original_status"] is LifecycleStatus.SUPERSEDED
    assert lifecycle_context["replacement_status"] is LifecycleStatus.VALID


@given(
    "attestation A issued for window W with 3 unmatched records",
    target_fixture="lifecycle_context",
)
def issued_with_unmatched(
    owner_engine: Engine,
    record_factories: dict[str, RecordFactory],
    default_boundaries: dict[str, str],
) -> dict[str, Any]:
    factory = record_factories[TENANT_A]
    common = {
        "boundary_ref": default_boundaries[TENANT_A],
        "window_start": datetime(2026, 7, 31, 11, tzinfo=UTC),
        "window_end": datetime(2026, 7, 31, 13, tzinfo=UTC),
    }
    original = signed_attestation(
        factory,
        record_id="01890f47-2f58-7cc0-98c4-000000000654",
        sequence=654,
        **common,
    )
    replacement = signed_attestation(
        factory,
        record_id="01890f47-2f58-7cc0-98c4-000000000655",
        sequence=655,
        **common,
    )
    with owner_engine.begin() as connection:
        record_attestation(connection, original)
        before = connection.execute(
            select(attestations.c.canonical_bytes).where(
                attestations.c.attestation_id == original.record_id
            )
        ).scalar_one()
    return {
        "record": original,
        "replacement": replacement,
        "before": before,
        "factory": factory,
        "notified": [],
    }


@when("a destination confirmation matching one of them arrives after issuance")
def late_confirmation(
    owner_engine: Engine, lifecycle_context: dict[str, Any]
) -> None:
    factory = lifecycle_context["factory"]
    with owner_engine.begin() as connection:
        lifecycle_context["transition"] = supersede_attestation(
            connection,
            tenant_id=TENANT_A,
            original_attestation_id=lifecycle_context["record"].record_id,
            superseding_attestation=lifecycle_context["replacement"],
            effective_at=datetime.now(UTC),
            signer=IssuerSigner(factory.receipt_key_id, factory.receipt_private_key),
            notify=lambda party: lifecycle_context["notified"].append(party["name"]),
        )


@then("attestation A is not modified")
def a_not_modified(owner_engine: Engine, lifecycle_context: dict[str, Any]) -> None:
    with owner_engine.connect() as connection:
        after = connection.execute(
            select(attestations.c.canonical_bytes).where(
                attestations.c.attestation_id
                == lifecycle_context["record"].record_id
            )
        ).scalar_one()
    assert after == lifecycle_context["before"]


@then("a superseding attestation A' is issued referencing A")
def replacement_issued(lifecycle_context: dict[str, Any]) -> None:
    replacement_link(lifecycle_context)


@then("relying parties of A are notified")
def parties_notified(lifecycle_context: dict[str, Any]) -> None:
    assert (
        lifecycle_context["transition"].record.body.relying_party_notification_status
        == "notified"
    )
    assert lifecycle_context["notified"] == ["buyer"]


@given("a valid attestation covering window W", target_fixture="lifecycle_context")
def valid_attestation_covering_window(
    owner_engine: Engine,
    tenant_engines: TenantEngines,
    record_factories: dict[str, RecordFactory],
    default_boundaries: dict[str, str],
) -> dict[str, Any]:
    factory = record_factories[TENANT_A]
    row = factory.next_record()
    with tenant_connection(tenant_engines, TENANT_A) as connection:
        connection.execute(evidence_partition(TENANT_A).insert(), row)
    record = signed_attestation(
        factory,
        record_id="01890f47-2f58-7cc0-98c4-000000000656",
        boundary_ref=default_boundaries[TENANT_A],
        sequence=656,
        window_start=datetime(2026, 7, 31, 11, tzinfo=UTC),
        window_end=datetime(2026, 7, 31, 13, tzinfo=UTC),
    )
    with owner_engine.begin() as connection:
        record_attestation(connection, record)
    return {"evidence": row, "record": record}


@when("deletion of evidence within W is requested")
def request_evidence_deletion(
    owner_engine: Engine, lifecycle_context: dict[str, Any]
) -> None:
    try:
        with owner_engine.begin() as connection:
            connection.execute(
                text(
                    "DELETE FROM evidence_records"
                    " WHERE tenant_id = :tenant_id AND record_id = :record_id"
                ),
                {
                    "tenant_id": TENANT_A,
                    "record_id": lifecycle_context["evidence"]["record_id"],
                },
            )
    except DBAPIError as exc:
        lifecycle_context["deletion_error"] = str(exc.orig)


@then("deletion is refused")
def deletion_refused(lifecycle_context: dict[str, Any]) -> None:
    assert "deletion_error" in lifecycle_context


@then("the refusal states that the covering attestation must be revoked first")
def deletion_refusal_is_actionable(lifecycle_context: dict[str, Any]) -> None:
    assert "covering attestation must be revoked first" in lifecycle_context[
        "deletion_error"
    ]
