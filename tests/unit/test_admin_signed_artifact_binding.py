"""Administrative projections and stored proofs come from one signed artifact."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import Engine

from sdk_python.evidence.signing import InvalidSignatureError
from services.admin import record_boundary, record_qualification
from tests.admin_support import (
    AdminActor,
    boundary_body,
    constitutive_receipt,
    qualification_body,
    signed_boundary,
    signed_qualification,
)
from tests.ledger_support import TENANT_A


@pytest.fixture
def actor(admin_actors: dict[str, AdminActor]) -> AdminActor:
    return admin_actors[TENANT_A]


def _receipt(record: object, actor: AdminActor):
    return constitutive_receipt(
        record,  # type: ignore[arg-type]
        issuer_key_id=actor.issuer_key_id,
        issuer_private_key=actor.issuer_private_key,
        recorded_at=datetime(2026, 2, 1, tzinfo=UTC),
    )


def test_qualification_refuses_a_model_different_from_the_signed_bytes(
    owner_engine: Engine, actor: AdminActor
) -> None:
    signed, canonical, signature = signed_qualification(
        tenant_id=actor.tenant_id,
        collector_id=actor.collector_id,
        key_id=actor.key_id,
        private_key=actor.private_key,
        boundary_ref=f"{actor.tenant_id}:default:1",
        body=qualification_body(
            action_family="artifact.qualification",
            destination_system="payments-core",
            assigned_class="C4",
            qualified_at=datetime(2026, 1, 1, tzinfo=UTC),
        ),
    )
    substituted_body = signed.body.model_copy(update={"assigned_class": "C1"})
    substituted = signed.model_copy(update={"body": substituted_body})

    with owner_engine.connect() as conn:
        transaction = conn.begin()
        try:
            with pytest.raises(InvalidSignatureError, match="do not match"):
                record_qualification(
                    conn,
                    record=substituted,
                    canonical_bytes=canonical,
                    signature=signature,
                    receipt=_receipt(substituted, actor),
                )
        finally:
            transaction.rollback()


def test_qualification_refuses_a_detached_signature_substitution(
    owner_engine: Engine, actor: AdminActor
) -> None:
    signed, canonical, _signature = signed_qualification(
        tenant_id=actor.tenant_id,
        collector_id=actor.collector_id,
        key_id=actor.key_id,
        private_key=actor.private_key,
        boundary_ref=f"{actor.tenant_id}:default:1",
        body=qualification_body(
            action_family="artifact.detached-qualification",
            destination_system="payments-core",
            assigned_class="C4",
            qualified_at=datetime(2026, 1, 1, tzinfo=UTC),
        ),
    )

    with owner_engine.connect() as conn:
        transaction = conn.begin()
        try:
            with pytest.raises(InvalidSignatureError, match="detached signature"):
                record_qualification(
                    conn,
                    record=signed,
                    canonical_bytes=canonical,
                    signature=b"\x00" * 64,
                    receipt=_receipt(signed, actor),
                )
        finally:
            transaction.rollback()


def test_qualification_refuses_caller_key_material_substitution(
    owner_engine: Engine, actor: AdminActor
) -> None:
    """A registered key id cannot be rebound to caller-chosen key material."""
    rogue = Ed25519PrivateKey.generate()
    signed, canonical, signature = signed_qualification(
        tenant_id=actor.tenant_id,
        collector_id=actor.collector_id,
        key_id=actor.key_id,
        private_key=rogue,
        boundary_ref=f"{actor.tenant_id}:default:1",
        body=qualification_body(
            action_family="artifact.rogue-qualification-key",
            destination_system="payments-core",
            assigned_class="C4",
            qualified_at=datetime(2026, 1, 1, tzinfo=UTC),
        ),
    )

    with owner_engine.connect() as conn:
        transaction = conn.begin()
        try:
            with pytest.raises(InvalidSignatureError):
                record_qualification(
                    conn,
                    record=signed,
                    canonical_bytes=canonical,
                    signature=signature,
                    receipt=_receipt(signed, actor),
                )
        finally:
            transaction.rollback()


def test_boundary_refuses_a_model_different_from_the_signed_bytes(
    owner_engine: Engine, actor: AdminActor
) -> None:
    with owner_engine.connect() as conn:
        transaction = conn.begin()
        try:
            qualification_ref = actor.write_qualification(
                conn,
                action_family="artifact.boundary",
                destination_system="payments-core",
                assigned_class="C4",
                qualified_at=datetime(2026, 1, 1, tzinfo=UTC),
            )
            signed, canonical, signature = signed_boundary(
                tenant_id=actor.tenant_id,
                collector_id=actor.collector_id,
                key_id=actor.key_id,
                private_key=actor.private_key,
                name="artifact-binding",
                version=1,
                body=boundary_body(
                    tenant_id=actor.tenant_id,
                    version=1,
                    window_start=datetime(2026, 3, 1, tzinfo=UTC),
                    window_end=datetime(2026, 4, 1, tzinfo=UTC),
                    families=[
                        {
                            "action_family": "artifact.boundary",
                            "destination_system": "payments-core",
                            "qualification_ref": qualification_ref,
                        }
                    ],
                ),
            )
            substituted_body = signed.body.model_copy(
                update={"deployment": "substituted-deployment"}
            )
            substituted = signed.model_copy(update={"body": substituted_body})

            with pytest.raises(InvalidSignatureError, match="do not match"):
                record_boundary(
                    conn,
                    record=substituted,
                    canonical_bytes=canonical,
                    signature=signature,
                    receipt=_receipt(substituted, actor),
                )
        finally:
            transaction.rollback()


def test_boundary_refuses_a_detached_signature_substitution(
    owner_engine: Engine, actor: AdminActor
) -> None:
    with owner_engine.connect() as conn:
        transaction = conn.begin()
        try:
            qualification_ref = actor.write_qualification(
                conn,
                action_family="artifact.detached-boundary",
                destination_system="payments-core",
                assigned_class="C4",
                qualified_at=datetime(2026, 1, 1, tzinfo=UTC),
            )
            signed, canonical, _signature = signed_boundary(
                tenant_id=actor.tenant_id,
                collector_id=actor.collector_id,
                key_id=actor.key_id,
                private_key=actor.private_key,
                name="artifact-detached-signature",
                version=1,
                body=boundary_body(
                    tenant_id=actor.tenant_id,
                    version=1,
                    window_start=datetime(2026, 3, 1, tzinfo=UTC),
                    window_end=datetime(2026, 4, 1, tzinfo=UTC),
                    families=[
                        {
                            "action_family": "artifact.detached-boundary",
                            "destination_system": "payments-core",
                            "qualification_ref": qualification_ref,
                        }
                    ],
                ),
            )

            with pytest.raises(InvalidSignatureError, match="detached signature"):
                record_boundary(
                    conn,
                    record=signed,
                    canonical_bytes=canonical,
                    signature=b"\x00" * 64,
                    receipt=_receipt(signed, actor),
                )
        finally:
            transaction.rollback()


def test_boundary_refuses_caller_key_material_substitution(
    owner_engine: Engine, actor: AdminActor
) -> None:
    """The boundary path resolves the tenant's registered evidence key too."""
    rogue = Ed25519PrivateKey.generate()
    with owner_engine.connect() as conn:
        transaction = conn.begin()
        try:
            qualification_ref = actor.write_qualification(
                conn,
                action_family="artifact.rogue-boundary-key",
                destination_system="payments-core",
                assigned_class="C4",
                qualified_at=datetime(2026, 1, 1, tzinfo=UTC),
            )
            signed, canonical, signature = signed_boundary(
                tenant_id=actor.tenant_id,
                collector_id=actor.collector_id,
                key_id=actor.key_id,
                private_key=rogue,
                name="artifact-rogue-key",
                version=1,
                body=boundary_body(
                    tenant_id=actor.tenant_id,
                    version=1,
                    window_start=datetime(2026, 3, 1, tzinfo=UTC),
                    window_end=datetime(2026, 4, 1, tzinfo=UTC),
                    families=[
                        {
                            "action_family": "artifact.rogue-boundary-key",
                            "destination_system": "payments-core",
                            "qualification_ref": qualification_ref,
                        }
                    ],
                ),
            )

            with pytest.raises(InvalidSignatureError):
                record_boundary(
                    conn,
                    record=signed,
                    canonical_bytes=canonical,
                    signature=signature,
                    receipt=_receipt(signed, actor),
                )
        finally:
            transaction.rollback()
