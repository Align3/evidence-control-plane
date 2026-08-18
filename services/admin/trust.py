"""Trusted key resolution for administrative evidence records.

The caller supplies a record, never the keyring used to authenticate it.  A
key identifier has meaning only together with the registered tenant,
namespace, and key material stored in ``keys``; accepting a caller-provided
mapping would let one identifier name two different keys.
"""

from __future__ import annotations

from collections.abc import Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import Connection, select

from sdk_python.evidence.signing import SignatureError, UnknownKeyError
from services.ingestion.receipts import RegisteredPublicKey
from services.ledger.schema import keys


def registered_evidence_keyring(
    connection: Connection,
    *,
    tenant_id: str,
    signature: object,
) -> Mapping[str, Ed25519PublicKey]:
    """Resolve one evidence signer from the authoritative registry."""

    if not isinstance(signature, dict):
        raise SignatureError("signature must be a JSON object")
    key_id = signature.get("key_id")
    if not isinstance(key_id, str) or not key_id:
        raise SignatureError("key_id must be a non-empty string")

    raw = connection.execute(
        select(keys.c.public_key).where(
            keys.c.tenant_id == tenant_id,
            keys.c.key_id == key_id,
            keys.c.namespace == "evidence",
        )
    ).scalar_one_or_none()
    if raw is None:
        raise UnknownKeyError(
            f"unknown evidence signing key for tenant {tenant_id!r}: {key_id}"
        )
    try:
        public_key = Ed25519PublicKey.from_public_bytes(bytes(raw))
    except ValueError as exc:
        raise SignatureError(
            f"registered evidence key {key_id!r} has invalid Ed25519 material"
        ) from exc
    return {key_id: public_key}


def registered_receipt_keyring(
    connection: Connection,
    *,
    tenant_id: str,
    key_id: str,
) -> Mapping[str, RegisteredPublicKey]:
    """Resolve a constitutive receipt signer from the tenant key registry.

    Namespace filtering is deliberately left to ``verify_ingestion_receipt``:
    resolving an evidence-namespace row and then refusing it as the wrong
    role proves that an existing key cannot acquire issuer authority merely
    because a caller presents it on the receipt path.
    """

    row = connection.execute(
        select(keys.c.namespace, keys.c.public_key).where(
            keys.c.tenant_id == tenant_id,
            keys.c.key_id == key_id,
        )
    ).mappings().one_or_none()
    if row is None:
        raise UnknownKeyError(
            f"unknown receipt signing key for tenant {tenant_id!r}: {key_id}"
        )
    try:
        public_key = Ed25519PublicKey.from_public_bytes(bytes(row["public_key"]))
    except ValueError as exc:
        raise SignatureError(
            f"registered receipt key {key_id!r} has invalid Ed25519 material"
        ) from exc
    return {
        key_id: RegisteredPublicKey(
            namespace=str(row["namespace"]),
            public_key=public_key,
        )
    }


__all__ = ["registered_evidence_keyring", "registered_receipt_keyring"]
