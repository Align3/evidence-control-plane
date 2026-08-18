"""Client-held signing identity (SE-005, SE-006).

Signing itself is `sdk_python.evidence.signing`. Nothing here reimplements
Ed25519 or canonicalisation; this module owns custody and containment only.

Containment is the reason the key is wrapped rather than passed around bare.
An `Ed25519PrivateKey` handed directly to application code ends up in a
dataclass `repr`, a structured log field, or a pytest assertion diff sooner or
later. Wrapping it means the failure mode has to be deliberate: every path that
renders this object renders a redaction.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Never

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

REDACTED = "<redacted Ed25519 private key>"


class SigningUnavailableError(RuntimeError):
    """Local signing failed.

    Carries no key material and no wrapped cause: a `cryptography` exception
    chained here would put the key object into the traceback frame locals,
    where any traceback formatter that renders locals would print it.
    """


@dataclass(frozen=True, slots=True, repr=False)
class SigningIdentity:
    """One key per (tenant, deployment, collector instance) under SE-005.

    SE-006's default custody is client-held: this object is constructed inside
    the customer's process from their own key material, and the hosted service
    never receives it.
    """

    key_id: str
    private_key: Ed25519PrivateKey

    def __post_init__(self) -> None:
        if not self.key_id:
            raise ValueError("a signing identity requires a key_id")
        if not isinstance(self.private_key, Ed25519PrivateKey):
            raise TypeError("signing identity requires an Ed25519 private key")

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    # Every rendering path is closed, not just the obvious one. `repr` covers
    # f-strings and containers, `str` covers direct interpolation, and the
    # reduce hooks stop `copy`/`pickle` from moving the key somewhere that
    # renders it without this class's cooperation.
    def __repr__(self) -> str:
        return f"SigningIdentity(key_id={self.key_id!r}, private_key={REDACTED})"

    def __str__(self) -> str:
        return self.__repr__()

    def __format__(self, format_spec: str) -> str:
        return self.__repr__()

    def __reduce__(self) -> Never:
        raise TypeError(
            "a SigningIdentity cannot be serialized; SE-006 keeps client-held "
            "key material in the process that created it"
        )

    def __getstate__(self) -> Never:
        self.__reduce__()  # always raises; declared Never for the type checker
        raise AssertionError("unreachable")

    def sign_bytes(self, payload: bytes) -> bytes:
        """Raw Ed25519 over already-prepared bytes.

        The exception is raised `from None` deliberately. Chaining the original
        would attach a frame whose locals hold the private key, which is exactly
        the leak this module exists to prevent.
        """

        try:
            return self.private_key.sign(payload)
        except Exception:  # noqa: BLE001 - see docstring: cause is dropped on purpose
            raise SigningUnavailableError(
                f"local signing failed for key_id {self.key_id!r}"
            ) from None


def redact(value: Any) -> Any:
    """Return `value` with any signing identity replaced by its redaction."""

    if isinstance(value, SigningIdentity | Ed25519PrivateKey):
        return REDACTED
    return value
