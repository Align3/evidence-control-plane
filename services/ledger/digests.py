"""Digest helpers (ES-003).

The ledger computes one digest and one only: SHA-256 over the canonical
bytes it was handed. It does **not** canonicalize -- serialization is the
writer's responsibility (ES-001), and a ledger that re-serialized before
hashing would be asserting agreement with the writer's canonicalizer rather
than storing what was signed.
"""

from __future__ import annotations

import hashlib
import hmac

DIGEST_PREFIX = "sha256:"


def digest_bytes(canonical_bytes: bytes) -> bytes:
    """Raw SHA-256 of the canonical bytes, as stored in `record_digest`."""
    return hashlib.sha256(canonical_bytes).digest()


def digest_ref(raw: bytes) -> str:
    """Wire form: lowercase hex with the `sha256:` prefix (ES-003)."""
    return DIGEST_PREFIX + raw.hex()


def parse_digest_ref(reference: str) -> bytes:
    """Inverse of `digest_ref`, rejecting any other algorithm.

    ES-003 fixes the algorithm; accepting an unprefixed or differently
    prefixed digest here would let a caller smuggle a weaker one in.
    """
    if not reference.startswith(DIGEST_PREFIX):
        raise ValueError(f"unsupported digest {reference!r}: expected {DIGEST_PREFIX}")
    raw = bytes.fromhex(reference.removeprefix(DIGEST_PREFIX))
    if len(raw) != 32:
        raise ValueError(f"digest {reference!r} is not 32 bytes")
    return raw


def digest_matches(canonical_bytes: bytes, record_digest: bytes) -> bool:
    """Whether a stored digest still reproduces from the canonical bytes."""
    return hmac.compare_digest(digest_bytes(canonical_bytes), record_digest)
