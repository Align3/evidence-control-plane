"""Digest helpers (ES-003).

Small surface, but the refusals matter: the algorithm is fixed at SHA-256,
and a helper that quietly accepted a shorter or differently-prefixed digest
would let a weaker one into `record_digest` and `prev_digest`, which are what
the chain is made of.
"""

from __future__ import annotations

import hashlib

import pytest
from hypothesis import given
from hypothesis import strategies as st

from services.ledger import digest_bytes, digest_matches, digest_ref, parse_digest_ref


@given(st.binary(max_size=4096))
def test_digest_ref_roundtrips(payload: bytes) -> None:
    raw = digest_bytes(payload)
    assert parse_digest_ref(digest_ref(raw)) == raw
    assert digest_ref(raw) == "sha256:" + hashlib.sha256(payload).hexdigest()


@given(st.binary(max_size=1024), st.binary(max_size=1024))
def test_digest_matches_only_its_own_bytes(a: bytes, b: bytes) -> None:
    assert digest_matches(a, digest_bytes(a))
    if a != b:
        assert not digest_matches(a, digest_bytes(b))


@pytest.mark.parametrize(
    "reference",
    [
        "sha1:" + "0" * 40,
        "md5:" + "0" * 32,
        "0" * 64,                    # unprefixed
        "sha256:" + "0" * 40,        # right algorithm, wrong length
        "SHA256:" + "0" * 64,        # prefix is lowercase (ES-003)
    ],
)
def test_non_sha256_references_are_refused(reference: str) -> None:
    with pytest.raises(ValueError):
        parse_digest_ref(reference)
