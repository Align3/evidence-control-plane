"""Property tests for the tenant-id to identifier mapping.

`tenant_id` reaches SQL identifiers in `CREATE TABLE ... PARTITION OF` and
`CREATE ROLE`, neither of which accepts a bind parameter. Two properties
carry the safety of that, and both are universal claims -- exactly what
property testing is for:

1. **Injectivity.** Distinct accepted tenant ids derive distinct partition
   and role names. A collision would give two tenants one partition, which
   is a cross-tenant read with no attacker involved.

2. **Closure under the identifier alphabet.** Anything `validate_tenant_id`
   accepts contains no character that could terminate a quoted identifier or
   a string literal.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from services.ledger import application_role, partition_name, validate_tenant_id
from services.ledger.naming import MAX_IDENTIFIER_BYTES, MAX_TENANT_ID_LENGTH

# Generated from the real bound rather than a hand-copied one, so the
# strategy cannot quietly stop covering the longest accepted id -- which is
# exactly where truncation collisions live.
valid_tenant_ids = st.from_regex(
    rf"\A[a-z0-9][a-z0-9_]{{0,{MAX_TENANT_ID_LENGTH - 2}}}[a-z0-9]\Z"
)


def _as_stored(identifier: str) -> str:
    """The identifier as Postgres would store it: truncated, not rejected."""
    return identifier.encode("utf-8")[:MAX_IDENTIFIER_BYTES].decode("utf-8")

# Everything an attacker would reach for to break out of a quoted identifier
# or a string literal in the partition bound.
DANGEROUS = [
    'acme"; DROP TABLE evidence_records; --',
    "acme'; DROP TABLE evidence_records; --",
    "acme\\",
    "acme'",
    'acme"',
    "acme;",
    "acme evidence",
    "acme\nglobex",
    "acme\x00",
    "ACME",
    "acme-corp",
    "_acme",
    "acme_",
    "",
    "a" * 64,
    "évidence",
    # Long enough that 'evidence_records_' + id exceeds 63 bytes. Accepted
    # under the previous bound of 48, and two such ids sharing a 47-character
    # prefix truncated to one partition and one role.
    "a" * (MAX_TENANT_ID_LENGTH + 1),
    "a" * 47,
    "a" * 48,
]


@given(valid_tenant_ids)
def test_accepted_ids_contain_only_identifier_characters(tenant_id: str) -> None:
    assert validate_tenant_id(tenant_id) == tenant_id
    for derived in (partition_name(tenant_id), application_role(tenant_id)):
        assert derived.replace("_", "").isalnum()
        assert derived.islower() or derived.replace("_", "").isdigit()
        assert not (set(derived) & set("\"'\\;- \n\t\x00%")), derived


@given(valid_tenant_ids, valid_tenant_ids)
def test_derivation_is_injective(first: str, second: str) -> None:
    """Distinct tenants can never share a partition or a role.

    Compared **as Postgres stores them**. Comparing the Python strings is the
    wrong claim and passes vacuously: an over-long name is distinct in Python
    and identical in the catalogue, which is precisely the collision this
    test exists to exclude.
    """
    if first == second:
        return
    assert _as_stored(partition_name(first)) != _as_stored(partition_name(second))
    assert _as_stored(application_role(first)) != _as_stored(application_role(second))


@given(valid_tenant_ids)
def test_derived_identifiers_survive_postgres_intact(tenant_id: str) -> None:
    """No accepted tenant id derives a name Postgres would truncate."""
    for derived in (partition_name(tenant_id), application_role(tenant_id)):
        assert len(derived.encode("utf-8")) <= MAX_IDENTIFIER_BYTES, derived
        assert _as_stored(derived) == derived


# The two above are generated from MAX_TENANT_ID_LENGTH, so if that constant
# is ever wrong they widen with it and stop being a check on it. These two
# pin the boundary deterministically instead: they are the regression tests
# for the truncation collision and they must not depend on Hypothesis
# happening to reach the longest id.


def test_the_longest_accepted_tenant_id_still_fits_in_an_identifier() -> None:
    longest = "a" + "b" * (MAX_TENANT_ID_LENGTH - 2) + "c"
    assert len(longest) == MAX_TENANT_ID_LENGTH
    assert validate_tenant_id(longest) == longest
    for derived in (partition_name(longest), application_role(longest)):
        assert len(derived.encode("utf-8")) <= MAX_IDENTIFIER_BYTES, (
            f"{derived!r} is {len(derived.encode('utf-8'))} bytes; Postgres "
            f"truncates at {MAX_IDENTIFIER_BYTES} and two tenants collide"
        )


def test_ids_differing_only_past_the_truncation_point_cannot_collide() -> None:
    """The exact shape of the defect: same long prefix, different last byte."""
    first = "a" * (MAX_TENANT_ID_LENGTH - 1) + "b"
    second = "a" * (MAX_TENANT_ID_LENGTH - 1) + "c"
    assert first != second
    for derive in (partition_name, application_role):
        try:
            one, two = derive(first), derive(second)
        except ValueError:
            continue  # refusing them outright is also a correct answer
        assert _as_stored(one) != _as_stored(two), (
            f"{first!r} and {second!r} both derive {_as_stored(one)!r} once "
            "Postgres truncates -- two tenants, one relation"
        )


@given(valid_tenant_ids)
def test_partition_and_role_namespaces_do_not_overlap(tenant_id: str) -> None:
    """A partition named like a role (or vice versa) would let a grant meant
    for one land on the other."""
    assert partition_name(tenant_id) != application_role(tenant_id)


@pytest.mark.parametrize("tenant_id", DANGEROUS)
def test_dangerous_ids_are_refused(tenant_id: str) -> None:
    """Negative-first: the refusal is the property that matters here."""
    with pytest.raises(ValueError, match="invalid tenant_id"):
        validate_tenant_id(tenant_id)
    with pytest.raises(ValueError):
        partition_name(tenant_id)
    with pytest.raises(ValueError):
        application_role(tenant_id)
