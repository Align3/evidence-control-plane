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

valid_tenant_ids = st.from_regex(r"\A[a-z0-9][a-z0-9_]{0,45}[a-z0-9]\Z")

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
    """Distinct tenants can never share a partition or a role."""
    if first == second:
        return
    assert partition_name(first) != partition_name(second)
    assert application_role(first) != application_role(second)


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
