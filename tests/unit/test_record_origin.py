"""Closed ES-033 origin dispatch independent of individual happy paths."""

from __future__ import annotations

import pytest

from sdk_python.evidence import schema
from sdk_python.evidence.origin import (
    PRIMARY_SIGNER_NAMESPACE,
    primary_signer_namespace,
)


def test_every_published_record_type_has_exactly_one_origin_category() -> None:
    assert set(PRIMARY_SIGNER_NAMESPACE) == set(schema._RECORD_MODELS)
    assert set(PRIMARY_SIGNER_NAMESPACE.values()) == {"evidence", "issuer"}


def test_origin_dispatch_has_no_evidence_default_for_future_types() -> None:
    with pytest.raises(ValueError, match="no ES-033 origin classification"):
        primary_signer_namespace("FutureRecord")


def test_origin_dispatch_cannot_be_weakened_by_a_caller() -> None:
    with pytest.raises(TypeError):
        PRIMARY_SIGNER_NAMESPACE["PopulationRecord"] = "evidence"  # type: ignore[index]


def test_hosted_connector_observations_are_issuer_primary() -> None:
    assert primary_signer_namespace("PopulationRecord") == "issuer"
    assert primary_signer_namespace("ExternalConfirmation") == "issuer"


def test_attestation_retains_evidence_primary_for_counter_signature_model() -> None:
    assert primary_signer_namespace("AttestationWindow") == "evidence"


def test_revocation_is_issuer_primary_without_a_customer_proof() -> None:
    """SE-002's other half, pinned separately from the AttestationWindow form.

    A `RevocationRecord` states an issuer conclusion with no customer-authored
    conclusion underneath it, so unlike `AttestationWindow` it takes an issuer
    primary signature rather than a customer primary plus counter-signature.
    Asserting it here keeps the two conclusion shapes from being conflated if
    the table is ever edited.
    """

    assert primary_signer_namespace("RevocationRecord") == "issuer"
    assert primary_signer_namespace("RevocationRecord") != primary_signer_namespace(
        "AttestationWindow"
    )
