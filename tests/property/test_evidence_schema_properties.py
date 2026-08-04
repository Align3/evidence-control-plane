"""Property tests for canonical bytes, digests, and every §5 record type."""

from __future__ import annotations

import json
import subprocess
import sys
from copy import deepcopy
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from sdk_python.evidence.canonical import canonical_digest, canonicalize
from sdk_python.evidence.schema import parse_record, serialize_record, validate_record

SAFE_INTEGER = 9_007_199_254_740_991
TEXT = st.text(st.characters(blacklist_categories=("Cs",)), max_size=24)
JSON_SCALAR = st.none() | st.booleans() | st.integers(-SAFE_INTEGER, SAFE_INTEGER) | TEXT
JSON_VALUE = st.recursive(
    JSON_SCALAR,
    lambda children: st.lists(children, max_size=4)
    | st.dictionaries(TEXT, children, max_size=4),
    max_leaves=12,
)
JSON_OBJECT = st.dictionaries(TEXT, JSON_VALUE, max_size=8)


def _reverse_mappings(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _reverse_mappings(item)
            for key, item in reversed(list(value.items()))
        }
    if isinstance(value, list):
        return [_reverse_mappings(item) for item in value]
    return value


@given(JSON_OBJECT)
def test_canonicalisation_is_deterministic_and_independent_of_dict_order(
    value: dict[str, Any],
) -> None:
    reordered = _reverse_mappings(value)
    assert canonicalize(value) == canonicalize(value)
    assert canonicalize(value) == canonicalize(reordered)


@given(JSON_OBJECT)
@settings(
    max_examples=12,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_canonicalisation_is_byte_stable_across_process_restarts(
    value: dict[str, Any],
) -> None:
    payload = json.dumps(value, ensure_ascii=False).encode()
    program = (
        "import json,sys; "
        "from sdk_python.evidence.canonical import canonicalize; "
        "sys.stdout.buffer.write(canonicalize(json.load(sys.stdin)))"
    )

    first = subprocess.run(  # noqa: S603 - fixed interpreter and static program
        [sys.executable, "-c", program], input=payload, capture_output=True, check=True
    ).stdout
    second = subprocess.run(  # noqa: S603 - fixed interpreter and static program
        [sys.executable, "-c", program], input=payload, capture_output=True, check=True
    ).stdout

    assert first == second == canonicalize(value)


@given(JSON_OBJECT)
def test_digest_is_unchanged_by_semantically_identical_reordering(
    value: dict[str, Any],
) -> None:
    body = deepcopy(dict(BODY_EXAMPLES)["AgentIdentity"])
    body["future_extension"] = value
    raw_record = _record("AgentIdentity", body)

    original = validate_record(raw_record)
    reordered = validate_record(_reverse_mappings(raw_record))

    assert canonical_digest(original) == canonical_digest(reordered)


TS = "2026-07-31T12:00:00.000+01:00"
DIGEST = "sha256:" + "0" * 64

BODY_EXAMPLES: list[tuple[str, dict[str, Any]]] = [
    (
        "AssuranceBoundary",
        {
            "boundary_version": "1",
            "tenant": "tenant-1",
            "deployment": "prod",
            "agent_identities": ["agent-1"],
            "action_families": [{"name": "payment", "qualification_ref": "q-1"}],
            "destination_systems": ["payments"],
            "enforcement_points": ["gateway"],
            "policy_refs": ["policy-1"],
            "window_start": TS,
            "window_end": TS,
            "collection_modes": ["inline"],
            "fail_behaviour": {"payment": "closed"},
            "qualification_refs": ["q-1"],
        },
    ),
    (
        "QualificationRecord",
        {
            "action_family": "payment",
            "destination_system": "payments",
            "enumeration": {"api": "/events"},
            "identity_isolation": {"attribute": "service_identity"},
            "confirmation": {"api": "/events/{id}"},
            "temporal": {"authoritative_timestamp_source": "committed_at"},
            "retention_period": "P90D",
            "mutability": {"deletion_possible": False},
            "assigned_class": "C1",
            "class_evidence": ["audit-doc"],
            "trial": {"window": "P7D", "match_rate": "1.0"},
            "qualified_at": TS,
            "revalidation_cadence": "P30D",
        },
    ),
    (
        "PopulationRecord",
        {
            "action_family": "payment",
            "destination_system": "payments",
            "window_start": TS,
            "window_end": TS,
            "enumeration_query": {"from": TS, "to": TS},
            "record_identifiers": ["dest-1"],
            "count": 1,
            "pagination_complete": True,
            "result_cap_hit": False,
            "retrieved_at": TS,
            "authoritative_timestamps": {"min": TS, "max": TS},
        },
    ),
    (
        "AgentIdentity",
        {
            "agent_id": "agent-1",
            "deployment": "prod",
            "runtime": "python-3.12",
            "tenant_scope": "tenant-1",
            "service_identity": "collector@example.invalid",
            "model_versions": ["model-1"],
            "tool_versions": ["tool-1"],
            "credential_ref": "service_identity",
        },
    ),
    (
        "ActionProposal",
        {
            "action_family": "payment",
            "action_id": "action-1",
            "tool": "payments-api",
            "parameters_digest": DIGEST,
            "purpose": "invoice",
            "target_ref": "invoice-1",
            "risk_class": "high",
            "proposed_at": TS,
        },
    ),
    (
        "AuthorityDecision",
        {
            "action_id": "action-1",
            "decision": "grant",
            "policy_ref": "policy-1",
            "policy_version": "1",
            "constraints": [],
            "decided_by": "engine-1",
            "decided_at": TS,
        },
    ),
    (
        "HumanReview",
        {
            "action_id": "action-1",
            "reviewer_identity": "reviewer-1",
            "reviewer_authority": {"role": "approver", "authorised": True},
            "surface": {"ui": "review", "version": "1"},
            "evidence_shown": DIGEST,
            "evidence_shown_refs": ["proposal-1"],
            "options_offered": ["approve", "deny"],
            "time_available_ms": 30000,
            "time_taken_ms": 1000,
            "decision": "approve",
            "modifications": None,
            "action_state_at_review": "proposed",
            "decided_at": TS,
        },
    ),
    (
        "ExecutionReceipt",
        {
            "action_id": "action-1",
            "dispatch_attempt": 1,
            "connector_identity": "connector-1",
            "connector_version": "1",
            "destination_response_digest": DIGEST,
            "destination_record_ref": "dest-1",
            "status": "accepted",
            "dispatched_at": TS,
            "responded_at": TS,
        },
    ),
    (
        "ExternalConfirmation",
        {
            "action_id": "action-1",
            "destination_system": "payments",
            "destination_record_id": "dest-1",
            "destination_record_digest": DIGEST,
            "authoritative_timestamp": TS,
            "reconciliation_status": "matched",
            "retrieved_at": TS,
        },
    ),
    (
        "FinalityRecord",
        {
            "action_id": "action-1",
            "state": "settled",
            "reversible_until": None,
            "compensation_ref": None,
            "settled_at": TS,
        },
    ),
    (
        "OutcomeRecord",
        {
            "action_id": "action-1",
            "outcome_contract_ref": "contract-1",
            "authoritative_source": "payments",
            "result": {"state": "paid"},
            "finalised_at": TS,
            "disputed": False,
            "reversal_ref": None,
        },
    ),
    (
        "CoverageGap",
        {
            "gap_start": TS,
            "gap_end": TS,
            "affected_scope": {"families": ["payment"]},
            "cause": "collector_unreachable",
            "detection_source": "sdk",
            "exposure": "unknown",
            "actions_during_gap": None,
        },
    ),
    (
        "AttestationWindow",
        {
            "boundary_ref": "boundary-1",
            "window_start": TS,
            "window_end": TS,
            "methodology_version": "1.0.0",
            "denominator_class": "C5",
            "population_record_refs": ["population-1"],
            "coverage_level": "observed",
            "verification_status": "self_computed",
            "coverage_ratio": None,
            "counts": {
                "matched": 0,
                "unmatched_with_evidence": 0,
                "unmatched_without_evidence": 0,
                "duplicate": 0,
                "ambiguous": 0,
            },
            "gaps": [],
            "assertions": [],
            "exclusions": [],
            "relying_parties": ["auditor"],
            "validity_from": TS,
            "validity_until": TS,
            "liability_ref": "terms-1",
            "issued_at": TS,
            "issuer": "issuer-1",
            "verifier_version": "1",
        },
    ),
    (
        "RevocationRecord",
        {
            "attestation_ref": "attestation-1",
            "reason": "superseded",
            "issuer": "issuer-1",
            "effective_at": TS,
            "superseding_ref": None,
            "relying_party_notification_status": "pending",
        },
    ),
]


def _record(record_type: str, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "record_id": "01890f47-2f58-7cc0-98c4-dc0c0c07398f",
        "record_type": record_type,
        "schema_version": "1.0.0",
        "tenant_id": "tenant-1",
        "boundary_ref": "boundary-1",
        "stream_id": "collector-1",
        "sequence": 1,
        "prev_digest": None,
        "source": {"collector": "sdk-python", "version": "0.1.0"},
        "clocks": {"source_time": TS},
        "body": body,
        "signature": {},
    }


@pytest.mark.parametrize(("record_type", "body"), BODY_EXAMPLES)
@given(extension_value=JSON_VALUE)
@settings(max_examples=8)
def test_parse_serialize_round_trip_for_every_record_type(
    record_type: str,
    body: dict[str, Any],
    extension_value: Any,
) -> None:
    extended_body = deepcopy(body)
    extended_body["future_extension"] = extension_value
    original = validate_record(_record(record_type, extended_body))

    canonical = serialize_record(original)
    reparsed = parse_record(canonical)

    assert reparsed == original
    # Model equality is strictly weaker than byte equality: pydantic __eq__
    # ignores model_fields_set, so a member dropped from serialization would
    # still compare equal after a round trip. The digest is computed over the
    # bytes, so the bytes are what has to be stable.
    assert serialize_record(reparsed) == canonical
