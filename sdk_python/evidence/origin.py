"""Closed record-origin signing policy (ES-033 / SE-003)."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final, Literal

PrimarySignerNamespace = Literal["evidence", "issuer"]

# Complete rather than defaulting to evidence. A new record type is not
# authorised until the specification, this table, Go, and the vectors agree.
PRIMARY_SIGNER_NAMESPACE: Final[Mapping[str, PrimarySignerNamespace]] = MappingProxyType(
    {
        "AssuranceBoundary": "evidence",
        "QualificationRecord": "evidence",
        "PopulationRecord": "issuer",
        "AgentIdentity": "evidence",
        "ActionProposal": "evidence",
        "AuthorityDecision": "evidence",
        "HumanReview": "evidence",
        "ExecutionReceipt": "evidence",
        "ExternalConfirmation": "issuer",
        "FinalityRecord": "evidence",
        "OutcomeRecord": "evidence",
        "CoverageGap": "evidence",
        "AttestationWindow": "evidence",
        "RevocationRecord": "issuer",
    }
)


def primary_signer_namespace(record_type: str) -> PrimarySignerNamespace:
    """Return the role assigned by ES-033, with no permissive fallback."""

    try:
        return PRIMARY_SIGNER_NAMESPACE[record_type]
    except KeyError as exc:
        raise ValueError(
            f"record type {record_type!r} has no ES-033 origin classification"
        ) from exc
