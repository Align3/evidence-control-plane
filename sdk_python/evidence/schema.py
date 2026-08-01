"""Typed evidence record envelopes and every body defined in spec §5."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import date
from typing import Annotated, ClassVar, Literal, Never
from uuid import UUID

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

from sdk_python.evidence.canonical import MAX_SAFE_INTEGER, canonicalize

type JsonScalar = None | bool | int | str
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]
type JsonObject = dict[str, JsonValue]

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SEMVER_RE = re.compile(
    r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_TIMESTAMP_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})"
    r"\.(\d{3,})(Z|[+-](\d{2}):(\d{2}))$"
)

ENVELOPE_FIELDS = frozenset(
    {
        "record_id",
        "record_type",
        "schema_version",
        "tenant_id",
        "boundary_ref",
        "stream_id",
        "sequence",
        "prev_digest",
        "source",
        "clocks",
        "body",
        "signature",
    }
)


class EnvelopeValidationError(ValueError):
    """Raised when the closed record envelope cannot be verified."""


def _assert_json_value(value: object, path: str = "record") -> None:
    if value is None or isinstance(value, (bool, str)):
        if isinstance(value, str):
            for character in value:
                if 0xD800 <= ord(character) <= 0xDFFF:
                    raise ValueError(f"{path} contains a lone Unicode surrogate")
        return
    if isinstance(value, float):
        raise ValueError(f"IEEE-754 floats are forbidden in signed records ({path})")
    if isinstance(value, int):
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise ValueError(f"{path} contains an integer outside the interoperable JCS range")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _assert_json_value(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{path} contains a non-string JSON object key")
            _assert_json_value(item, f"{path}.{key}")
        return
    if isinstance(value, BaseModel):
        _assert_json_value(value.model_dump(mode="json", exclude_unset=True), path)
        return
    raise ValueError(f"{path} contains unsupported JSON type {type(value).__name__}")


def _uuid7(value: str) -> str:
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise ValueError("record_id must be a lowercase UUIDv7") from exc
    if parsed.version != 7 or str(parsed) != value:
        raise ValueError("record_id must be a lowercase UUIDv7")
    return value


def _digest(value: str) -> str:
    if _DIGEST_RE.fullmatch(value) is None:
        raise ValueError("digest must be lowercase sha256:<64 hex characters>")
    return value


def _semver(value: str) -> str:
    if _SEMVER_RE.fullmatch(value) is None:
        raise ValueError("schema_version must be semantic version syntax")
    return value


def _timestamp(value: str) -> str:
    match = _TIMESTAMP_RE.fullmatch(value)
    if match is None:
        raise ValueError("timestamp must be RFC 3339 with offset and millisecond precision")
    year, month, day, hour, minute, second = (int(part) for part in match.groups()[:6])
    try:
        date(year, month, day)
    except ValueError as exc:
        raise ValueError("timestamp contains an invalid calendar date") from exc
    if hour > 23 or minute > 59 or second > 60:
        raise ValueError("timestamp contains an invalid time")
    offset_hour, offset_minute = match.group(9), match.group(10)
    if offset_hour is not None and (int(offset_hour) > 23 or int(offset_minute) > 59):
        raise ValueError("timestamp contains an invalid UTC offset")
    return value


UUID7 = Annotated[str, AfterValidator(_uuid7)]
Digest = Annotated[str, AfterValidator(_digest)]
SemVer = Annotated[str, AfterValidator(_semver)]
Timestamp = Annotated[str, AfterValidator(_timestamp)]
PositiveInteger = Annotated[int, Field(ge=1, le=MAX_SAFE_INTEGER)]
NonNegativeInteger = Annotated[int, Field(ge=0, le=MAX_SAFE_INTEGER)]
SafeInteger = Annotated[int, Field(ge=-MAX_SAFE_INTEGER, le=MAX_SAFE_INTEGER)]


class JsonModel(BaseModel):
    model_config = ConfigDict(strict=True)

    #: Fields the specification marks optional *by presence*, as opposed to the
    #: fields that are required but nullable by lifecycle state. Absence and an
    #: explicit null would otherwise be two encodings of one meaning, and since
    #: canonicalisation serializes with ``exclude_unset`` they would produce
    #: different canonical bytes — hence different digests — for records that
    #: are semantically identical and compare equal. Only one encoding is
    #: canonical: omit the member.
    presence_optional_fields: ClassVar[frozenset[str]] = frozenset()

    @model_validator(mode="before")
    @classmethod
    def contains_only_json_values(cls, value: object) -> object:
        _assert_json_value(value)
        if isinstance(value, dict):
            for name in cls.presence_optional_fields:
                if name in value and value[name] is None:
                    raise ValueError(
                        f"{name} is optional by presence: omit the member rather than "
                        "encoding it as null, so that one record has one canonical form"
                    )
        return value

    @model_validator(mode="after")
    def absent_optional_fields_are_never_serialized(self) -> JsonModel:
        # Direct Python construction with ``field=None`` reaches this point with
        # the field marked as set. Clearing it keeps the canonical bytes a pure
        # function of the record's content rather than of how it was built.
        for name in self.presence_optional_fields:
            if getattr(self, name, None) is None:
                self.__pydantic_fields_set__.discard(name)
        return self


class ClocksModel(JsonModel):
    """ES-019 clock fields. Part of the closed envelope, so extras are refused."""

    model_config = ConfigDict(strict=True, extra="forbid")

    presence_optional_fields: ClassVar[frozenset[str]] = frozenset({"authoritative_time"})

    source_time: Timestamp
    ingest_time: Timestamp
    clock_skew_ms: SafeInteger
    # ES-020: present only where the destination supplies one.
    authoritative_time: Timestamp | None = None


class BodyModel(JsonModel):
    # ES-005: forward-compatible body extensions are retained, not ignored.
    model_config = ConfigDict(strict=True, extra="allow")


class AssuranceBoundaryBody(BodyModel):
    boundary_version: str
    tenant: str
    deployment: str
    agent_identities: list[JsonValue]
    action_families: list[JsonValue]
    destination_systems: list[JsonValue]
    enforcement_points: list[JsonValue]
    policy_refs: list[str]
    window_start: Timestamp
    window_end: Timestamp
    collection_modes: list[str]
    fail_behaviour: JsonObject
    qualification_refs: list[str]


class QualificationRecordBody(BodyModel):
    action_family: str
    destination_system: str
    enumeration: JsonObject
    identity_isolation: JsonObject
    confirmation: JsonObject
    temporal: JsonObject
    retention_period: str
    mutability: JsonObject
    assigned_class: Literal["C1", "C2", "C3", "C4", "C5"]
    class_evidence: JsonValue
    trial: JsonObject
    qualified_at: Timestamp
    revalidation_cadence: str


class PopulationRecordBody(BodyModel):
    presence_optional_fields: ClassVar[frozenset[str]] = frozenset(
        {"record_identifiers", "identifier_digest"}
    )

    action_family: str
    destination_system: str
    window_start: Timestamp
    window_end: Timestamp
    enumeration_query: JsonObject
    record_identifiers: list[str] | None = None
    identifier_digest: Digest | None = None
    count: NonNegativeInteger
    pagination_complete: bool
    result_cap_hit: bool
    retrieved_at: Timestamp
    authoritative_timestamps: JsonObject

    @model_validator(mode="after")
    def has_one_identifier_representation(self) -> PopulationRecordBody:
        if (self.record_identifiers is None) == (self.identifier_digest is None):
            raise ValueError("exactly one of record_identifiers or identifier_digest is required")
        return self


class AgentIdentityBody(BodyModel):
    agent_id: str
    deployment: str
    runtime: str
    tenant_scope: str
    service_identity: str
    model_versions: list[str]
    tool_versions: list[str]
    credential_ref: str


class ActionProposalBody(BodyModel):
    # ES-025: cleartext parameters are absent unless configured in, never null.
    presence_optional_fields: ClassVar[frozenset[str]] = frozenset({"parameters"})

    action_family: str
    action_id: str
    tool: str
    parameters_digest: Digest
    parameters: JsonObject | None = None
    purpose: str
    target_ref: str
    risk_class: str
    proposed_at: Timestamp


class AuthorityDecisionBody(BodyModel):
    action_id: str
    decision: Literal["grant", "deny", "review_required"]
    policy_ref: str
    policy_version: str
    constraints: list[JsonValue]
    decided_by: str
    decided_at: Timestamp


class HumanReviewBody(BodyModel):
    action_id: str
    reviewer_identity: str
    reviewer_authority: JsonObject
    surface: JsonObject
    evidence_shown: Digest
    evidence_shown_refs: list[str]
    options_offered: list[
        Literal["approve", "deny", "modify", "escalate", "stop", "reverse", "compensate"]
    ]
    time_available_ms: NonNegativeInteger
    time_taken_ms: NonNegativeInteger
    decision: str
    modifications: JsonValue
    action_state_at_review: Literal[
        "proposed", "dispatched", "accepted", "committed", "reversible", "irreversible"
    ]
    decided_at: Timestamp


class ExecutionReceiptBody(BodyModel):
    action_id: str
    dispatch_attempt: PositiveInteger
    connector_identity: str
    connector_version: str
    destination_response_digest: Digest
    destination_record_ref: str
    status: str
    dispatched_at: Timestamp
    responded_at: Timestamp


class ExternalConfirmationBody(BodyModel):
    action_id: str
    destination_system: str
    destination_record_id: str
    destination_record_digest: Digest
    authoritative_timestamp: Timestamp
    reconciliation_status: Literal[
        "matched",
        "unmatched_with_evidence",
        "unmatched_without_evidence",
        "duplicate",
        "ambiguous",
        "out_of_scope",
    ]
    retrieved_at: Timestamp


class FinalityRecordBody(BodyModel):
    action_id: str
    state: str
    reversible_until: Timestamp | None
    compensation_ref: str | None
    settled_at: Timestamp


class OutcomeRecordBody(BodyModel):
    action_id: str
    outcome_contract_ref: str
    authoritative_source: str
    result: JsonValue
    finalised_at: Timestamp
    disputed: bool
    reversal_ref: str | None


class CoverageGapBody(BodyModel):
    gap_start: Timestamp
    gap_end: Timestamp
    affected_scope: JsonObject
    cause: Literal[
        "collector_unreachable",
        "fail_open",
        "sequence_break",
        "denominator_unavailable",
        "clock_skew",
        "key_discontinuity",
    ]
    detection_source: str
    exposure: Literal["known", "estimated_bounds", "unknown"]
    actions_during_gap: NonNegativeInteger | None


class AttestationWindowBody(BodyModel):
    boundary_ref: str
    window_start: Timestamp
    window_end: Timestamp
    methodology_version: str
    denominator_class: Literal["C1", "C2", "C3", "C4", "C5"]
    population_record_refs: list[str]
    coverage_level: str
    verification_status: Literal["self_computed", "independently_reproduced"]
    coverage_ratio: str | None
    counts: JsonObject
    gaps: list[JsonValue]
    assertions: list[JsonValue]
    exclusions: list[JsonValue]
    relying_parties: list[JsonValue]
    validity_from: Timestamp
    validity_until: Timestamp
    liability_ref: str
    issued_at: Timestamp
    issuer: JsonValue
    verifier_version: str


class RevocationRecordBody(BodyModel):
    attestation_ref: str
    reason: str
    issuer: JsonValue
    effective_at: Timestamp
    superseding_ref: str | None
    relying_party_notification_status: str


class RecordEnvelope(JsonModel):
    """The closed ES-005 envelope shared by all typed record models."""

    model_config = ConfigDict(strict=True, extra="forbid")

    record_id: UUID7
    record_type: str
    schema_version: SemVer
    tenant_id: str
    boundary_ref: str
    stream_id: str
    sequence: PositiveInteger
    prev_digest: Digest | None
    source: JsonObject
    clocks: ClocksModel
    body: BodyModel
    signature: JsonObject


class AssuranceBoundaryRecord(RecordEnvelope):
    record_type: Literal["AssuranceBoundary"]
    body: AssuranceBoundaryBody


class QualificationRecord(RecordEnvelope):
    record_type: Literal["QualificationRecord"]
    body: QualificationRecordBody


class PopulationRecord(RecordEnvelope):
    record_type: Literal["PopulationRecord"]
    body: PopulationRecordBody


class AgentIdentityRecord(RecordEnvelope):
    record_type: Literal["AgentIdentity"]
    body: AgentIdentityBody


class ActionProposalRecord(RecordEnvelope):
    record_type: Literal["ActionProposal"]
    body: ActionProposalBody


class AuthorityDecisionRecord(RecordEnvelope):
    record_type: Literal["AuthorityDecision"]
    body: AuthorityDecisionBody


class HumanReviewRecord(RecordEnvelope):
    record_type: Literal["HumanReview"]
    body: HumanReviewBody


class ExecutionReceiptRecord(RecordEnvelope):
    record_type: Literal["ExecutionReceipt"]
    body: ExecutionReceiptBody


class ExternalConfirmationRecord(RecordEnvelope):
    record_type: Literal["ExternalConfirmation"]
    body: ExternalConfirmationBody


class FinalityRecord(RecordEnvelope):
    record_type: Literal["FinalityRecord"]
    body: FinalityRecordBody


class OutcomeRecord(RecordEnvelope):
    record_type: Literal["OutcomeRecord"]
    body: OutcomeRecordBody


class CoverageGapRecord(RecordEnvelope):
    record_type: Literal["CoverageGap"]
    body: CoverageGapBody


class AttestationWindowRecord(RecordEnvelope):
    record_type: Literal["AttestationWindow"]
    body: AttestationWindowBody


class RevocationRecord(RecordEnvelope):
    record_type: Literal["RevocationRecord"]
    body: RevocationRecordBody


type EvidenceRecord = (
    AssuranceBoundaryRecord
    | QualificationRecord
    | PopulationRecord
    | AgentIdentityRecord
    | ActionProposalRecord
    | AuthorityDecisionRecord
    | HumanReviewRecord
    | ExecutionReceiptRecord
    | ExternalConfirmationRecord
    | FinalityRecord
    | OutcomeRecord
    | CoverageGapRecord
    | AttestationWindowRecord
    | RevocationRecord
)

_RECORD_MODELS: dict[str, type[RecordEnvelope]] = {
    "AssuranceBoundary": AssuranceBoundaryRecord,
    "QualificationRecord": QualificationRecord,
    "PopulationRecord": PopulationRecord,
    "AgentIdentity": AgentIdentityRecord,
    "ActionProposal": ActionProposalRecord,
    "AuthorityDecision": AuthorityDecisionRecord,
    "HumanReview": HumanReviewRecord,
    "ExecutionReceipt": ExecutionReceiptRecord,
    "ExternalConfirmation": ExternalConfirmationRecord,
    "FinalityRecord": FinalityRecord,
    "OutcomeRecord": OutcomeRecord,
    "CoverageGap": CoverageGapRecord,
    "AttestationWindow": AttestationWindowRecord,
    "RevocationRecord": RevocationRecord,
}


def validate_record(value: Mapping[str, object]) -> EvidenceRecord:
    """Validate a parsed object and dispatch it to its typed §5 record model."""

    # Materialise once: a Mapping whose __iter__ and keys() disagree must not be
    # able to show one set of members to the ES-005 check and another to the model.
    fields = dict(value)

    non_string_fields = [key for key in fields if not isinstance(key, str)]
    if non_string_fields:
        raise EnvelopeValidationError(
            f"unknown envelope field: {', '.join(repr(key) for key in non_string_fields)}"
        )
    unknown_fields = sorted(set(fields) - ENVELOPE_FIELDS)
    if unknown_fields:
        raise EnvelopeValidationError(f"unknown envelope field: {', '.join(unknown_fields)}")

    record_type = fields.get("record_type")
    if not isinstance(record_type, str):
        raise EnvelopeValidationError("record_type is required and must be a string")
    model = _RECORD_MODELS.get(record_type)
    if model is None:
        raise EnvelopeValidationError(f"unknown record_type: {record_type}")
    return model.model_validate(fields)  # type: ignore[return-value]


def _duplicate_safe_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise EnvelopeValidationError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _float_token_is_forbidden(token: str) -> Never:
    raise EnvelopeValidationError(f"IEEE-754 floats are forbidden in signed records: {token}")


def _constant_is_forbidden(token: str) -> Never:
    raise EnvelopeValidationError(f"non-JSON numeric constant is forbidden: {token}")


def parse_record(value: bytes | str | Mapping[str, object]) -> EvidenceRecord:
    """Parse JSON bytes/text or validate an already-decoded record object."""

    if isinstance(value, (bytes, str)):
        decoded: object = json.loads(
            value,
            object_pairs_hook=_duplicate_safe_object,
            parse_float=_float_token_is_forbidden,
            parse_constant=_constant_is_forbidden,
        )
        if not isinstance(decoded, dict):
            raise EnvelopeValidationError("record envelope must be a JSON object")
        return validate_record(decoded)
    return validate_record(value)


def serialize_record(record: RecordEnvelope) -> bytes:
    """Serialize a validated record to authoritative RFC 8785 bytes."""

    return canonicalize(record)
