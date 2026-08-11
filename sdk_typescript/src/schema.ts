import { refuse } from "./errors.ts";
import { MAX_JSON_NESTING_DEPTH, type JsonObject, type JsonValue } from "./json.ts";
import { RECORD_TYPES, type RecordType } from "./types.ts";

const ENVELOPE_MEMBERS = new Set([
  "record_id", "record_type", "schema_version", "tenant_id", "boundary_ref", "stream_id",
  "sequence", "prev_digest", "source", "clocks", "body", "signature",
]);

const REQUIRED_ENVELOPE_MEMBERS = [
  "record_id", "record_type", "schema_version", "tenant_id", "stream_id", "sequence",
  "prev_digest", "source", "clocks", "body",
];

const REQUIRED_BODY_MEMBERS: Record<RecordType, readonly string[]> = {
  AssuranceBoundary: ["boundary_version", "tenant", "deployment", "agent_identities", "action_families", "destination_systems", "enforcement_points", "policy_refs", "window_start", "window_end", "collection_modes", "fail_behaviour", "qualification_refs"],
  QualificationRecord: ["action_family", "destination_system", "enumeration", "identity_isolation", "confirmation", "temporal", "retention_period", "mutability", "assigned_class", "class_evidence", "trial", "qualified_at", "revalidation_cadence"],
  PopulationRecord: ["action_family", "destination_system", "window_start", "window_end", "enumeration_query", "count", "pagination_complete", "result_cap_hit", "retrieved_at", "authoritative_timestamps"],
  AgentIdentity: ["agent_id", "deployment", "runtime", "tenant_scope", "service_identity", "model_versions", "tool_versions", "credential_ref"],
  ActionProposal: ["action_family", "action_id", "tool", "parameters_digest", "purpose", "target_ref", "risk_class", "proposed_at"],
  AuthorityDecision: ["action_id", "decision", "policy_ref", "policy_version", "constraints", "decided_by", "decided_at"],
  HumanReview: ["action_id", "reviewer_identity", "reviewer_authority", "surface", "evidence_shown", "evidence_shown_refs", "options_offered", "time_available_ms", "time_taken_ms", "decision", "modifications", "action_state_at_review", "decided_at"],
  ExecutionReceipt: ["action_id", "dispatch_attempt", "connector_identity", "connector_version", "destination_response_digest", "destination_record_ref", "status", "dispatched_at", "responded_at"],
  ExternalConfirmation: ["action_id", "destination_system", "destination_record_id", "destination_record_digest", "authoritative_timestamp", "reconciliation_status", "retrieved_at"],
  FinalityRecord: ["action_id", "state", "reversible_until", "compensation_ref", "settled_at"],
  OutcomeRecord: ["action_id", "outcome_contract_ref", "authoritative_source", "result", "finalised_at", "disputed", "reversal_ref"],
  CoverageGap: ["gap_start", "gap_end", "affected_scope", "cause", "detection_source", "exposure", "actions_during_gap"],
  AttestationWindow: ["boundary_ref", "window_start", "window_end", "methodology_version", "denominator_class", "population_record_refs", "coverage_level", "verification_status", "coverage_ratio", "counts", "gaps", "assertions", "exclusions", "relying_parties", "validity_from", "validity_until", "liability_ref", "issued_at", "issuer", "verifier_version", "capped_by_class"],
  RevocationRecord: ["attestation_ref", "reason", "issuer", "effective_at", "superseding_ref", "relying_party_notification_status"],
};

const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
const UUID_V7_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const RFC3339_MILLISECONDS_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3,}(?:Z|[+-]\d{2}:\d{2})$/;

export interface ValidationOptions {
  requireSignature?: boolean;
  validateBody?: boolean;
}

export function validateRecord(record: JsonObject, options: ValidationOptions = {}): void {
  for (const key of Object.keys(record)) {
    if (!ENVELOPE_MEMBERS.has(key)) refuse("schema.unknown_envelope_field", `unknown envelope field: ${key}`);
  }
  for (const key of REQUIRED_ENVELOPE_MEMBERS) requireMember(record, key, "schema.missing_envelope_field");
  if (options.requireSignature) requireMember(record, "signature", "signature.missing_customer_member");

  if (typeof record.record_type !== "string" || !RECORD_TYPES.includes(record.record_type as RecordType)) {
    refuse("schema.record_type_unknown", "record_type is not defined by evidence-spec section 5");
  }
  const type = record.record_type as RecordType;
  if (typeof record.schema_version !== "string" || !/^\d+\.\d+\.\d+$/.test(record.schema_version)) {
    refuse("schema.version_invalid", "schema_version must be semver");
  }
  const major = Number.parseInt(record.schema_version.split(".")[0]!, 10);
  if (major === 1) {
    requireMember(record, "boundary_ref", "schema.boundary_ref_required");
  } else if (major === 2) {
    if (type === "QualificationRecord") {
      if (Object.hasOwn(record, "boundary_ref")) refuse("schema.boundary_ref_forbidden", "schema-2 QualificationRecord must omit boundary_ref");
    } else {
      requireMember(record, "boundary_ref", "schema.boundary_ref_required");
    }
  } else {
    refuse("schema.version_unsupported", `unsupported schema major ${major}`);
  }

  if (typeof record.record_id !== "string" || !UUID_V7_PATTERN.test(record.record_id)) {
    refuse("schema.record_id_invalid", "record_id must be a lowercase UUIDv7");
  }
  if (!Number.isSafeInteger(record.sequence) || (record.sequence as number) < 1) {
    refuse("schema.sequence_invalid", "sequence must be a positive safe integer");
  }
  if (record.prev_digest !== null && !isDigest(record.prev_digest)) {
    refuse("schema.digest_invalid", "prev_digest must be null or an ES-003 digest");
  }
  if (!isObject(record.clocks)) refuse("schema.clocks_invalid", "clocks must be an object");
  const clocks = record.clocks;
  if (Object.hasOwn(clocks, "ingest_time") || Object.hasOwn(clocks, "clock_skew_ms")) {
    refuse("schema.hosted_clock_field_forbidden", "hosted clock fields belong only in the issuer receipt");
  }
  requireMember(clocks, "source_time", "schema.source_time_required");
  assertTimestamp(clocks.source_time, "source_time");
  if (Object.hasOwn(clocks, "authoritative_time")) {
    if (clocks.authoritative_time === null) refuse("schema.optional_null_forbidden", "authoritative_time must be absent rather than null");
    assertTimestamp(clocks.authoritative_time, "authoritative_time");
  }

  if (!isObject(record.body)) refuse("schema.body_invalid", "body must be an object");
  if (type === "ActionProposal" && Object.hasOwn(record.body, "parameters") && record.body.parameters === null) {
    refuse("schema.optional_null_forbidden", "parameters must be absent rather than null");
  }
  if (type === "HumanReview" && record.body.evidence_shown_provenance !== undefined) {
    if (record.body.evidence_shown_provenance !== "client_rendered" && record.body.evidence_shown_provenance !== "server_reconstructed") {
      refuse("schema.evidence_shown_provenance_invalid", "unknown evidence_shown provenance");
    }
  }
  if (options.validateBody !== false) validateBody(type, record.body);
  assertJsonValue(record);
}

function validateBody(type: RecordType, body: JsonObject): void {
  for (const key of REQUIRED_BODY_MEMBERS[type]) requireMember(body, key, "schema.missing_body_field");
  if (type === "PopulationRecord") {
    const identifiers = Object.hasOwn(body, "record_identifiers");
    const digest = Object.hasOwn(body, "identifier_digest");
    if (identifiers === digest) refuse("schema.population_identifiers_invalid", "exactly one population identifier representation is required");
  }
  if (type === "ExternalConfirmation") {
    const statuses = new Set(["matched", "unmatched_with_evidence", "unmatched_without_evidence", "duplicate", "ambiguous", "out_of_scope"]);
    if (!statuses.has(String(body.reconciliation_status))) refuse("schema.reconciliation_status_invalid", "reconciliation_status is closed");
  }
  if (type === "AttestationWindow") {
    if ((body.denominator_class === "C4" || body.denominator_class === "C5") && body.coverage_ratio !== null) {
      refuse("schema.coverage_ratio_must_be_null", "C4/C5 coverage_ratio must be explicit null");
    }
  }
}

export function assertTimestamp(value: JsonValue | undefined, field: string): asserts value is string {
  if (typeof value !== "string" || !RFC3339_MILLISECONDS_PATTERN.test(value)) {
    refuse("schema.timestamp_invalid", `${field} must be RFC 3339 with explicit offset and millisecond precision`);
  }
}

export function isDigest(value: JsonValue | undefined): value is string {
  return typeof value === "string" && DIGEST_PATTERN.test(value);
}

export function isObject(value: JsonValue | undefined): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function requireMember(object: JsonObject, key: string, code: string): void {
  if (!Object.hasOwn(object, key) || object[key] === undefined) refuse(code, `missing required member: ${key}`);
}

function assertJsonValue(value: unknown, path = "$", seen = new Set<object>(), depth = 0): asserts value is JsonValue {
  if (depth > MAX_JSON_NESTING_DEPTH) {
    refuse("canonicalization.nesting_too_deep", `JSON nesting exceeds ${MAX_JSON_NESTING_DEPTH}`);
  }
  if (value === null || typeof value === "string" || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isFinite(value) || !Number.isInteger(value)) refuse("canonicalization.float_forbidden", `${path} contains a forbidden number`);
    if (!Number.isSafeInteger(value)) refuse("canonicalization.integer_out_of_range", `${path} contains an out-of-range integer`);
    return;
  }
  if (typeof value !== "object") refuse("canonicalization.unsupported_value", `${path} is not JSON`);
  if (seen.has(value)) refuse("canonicalization.cyclic_value", `${path} is cyclic`);
  seen.add(value);
  if (Array.isArray(value)) value.forEach((item, index) => assertJsonValue(item, `${path}[${index}]`, seen, depth + 1));
  else Object.entries(value).forEach(([key, item]) => assertJsonValue(item, `${path}.${key}`, seen, depth + 1));
  seen.delete(value);
}
