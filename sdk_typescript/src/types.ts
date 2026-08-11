import type { JsonObject, JsonValue } from "./json.ts";

export const RECORD_TYPES = [
  "AssuranceBoundary",
  "QualificationRecord",
  "PopulationRecord",
  "AgentIdentity",
  "ActionProposal",
  "AuthorityDecision",
  "HumanReview",
  "ExecutionReceipt",
  "ExternalConfirmation",
  "FinalityRecord",
  "OutcomeRecord",
  "CoverageGap",
  "AttestationWindow",
  "RevocationRecord",
] as const;

export type RecordType = (typeof RECORD_TYPES)[number];
export type Digest = `sha256:${string}`;
export type Rfc3339Timestamp = string;

export interface Source extends JsonObject {
  collector: string;
  version: string;
  deployment?: string;
  implementation?: string;
}

export interface CustomerClocks extends JsonObject {
  source_time: Rfc3339Timestamp;
  authoritative_time?: Rfc3339Timestamp;
}

export interface CustomerSignature extends JsonObject {
  alg: "ed25519";
  key_id: string;
  sig: string;
  signed_digest: Digest;
  key_continuity?: KeyContinuity;
  issuer?: IssuerSignature;
}

export interface IssuerSignature extends JsonObject {
  alg: "ed25519";
  key_id: string;
  sig: string;
  signed_digest: Digest;
}

export interface KeyContinuity extends JsonObject {
  alg: "ed25519";
  predecessor_key_id: string;
  new_key_id: string;
  new_public_key: string;
  tenant_id: string;
  stream_id: string;
  sig: string;
}

export interface AssuranceBoundaryBody extends JsonObject {
  boundary_version: string | number;
  tenant: string;
  deployment: string;
  agent_identities: JsonValue[];
  action_families: JsonValue[];
  destination_systems: JsonValue[];
  enforcement_points: JsonValue[];
  policy_refs: JsonValue[];
  window_start: Rfc3339Timestamp;
  window_end: Rfc3339Timestamp;
  collection_modes: JsonValue[];
  fail_behaviour: JsonValue;
  qualification_refs: JsonValue[];
}

export interface QualificationRecordBody extends JsonObject {
  action_family: string;
  destination_system: string;
  enumeration: JsonObject;
  identity_isolation: JsonObject;
  confirmation: JsonObject;
  temporal: JsonObject;
  retention_period: JsonValue;
  mutability: JsonObject;
  assigned_class: "C1" | "C2" | "C3" | "C4" | "C5";
  class_evidence: JsonValue;
  trial: JsonObject;
  qualified_at: Rfc3339Timestamp;
  revalidation_cadence: JsonValue;
}

interface PopulationCommon extends JsonObject {
  action_family: string;
  destination_system: string;
  window_start: Rfc3339Timestamp;
  window_end: Rfc3339Timestamp;
  enumeration_query: JsonValue;
  count: number;
  pagination_complete: boolean;
  result_cap_hit: boolean;
  retrieved_at: Rfc3339Timestamp;
  authoritative_timestamps: JsonObject;
}

export type PopulationRecordBody = PopulationCommon & (
  | { record_identifiers: JsonValue[]; identifier_digest?: never }
  | { identifier_digest: Digest; record_identifiers?: never }
);

export interface AgentIdentityBody extends JsonObject {
  agent_id: string;
  deployment: string;
  runtime: string;
  tenant_scope: string;
  service_identity: string;
  model_versions: JsonValue[];
  tool_versions: JsonValue[];
  credential_ref: string;
}

export interface ActionProposalBody extends JsonObject {
  action_family: string;
  action_id: string;
  tool: string;
  parameters_digest: Digest;
  parameters?: JsonValue;
  purpose: string;
  target_ref: string;
  risk_class: string;
  proposed_at: Rfc3339Timestamp;
}

export interface AuthorityDecisionBody extends JsonObject {
  action_id: string;
  decision: "grant" | "deny" | "review_required";
  policy_ref: string;
  policy_version: string;
  constraints: JsonValue[];
  decided_by: string;
  decided_at: Rfc3339Timestamp;
}

export type ReviewActionState = "proposed" | "dispatched" | "accepted" | "committed" | "reversible" | "irreversible";
export type ReviewOption = "approve" | "deny" | "modify" | "escalate" | "stop" | "reverse" | "compensate";
export type EvidenceShownProvenance = "client_rendered" | "server_reconstructed";

export interface HumanReviewBody extends JsonObject {
  action_id: string;
  reviewer_identity: JsonValue;
  reviewer_authority: JsonValue;
  surface: JsonValue;
  evidence_shown: Digest;
  evidence_shown_refs: JsonValue[];
  options_offered: ReviewOption[];
  time_available_ms: number;
  time_taken_ms: number;
  decision: JsonValue;
  modifications: JsonValue;
  action_state_at_review: ReviewActionState;
  decided_at: Rfc3339Timestamp;
  evidence_shown_provenance?: EvidenceShownProvenance;
}

export interface ExecutionReceiptBody extends JsonObject {
  action_id: string;
  dispatch_attempt: number;
  connector_identity: string;
  connector_version: string;
  destination_response_digest: Digest;
  destination_record_ref: string;
  status: string;
  dispatched_at: Rfc3339Timestamp;
  responded_at: Rfc3339Timestamp;
}

export interface ExternalConfirmationBody extends JsonObject {
  action_id: string;
  destination_system: string;
  destination_record_id: string;
  destination_record_digest: Digest;
  authoritative_timestamp: Rfc3339Timestamp;
  reconciliation_status: "matched" | "unmatched_with_evidence" | "unmatched_without_evidence" | "duplicate" | "ambiguous" | "out_of_scope";
  retrieved_at: Rfc3339Timestamp;
}

export interface FinalityRecordBody extends JsonObject {
  action_id: string;
  state: string;
  reversible_until: Rfc3339Timestamp | null;
  compensation_ref: string | null;
  settled_at: Rfc3339Timestamp;
}

export interface OutcomeRecordBody extends JsonObject {
  action_id: string;
  outcome_contract_ref: string;
  authoritative_source: string;
  result: JsonValue;
  finalised_at: Rfc3339Timestamp;
  disputed: boolean;
  reversal_ref: string | null;
}

export interface CoverageGapBody extends JsonObject {
  gap_start: Rfc3339Timestamp;
  gap_end: Rfc3339Timestamp;
  affected_scope: JsonValue;
  cause: "collector_unreachable" | "fail_open" | "sequence_break" | "denominator_unavailable" | "clock_skew" | "key_discontinuity";
  detection_source: string;
  exposure: "known" | "estimated_bounds" | "unknown";
  actions_during_gap: number | null;
}

export interface AttestationWindowBody extends JsonObject {
  boundary_ref: string;
  window_start: Rfc3339Timestamp;
  window_end: Rfc3339Timestamp;
  methodology_version: string;
  denominator_class: "C1" | "C2" | "C3" | "C4" | "C5";
  population_record_refs: JsonValue[];
  coverage_level: string;
  verification_status: "self_computed" | "independently_reproduced";
  coverage_ratio: JsonValue | null;
  counts: JsonObject;
  gaps: JsonValue[];
  assertions: JsonValue[];
  exclusions: JsonValue[];
  relying_parties: JsonValue;
  validity_from: Rfc3339Timestamp;
  validity_until: Rfc3339Timestamp;
  liability_ref: string;
  issued_at: Rfc3339Timestamp;
  issuer: JsonValue;
  verifier_version: string;
  capped_by_class: boolean;
}

export interface RevocationRecordBody extends JsonObject {
  attestation_ref: string;
  reason: string;
  issuer: JsonValue;
  effective_at: Rfc3339Timestamp;
  superseding_ref: string | null;
  relying_party_notification_status: JsonValue;
}

export interface RecordBodyMap {
  AssuranceBoundary: AssuranceBoundaryBody;
  QualificationRecord: QualificationRecordBody;
  PopulationRecord: PopulationRecordBody;
  AgentIdentity: AgentIdentityBody;
  ActionProposal: ActionProposalBody;
  AuthorityDecision: AuthorityDecisionBody;
  HumanReview: HumanReviewBody;
  ExecutionReceipt: ExecutionReceiptBody;
  ExternalConfirmation: ExternalConfirmationBody;
  FinalityRecord: FinalityRecordBody;
  OutcomeRecord: OutcomeRecordBody;
  CoverageGap: CoverageGapBody;
  AttestationWindow: AttestationWindowBody;
  RevocationRecord: RevocationRecordBody;
}

export interface UnsignedEvidenceRecord<T extends RecordType = RecordType> extends JsonObject {
  record_id: string;
  record_type: T;
  schema_version: string;
  tenant_id: string;
  boundary_ref?: string;
  stream_id: string;
  sequence: number;
  prev_digest: Digest | null;
  source: Source;
  clocks: CustomerClocks;
  body: RecordBodyMap[T];
}

export interface SignedEvidenceRecord<T extends RecordType = RecordType> extends UnsignedEvidenceRecord<T> {
  signature: CustomerSignature;
}

export interface VerificationKey {
  namespace: "evidence" | "issuer";
  public_key: string;
}

export type VerificationKeyring = Record<string, VerificationKey>;
