import assert from "node:assert/strict";
import { test } from "node:test";
import { EvidenceEmitter, RECORD_TYPES, decodeBase64Url, verifyStream, type JsonObject, type RecordBodyMap, type RecordType } from "../src/index.ts";

const timestamp = "2026-08-01T12:00:00.000+01:00";
const digest = `sha256:${"0".repeat(64)}` as const;
const seed = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const publicKey = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik";

const bodies: Record<RecordType, JsonObject> = {
  AssuranceBoundary: { boundary_version: "1", tenant: "tenant-1", deployment: "prod", agent_identities: [], action_families: [], destination_systems: [], enforcement_points: [], policy_refs: [], window_start: timestamp, window_end: timestamp, collection_modes: [], fail_behaviour: {}, qualification_refs: [] },
  QualificationRecord: { action_family: "crm.write", destination_system: "crm", enumeration: {}, identity_isolation: {}, confirmation: {}, temporal: {}, retention_period: "P1Y", mutability: {}, assigned_class: "C1", class_evidence: [], trial: {}, qualified_at: timestamp, revalidation_cadence: "P30D" },
  PopulationRecord: { action_family: "crm.write", destination_system: "crm", window_start: timestamp, window_end: timestamp, enumeration_query: {}, record_identifiers: [], count: 0, pagination_complete: true, result_cap_hit: false, retrieved_at: timestamp, authoritative_timestamps: {} },
  AgentIdentity: { agent_id: "agent-1", deployment: "prod", runtime: "node-22", tenant_scope: "tenant-1", service_identity: "collector@example.invalid", model_versions: [], tool_versions: [], credential_ref: "service_identity" },
  ActionProposal: { action_family: "crm.write", action_id: "action-1", tool: "crm", parameters_digest: digest, purpose: "test", target_ref: "target-1", risk_class: "low", proposed_at: timestamp },
  AuthorityDecision: { action_id: "action-1", decision: "grant", policy_ref: "policy-1", policy_version: "1", constraints: [], decided_by: "policy-engine", decided_at: timestamp },
  HumanReview: { action_id: "action-1", reviewer_identity: "reviewer-1", reviewer_authority: { role: "approver", authorised: true }, surface: { name: "review", version: "1" }, evidence_shown: digest, evidence_shown_refs: [], options_offered: ["approve", "deny"], time_available_ms: 30000, time_taken_ms: 1000, decision: "approve", modifications: {}, action_state_at_review: "proposed", decided_at: timestamp, evidence_shown_provenance: "client_rendered" },
  ExecutionReceipt: { action_id: "action-1", dispatch_attempt: 1, connector_identity: "connector-1", connector_version: "1", destination_response_digest: digest, destination_record_ref: "destination-1", status: "accepted", dispatched_at: timestamp, responded_at: timestamp },
  ExternalConfirmation: { action_id: "action-1", destination_system: "crm", destination_record_id: "destination-1", destination_record_digest: digest, authoritative_timestamp: timestamp, reconciliation_status: "matched", retrieved_at: timestamp },
  FinalityRecord: { action_id: "action-1", state: "settled", reversible_until: null, compensation_ref: null, settled_at: timestamp },
  OutcomeRecord: { action_id: "action-1", outcome_contract_ref: "contract-1", authoritative_source: "crm", result: "success", finalised_at: timestamp, disputed: false, reversal_ref: null },
  CoverageGap: { gap_start: timestamp, gap_end: timestamp, affected_scope: {}, cause: "collector_unreachable", detection_source: "sdk", exposure: "unknown", actions_during_gap: null },
  AttestationWindow: { boundary_ref: "boundary-1", window_start: timestamp, window_end: timestamp, methodology_version: "1", denominator_class: "C1", population_record_refs: [], coverage_level: "observed", verification_status: "self_computed", coverage_ratio: "1.0", counts: {}, gaps: [], assertions: [], exclusions: [], relying_parties: [], validity_from: timestamp, validity_until: timestamp, liability_ref: "terms-1", issued_at: timestamp, issuer: "issuer-1", verifier_version: "1", capped_by_class: false },
  RevocationRecord: { attestation_ref: "attestation-1", reason: "superseded", issuer: "issuer-1", effective_at: timestamp, superseding_ref: null, relying_party_notification_status: "pending" },
};

test("the SDK emits and locally signs every section-5 record type", () => {
  const emitter = new EvidenceEmitter({
    tenantId: "tenant-1",
    boundaryRef: "boundary-1",
    streamId: "stream-1",
    source: { collector: "typescript-sdk", version: "0.1.0" },
    keyId: "K1",
    privateKeySeed: seed,
    now: () => timestamp,
  });
  const records = RECORD_TYPES.map((type) => emitter.emit(type, bodies[type] as RecordBodyMap[typeof type]));
  assert.deepEqual(records.map((record) => record.record_type), RECORD_TYPES);
  assert.deepEqual(records.map((record) => record.sequence), RECORD_TYPES.map((_, index) => index + 1));
  assert.ok(records.every((record) => record.signature.alg === "ed25519"));
  const result = verifyStream(records as unknown as JsonObject[], { K1: { namespace: "evidence", public_key: publicKey } });
  assert.equal(result.endSequence, RECORD_TYPES.length);
});

test("CoverageGap emission is entirely local", () => {
  const emitter = new EvidenceEmitter({ tenantId: "tenant-1", boundaryRef: "boundary-1", streamId: "offline", source: { collector: "typescript-sdk", version: "0.1.0" }, keyId: "K1", privateKeySeed: seed, now: () => timestamp });
  const record = emitter.emitCoverageGap(bodies.CoverageGap as RecordBodyMap["CoverageGap"]);
  assert.equal(record.record_type, "CoverageGap");
  assert.equal(decodeBase64Url(record.signature.sig, 64).length, 64);
});
