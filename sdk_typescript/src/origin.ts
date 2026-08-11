import { refuse } from "./errors.ts";
import type { JsonValue } from "./json.ts";
import type { RecordType, VerificationKey } from "./types.ts";

export type PrimarySignerNamespace = VerificationKey["namespace"];

/** Closed ES-033 dispatch: a future record type has no signing default. */
export const PRIMARY_SIGNER_NAMESPACE = Object.freeze({
  AssuranceBoundary: "evidence",
  QualificationRecord: "evidence",
  PopulationRecord: "issuer",
  AgentIdentity: "evidence",
  ActionProposal: "evidence",
  AuthorityDecision: "evidence",
  HumanReview: "evidence",
  ExecutionReceipt: "evidence",
  ExternalConfirmation: "issuer",
  FinalityRecord: "evidence",
  OutcomeRecord: "evidence",
  CoverageGap: "evidence",
  AttestationWindow: "evidence",
  RevocationRecord: "issuer",
} satisfies Record<RecordType, PrimarySignerNamespace>);

export function primarySignerNamespace(recordType: JsonValue | undefined): PrimarySignerNamespace {
  if (typeof recordType !== "string" || !Object.hasOwn(PRIMARY_SIGNER_NAMESPACE, recordType)) {
    return refuse("schema.record_type_unknown", "record_type has no ES-033 origin classification");
  }
  return PRIMARY_SIGNER_NAMESPACE[recordType as RecordType];
}
