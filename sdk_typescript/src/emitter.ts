import { randomBytes } from "node:crypto";
import { digestJson } from "./crypto.ts";
import { refuse } from "./errors.ts";
import type { JsonObject } from "./json.ts";
import { signRecord } from "./signing.ts";
import type {
  ActionProposalBody, AgentIdentityBody, AssuranceBoundaryBody, AttestationWindowBody,
  AuthorityDecisionBody, CoverageGapBody, CustomerClocks, ExecutionReceiptBody,
  ExternalConfirmationBody, FinalityRecordBody, HumanReviewBody, OutcomeRecordBody,
  PopulationRecordBody, QualificationRecordBody, RecordBodyMap, RecordType,
  RevocationRecordBody, SignedEvidenceRecord, Source, UnsignedEvidenceRecord,
} from "./types.ts";

export interface EmitterOptions {
  tenantId: string;
  boundaryRef?: string;
  streamId: string;
  source: Source;
  keyId: string;
  privateKeySeed: Uint8Array | string;
  schemaVersion?: string;
  now?: () => string;
  recordId?: () => string;
}

export interface EmitOverrides {
  clocks?: CustomerClocks;
  recordId?: string;
  boundaryRef?: string;
}

/** Stateful, synchronous local writer. No hosted service is involved in emission. */
export class EvidenceEmitter {
  private sequence = 0;
  private previousDigest: `sha256:${string}` | null = null;
  private readonly options: EmitterOptions;

  constructor(options: EmitterOptions) {
    this.options = options;
  }

  emit<T extends RecordType>(recordType: T, body: RecordBodyMap[T], overrides: EmitOverrides = {}): SignedEvidenceRecord<T> {
    const sequence = this.sequence + 1;
    const schemaVersion = this.options.schemaVersion ?? "1.0.0";
    const boundaryRef = overrides.boundaryRef ?? this.options.boundaryRef;
    const unsigned: Record<string, unknown> = {
      record_id: overrides.recordId ?? (this.options.recordId ?? uuidV7)(),
      record_type: recordType,
      schema_version: schemaVersion,
      tenant_id: this.options.tenantId,
      stream_id: this.options.streamId,
      sequence,
      prev_digest: this.previousDigest,
      source: this.options.source,
      clocks: overrides.clocks ?? { source_time: (this.options.now ?? nowRfc3339)() },
      body,
    };
    const major = Number.parseInt(schemaVersion.split(".")[0]!, 10);
    if (!(major === 2 && recordType === "QualificationRecord")) {
      if (boundaryRef === undefined) refuse("schema.boundary_ref_required", `${recordType} requires boundaryRef`);
      unsigned.boundary_ref = boundaryRef;
    }
    const signed = signRecord(unsigned as unknown as UnsignedEvidenceRecord<T>, this.options.keyId, this.options.privateKeySeed);
    this.sequence = sequence;
    this.previousDigest = digestJson(signed as unknown as JsonObject) as `sha256:${string}`;
    return signed as SignedEvidenceRecord<T>;
  }

  emitAssuranceBoundary(body: AssuranceBoundaryBody, overrides?: EmitOverrides) { return this.emit("AssuranceBoundary", body, overrides); }
  emitQualificationRecord(body: QualificationRecordBody, overrides?: EmitOverrides) { return this.emit("QualificationRecord", body, overrides); }
  emitPopulationRecord(body: PopulationRecordBody, overrides?: EmitOverrides) { return this.emit("PopulationRecord", body, overrides); }
  emitAgentIdentity(body: AgentIdentityBody, overrides?: EmitOverrides) { return this.emit("AgentIdentity", body, overrides); }
  emitActionProposal(body: ActionProposalBody, overrides?: EmitOverrides) { return this.emit("ActionProposal", body, overrides); }
  emitAuthorityDecision(body: AuthorityDecisionBody, overrides?: EmitOverrides) { return this.emit("AuthorityDecision", body, overrides); }
  emitHumanReview(body: HumanReviewBody, overrides?: EmitOverrides) { return this.emit("HumanReview", body, overrides); }
  emitExecutionReceipt(body: ExecutionReceiptBody, overrides?: EmitOverrides) { return this.emit("ExecutionReceipt", body, overrides); }
  emitExternalConfirmation(body: ExternalConfirmationBody, overrides?: EmitOverrides) { return this.emit("ExternalConfirmation", body, overrides); }
  emitFinalityRecord(body: FinalityRecordBody, overrides?: EmitOverrides) { return this.emit("FinalityRecord", body, overrides); }
  emitOutcomeRecord(body: OutcomeRecordBody, overrides?: EmitOverrides) { return this.emit("OutcomeRecord", body, overrides); }
  emitCoverageGap(body: CoverageGapBody, overrides?: EmitOverrides) { return this.emit("CoverageGap", body, overrides); }
  emitAttestationWindow(body: AttestationWindowBody, overrides?: EmitOverrides) { return this.emit("AttestationWindow", body, overrides); }
  emitRevocationRecord(body: RevocationRecordBody, overrides?: EmitOverrides) { return this.emit("RevocationRecord", body, overrides); }
}

export function uuidV7(now = Date.now(), entropy = randomBytes(10)): string {
  if (!Number.isSafeInteger(now) || now < 0 || now > 0xffffffffffff) refuse("schema.uuid_time_invalid", "UUIDv7 time must fit 48 bits");
  if (entropy.length !== 10) refuse("schema.uuid_entropy_invalid", "UUIDv7 requires 10 entropy bytes");
  const bytes = new Uint8Array(16);
  let milliseconds = BigInt(now);
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = Number(milliseconds & 0xffn);
    milliseconds >>= 8n;
  }
  bytes.set(entropy, 6);
  bytes[6] = 0x70 | (bytes[6]! & 0x0f);
  bytes[8] = 0x80 | (bytes[8]! & 0x3f);
  const hex = Buffer.from(bytes).toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function nowRfc3339(): string {
  return new Date().toISOString();
}
