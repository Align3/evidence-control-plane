import { refuse } from "./errors.ts";
import { assertTimestamp, isDigest } from "./schema.ts";
import type {
  Digest,
  EvidenceShownProvenance,
  HumanReviewBody,
  ReviewActionState,
  ReviewOption,
  Rfc3339Timestamp,
} from "./types.ts";
import type { JsonObject, JsonValue } from "./json.ts";

export type RenderedEvidence = string | Uint8Array;
export type AfterPaint = (capture: () => void) => void;

export interface EvidenceShownCapture {
  evidence_shown: Digest;
  evidence_shown_provenance: EvidenceShownProvenance;
}

export interface ReviewSurfaceInstrumentationOptions {
  /** Reads the client surface. It is invoked after rendering, never on the server payload. */
  readRenderedEvidence: () => RenderedEvidence;
  /** Injectable for tests/non-DOM renderers. Browser default waits until after a paint. */
  afterPaint?: AfterPaint;
}

export interface HumanReviewCaptureInput {
  action_id: string;
  reviewer_identity: string;
  reviewer_authority: JsonObject;
  surface: JsonObject;
  /** Result returned by client instrumentation or the explicit weaker fallback. */
  evidence: EvidenceShownCapture;
  evidence_shown_refs: string[];
  options_offered: ReviewOption[];
  time_available_ms: number;
  time_taken_ms: number;
  decision: string;
  modifications: JsonValue;
  action_state_at_review: ReviewActionState;
  decided_at: Rfc3339Timestamp;
}

/**
 * ES-013 instrumentation boundary. The digest input is read from the rendered
 * client surface after paint; no server data is accepted by capture().
 */
export class ReviewSurfaceInstrumentation {
  private readonly readRenderedEvidence: () => RenderedEvidence;
  private readonly afterPaint: AfterPaint;

  constructor(options: ReviewSurfaceInstrumentationOptions) {
    this.readRenderedEvidence = options.readRenderedEvidence;
    this.afterPaint = options.afterPaint ?? browserAfterPaint;
  }

  capture(): Promise<EvidenceShownCapture> {
    return new Promise((resolve, reject) => {
      this.afterPaint(() => {
        void clientRenderedEvidence(this.readRenderedEvidence()).then(resolve, reject);
      });
    });
  }
}

/** Hash exact bytes read from a client renderer. Strings are UTF-8 without normalization. */
async function clientRenderedEvidence(rendered: RenderedEvidence): Promise<EvidenceShownCapture> {
  return {
    evidence_shown: await digestRenderedBytes(toBytes(rendered)),
    evidence_shown_provenance: "client_rendered",
  };
}

/**
 * Explicitly labels the weaker claim when only a server reconstruction exists.
 * Keeping this separate prevents reconstructed data from entering capture().
 */
export async function serverReconstructedEvidence(reconstructed: RenderedEvidence): Promise<EvidenceShownCapture> {
  return {
    evidence_shown: await digestRenderedBytes(toBytes(reconstructed)),
    evidence_shown_provenance: "server_reconstructed",
  };
}

/**
 * Snapshot every ES-013/014 review property at the decision boundary.
 * Mutable objects owned by the UI are copied so later rendering cannot rewrite
 * the evidence record that the caller is about to sign.
 */
export function captureHumanReview(input: HumanReviewCaptureInput): HumanReviewBody {
  const actionStates = new Set<ReviewActionState>([
    "proposed", "dispatched", "accepted", "committed", "reversible", "irreversible",
  ]);
  if (!actionStates.has(input.action_state_at_review)) {
    refuse("review.action_state_invalid", "action_state_at_review is not a closed ES-014 state");
  }
  if (
    input.evidence.evidence_shown_provenance !== "client_rendered"
    && input.evidence.evidence_shown_provenance !== "server_reconstructed"
  ) {
    refuse("review.evidence_provenance_invalid", "evidence provenance is not an ES-013 value");
  }
  if (!isDigest(input.evidence.evidence_shown)) {
    refuse("review.evidence_digest_invalid", "evidence_shown must be an ES-003 SHA-256 digest");
  }
  assertTimestamp(input.decided_at, "decided_at");
  for (const [field, value] of [
    ["time_available_ms", input.time_available_ms],
    ["time_taken_ms", input.time_taken_ms],
  ] as const) {
    if (!Number.isSafeInteger(value) || value < 0) {
      refuse("review.timing_invalid", `${field} must be a non-negative safe integer`);
    }
  }
  return {
    action_id: input.action_id,
    reviewer_identity: input.reviewer_identity,
    reviewer_authority: cloneJson(input.reviewer_authority) as JsonObject,
    surface: cloneJson(input.surface) as JsonObject,
    evidence_shown: input.evidence.evidence_shown,
    evidence_shown_refs: [...input.evidence_shown_refs],
    options_offered: [...input.options_offered],
    time_available_ms: input.time_available_ms,
    time_taken_ms: input.time_taken_ms,
    decision: input.decision,
    modifications: cloneJson(input.modifications),
    action_state_at_review: input.action_state_at_review,
    decided_at: input.decided_at,
    evidence_shown_provenance: input.evidence.evidence_shown_provenance,
  };
}

function cloneJson(value: JsonValue): JsonValue {
  if (Array.isArray(value)) return value.map(cloneJson);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, cloneJson(item)]));
  }
  return value;
}

function toBytes(value: RenderedEvidence): Uint8Array {
  return typeof value === "string" ? new TextEncoder().encode(value) : new Uint8Array(value);
}

async function digestRenderedBytes(bytes: Uint8Array): Promise<Digest> {
  if (globalThis.crypto?.subtle === undefined) {
    refuse("review.digest_unavailable", "Web Crypto SHA-256 is required on the review surface");
  }
  const owned = Uint8Array.from(bytes);
  const digest = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", owned));
  return `sha256:${Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function browserAfterPaint(capture: () => void): void {
  const requestFrame = globalThis.requestAnimationFrame;
  if (typeof requestFrame !== "function") {
    refuse("review.client_render_unavailable", "capture requires a client render scheduler; use serverReconstructedEvidence for server data");
  }
  requestFrame(() => requestFrame(capture));
}
