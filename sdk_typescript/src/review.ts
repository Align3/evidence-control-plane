import { refuse } from "./errors.ts";
import type { Digest, EvidenceShownProvenance } from "./types.ts";

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
export async function clientRenderedEvidence(rendered: RenderedEvidence): Promise<EvidenceShownCapture> {
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
