import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { test } from "node:test";
import { captureHumanReview, ReviewSurfaceInstrumentation, serverReconstructedEvidence } from "../src/index.ts";
import * as reviewApi from "../src/review.ts";

const fixture = JSON.parse(readFileSync(resolve(import.meta.dirname, "../../tests/fixtures/ev10-rendered-evidence.json"), "utf8"));

test("ES-013 hashes what the client actually rendered after paint", async () => {
  let rendered = fixture.server_reconstruction;
  let afterPaint: (() => void) | undefined;
  const instrumentation = new ReviewSurfaceInstrumentation({
    readRenderedEvidence: () => rendered,
    afterPaint: (capture) => { afterPaint = capture; },
  });

  const pendingCapture = instrumentation.capture();
  rendered = fixture.client_rendered;
  assert.ok(afterPaint, "capture must be deferred to the render boundary");
  afterPaint!();

  const captured = await pendingCapture;
  assert.deepEqual(captured, await captureClientRendered(fixture.client_rendered));
  assert.equal(captured.evidence_shown_provenance, "client_rendered");
  assert.notEqual(captured.evidence_shown, (await serverReconstructedEvidence(fixture.server_reconstruction)).evidence_shown);
});

test("server reconstruction is explicitly labelled and cannot masquerade as rendered evidence", async () => {
  const capture = await serverReconstructedEvidence(fixture.server_reconstruction);
  assert.equal(capture.evidence_shown_provenance, "server_reconstructed");
  assert.equal("clientRenderedEvidence" in reviewApi, false);
});

test("capture refuses without a client render boundary", async () => {
  const instrumentation = new ReviewSurfaceInstrumentation({
    readRenderedEvidence: () => fixture.server_reconstruction,
  });
  await assert.rejects(instrumentation.capture(), { code: "review.client_render_unavailable" });
});

test("EV-11 captures the complete review at the decision boundary", async () => {
  const evidence = await captureClientRendered(fixture.client_rendered);
  const authority = { role: "approver", authorised: true };
  const options = ["approve", "deny"] as const;
  const captured = captureHumanReview({
    action_id: "action-1",
    reviewer_identity: "reviewer-1",
    reviewer_authority: authority,
    surface: { ui: "review", version: "1" },
    evidence,
    evidence_shown_refs: ["proposal-1"],
    options_offered: [...options],
    time_available_ms: 30_000,
    time_taken_ms: 1_000,
    decision: "approve",
    modifications: null,
    action_state_at_review: "proposed",
    decided_at: "2026-08-01T10:00:00.000Z",
  });

  authority.authorised = false;
  assert.equal(captured.reviewer_authority.authorised, true, "capture must snapshot mutable UI state");
  assert.equal(captured.evidence_shown, evidence.evidence_shown);
  assert.equal(captured.evidence_shown_provenance, "client_rendered");
  assert.deepEqual(captured.options_offered, ["approve", "deny"]);
  assert.equal(captured.action_state_at_review, "proposed");
});

test("EV-11 capture refuses invalid timing rather than emitting a misleading record", async () => {
  const evidence = await captureClientRendered(fixture.client_rendered);
  assert.throws(() => captureHumanReview({
    action_id: "action-1",
    reviewer_identity: "reviewer-1",
    reviewer_authority: { role: "approver", authorised: true },
    surface: { ui: "review", version: "1" },
    evidence,
    evidence_shown_refs: [],
    options_offered: ["approve"],
    time_available_ms: 1_000,
    time_taken_ms: -1,
    decision: "approve",
    modifications: null,
    action_state_at_review: "proposed",
    decided_at: "2026-08-01T10:00:00.000Z",
  }), { code: "review.timing_invalid" });
});

test("EV-11 capture refuses fabricated state and provenance values at runtime", async () => {
  const evidence = await captureClientRendered(fixture.client_rendered);
  const base = {
    action_id: "action-1",
    reviewer_identity: "reviewer-1",
    reviewer_authority: { role: "approver", authorised: true },
    surface: { ui: "review", version: "1" },
    evidence,
    evidence_shown_refs: [],
    options_offered: ["approve"],
    time_available_ms: 1_000,
    time_taken_ms: 10,
    decision: "approve",
    modifications: null,
    action_state_at_review: "proposed",
    decided_at: "2026-08-01T10:00:00.000Z",
  };
  assert.throws(
    () => captureHumanReview({ ...base, action_state_at_review: "completed" } as never),
    { code: "review.action_state_invalid" },
  );
  assert.throws(
    () => captureHumanReview({ ...base, evidence: { ...evidence, evidence_shown_provenance: "unknown" } } as never),
    { code: "review.evidence_provenance_invalid" },
  );
});

async function captureClientRendered(rendered: string) {
  return new ReviewSurfaceInstrumentation({
    readRenderedEvidence: () => rendered,
    afterPaint: (capture) => capture(),
  }).capture();
}
