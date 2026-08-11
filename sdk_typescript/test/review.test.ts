import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { test } from "node:test";
import { ReviewSurfaceInstrumentation, clientRenderedEvidence, serverReconstructedEvidence } from "../src/index.ts";

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
  assert.deepEqual(captured, await clientRenderedEvidence(fixture.client_rendered));
  assert.equal(captured.evidence_shown_provenance, "client_rendered");
  assert.notEqual(captured.evidence_shown, (await serverReconstructedEvidence(fixture.server_reconstruction)).evidence_shown);
});

test("server reconstruction is explicitly labelled and cannot masquerade as rendered evidence", async () => {
  const capture = await serverReconstructedEvidence(fixture.server_reconstruction);
  assert.equal(capture.evidence_shown_provenance, "server_reconstructed");
  assert.notDeepEqual(capture, await clientRenderedEvidence(fixture.server_reconstruction));
});

test("capture refuses without a client render boundary", async () => {
  const instrumentation = new ReviewSurfaceInstrumentation({
    readRenderedEvidence: () => fixture.server_reconstruction,
  });
  await assert.rejects(instrumentation.capture(), { code: "review.client_render_unavailable" });
});
