import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { test } from "node:test";
import {
  addIssuerSignature,
  assembleBundle,
  canonicalize,
  canonicalStringify,
  digestBytes,
  encodeBase64Url,
  parseCanonicalJson,
  primarySignerNamespace,
  publicKeyFromSeed,
  runConformanceVector,
  sha256Bytes,
  signEd25519,
  signRecord,
  verifyAttestationBundle,
  type ConformanceVector,
  type JsonObject,
  type JsonValue,
  type VerificationKeyring,
} from "../src/index.ts";

const corpusPath = resolve(import.meta.dirname, "../../tests/vectors/vectors-v0.1.json");
const corpus = JSON.parse(readFileSync(corpusPath, "utf8")) as {
  vectors: ConformanceVector[];
  adversarial_vectors: ConformanceVector[];
};
const BUNDLE_VECTORS = [...corpus.vectors, ...corpus.adversarial_vectors].filter((vector) => vector.operation === "verify_bundle");

const EVALUATED_AT = "2026-10-01T00:00:00.000Z";

// Local keys, so a test can re-sign a mutated record instead of being limited
// to the mutations that happen to survive a signature it cannot reproduce. A
// rule is only shown to hold if the input violating it is otherwise valid.
const EVIDENCE_SEED = new Uint8Array(32).fill(7);
const ISSUER_SEED = new Uint8Array(32).fill(9);
const KEYRING: VerificationKeyring = {
  E1: { namespace: "evidence", public_key: encodeBase64Url(publicKeyFromSeed(EVIDENCE_SEED)) },
  I1: { namespace: "issuer", public_key: encodeBase64Url(publicKeyFromSeed(ISSUER_SEED)) },
};

test("EV-10 the conformance runner reproduces every published verify_bundle vector", () => {
  assert.equal(BUNDLE_VECTORS.length, 16, "the corpus verify_bundle population changed");
  for (const vector of BUNDLE_VECTORS) {
    assert.deepEqual(runConformanceVector(vector), vector.expected, `${vector.id}: complete result differs`);
  }
});

test("ES-034 a valid bundle verifies offline and reports revocation as unchecked, never valid", () => {
  const vector = requireVector("bundle-valid-offline");
  const result = runConformanceVector(vector);

  assert.equal(result.accepted, true);
  assert.equal(result.verdict, "unchecked_revocation");
  // TM-014: offline is not a licence to report the stronger answer.
  assert.equal(result.revocation_status, "unchecked");
  assert.notEqual(result.revocation_status, "valid");
  assert.equal(result.coverage_ratio, "0.3333");
  assert.deepEqual(result.unchecked, []);
  assert.equal(result.evaluated_at, EVALUATED_AT);
});

test("ES-017 the ratio is recomputed from the carried population, not read from the claim", () => {
  // matched 1 of a population of 4 less 1 out-of-scope; and 2 of 3, which
  // truncates rather than rounding to 0.6667.
  assert.equal(runConformanceVector(requireVector("coverage-ratio-excludes-out-of-scope-fixed-scale")).coverage_ratio, "0.3333");
  assert.equal(runConformanceVector(requireVector("coverage-ratio-truncates-two-thirds")).coverage_ratio, "0.6666");
  for (const id of ["coverage-ratio-null-on-result-cap", "coverage-ratio-null-on-incomplete-pagination"]) {
    assert.equal(runConformanceVector(requireVector(id)).coverage_ratio, null, id);
  }
});

test("CM-009 an unenumerable denominator withholds the ratio and names what went unchecked", () => {
  const result = runConformanceVector(requireVector("coverage-class-caps-level-and-withholds-ratio"));
  assert.equal(result.accepted, true);
  assert.equal(result.coverage_ratio, null);
  // Neither is a failure: at C4 the count-conservation identity has nothing to
  // be checked against, and at the class ceiling capped_by_class is not
  // falsifiable from the bundle alone.
  assert.deepEqual(result.unchecked, ["coverage.capped_by_class", "coverage.count_conservation"]);
});

test("the adversarial verify_bundle vectors are refused with their published codes", () => {
  const refusals: Record<string, string> = {
    "reject-bundle-object-container": "bundle.container_invalid",
    "reject-assertion-outside-catalogue": "assertion.outside_catalogue",
    "reject-qualification-at-window-boundary": "qualification.postdates_window",
    "reject-unpublished-schema-version": "schema.version_unsupported",
    "reject-unpublished-methodology-version": "methodology.version_unsupported",
  };
  for (const [id, code] of Object.entries(refusals)) {
    const result = runConformanceVector(requireVector(id));
    assert.equal(result.accepted, false, id);
    assert.equal(result.verdict, "invalid", id);
    assert.deepEqual(result.error_codes, [code], id);
    assert.equal(result.coverage_ratio, null, id);
  }
});

test("ES-035 a schema version absent from the registry names nothing it did not authenticate", () => {
  // The refusal happens per element, before any record is authenticated, so
  // there is no attestation identity to report and reporting one would claim
  // an authentication that never occurred.
  const result = runConformanceVector(requireVector("reject-unpublished-schema-version"));
  assert.equal(Object.hasOwn(result, "attestation_id"), false);

  // CM-025's refusal comes after every schema and signature check passed, so
  // the identity is authenticated and is useful diagnostic output.
  const methodology = runConformanceVector(requireVector("reject-unpublished-methodology-version"));
  assert.equal(methodology.attestation_id, "01890f47-2f58-7cc0-98c4-000000000194");
});

test("AR-029 an answer the verifier cannot authenticate establishes nothing", () => {
  const bundle = validBundle();
  for (const [label, response] of [
    ["captive portal at 200", { status_code: 200, body: new TextEncoder().encode("<html>captive portal</html>") }],
    ["service unavailable", { status_code: 503 }],
    ["redirect", { status_code: 302, body: new TextEncoder().encode("[]") }],
    ["200 with no body", { status_code: 200 }],
  ] as const) {
    const result = verifyAttestationBundle(bundle, { verificationKeys: KEYRING, evaluatedAt: EVALUATED_AT, revocationResponse: response });
    assert.equal(result.revocationStatus, "unchecked", label);
    assert.notEqual(result.revocationStatus, "valid", label);
    assert.notEqual(result.revocationStatus, "revoked", label);
    assert.equal(result.verdict, "unchecked_revocation", label);
  }
});

test("AR-029 a 404 is the issuer having published nothing, and that is a checked answer", () => {
  const result = verifyAttestationBundle(validBundle(), { verificationKeys: KEYRING, evaluatedAt: EVALUATED_AT, revocationResponse: { status_code: 404 } });
  assert.equal(result.revocationStatus, "valid");
  assert.equal(result.verdict, "valid");
});

test("AR-029 an authenticated record about another attestation is not an answer about this one", () => {
  const revocation = revocationRecord({ attestation_ref: "01890f47-2f58-7cc0-98c4-0000000009ff", effective_at: "2026-09-01T00:00:00.000Z", superseding_ref: null });
  const result = verifyAttestationBundle(validBundle(), {
    verificationKeys: KEYRING,
    evaluatedAt: EVALUATED_AT,
    revocationResponse: { status_code: 200, body: canonicalize(revocation) },
  });
  assert.equal(result.revocationStatus, "unchecked");
});

test("ES-033 a revocation signed by an evidence-namespace key is not an issuer answer", () => {
  const record = revocationRecord({ attestation_ref: attestationId(), effective_at: "2026-09-01T00:00:00.000Z", superseding_ref: null }, "E1", EVIDENCE_SEED);
  const result = verifyAttestationBundle(validBundle(), {
    verificationKeys: KEYRING,
    evaluatedAt: EVALUATED_AT,
    revocationResponse: { status_code: 200, body: canonicalize(record) },
  });
  assert.equal(result.revocationStatus, "unchecked");
});

test("AR-030 superseding_ref separates supersession from revocation", () => {
  const superseded = revoke({ effective_at: "2026-09-01T00:00:00.000Z", superseding_ref: "attestation-2" });
  assert.equal(superseded.revocationStatus, "superseded");
  assert.equal(superseded.verdict, "superseded");
  assert.equal(superseded.supersedingRef, "attestation-2");

  const revoked = revoke({ effective_at: "2026-09-01T00:00:00.000Z", superseding_ref: null });
  assert.equal(revoked.revocationStatus, "revoked");
  assert.equal(revoked.verdict, "revoked");
  assert.equal(revoked.supersedingRef, undefined);
});

test("AR-030 an absent superseding_ref is non-conformant, not a third state", () => {
  const classify = (members: Record<string, JsonValue>): string => {
    const record = revocationRecord({ attestation_ref: attestationId(), effective_at: "2026-09-01T00:00:00.000Z", ...members });
    return verifyAttestationBundle(validBundle(), {
      verificationKeys: KEYRING,
      evaluatedAt: EVALUATED_AT,
      revocationResponse: { status_code: 200, body: canonicalize(record) },
    }).revocationStatus;
  };

  // The control: the same record, signed the same way, with the member
  // present. Without it, "unchecked" below would be indistinguishable from a
  // probe whose signature never verified in the first place.
  assert.equal(classify({ superseding_ref: null }), "revoked");

  // ES-002b makes the member required and nullable, so its absence is a
  // defective record rather than a quieter way of saying null.
  assert.equal(classify({}), "unchecked");
});

test("AR-031 the effective_at boundary is exact and comparison is on instants", () => {
  // One millisecond after the evaluation instant: pending, and surfaced.
  const pending = revoke({ effective_at: "2026-10-01T00:00:00.001Z", superseding_ref: null });
  assert.equal(pending.revocationStatus, "valid");
  assert.equal(pending.verdict, "valid");
  assert.equal(pending.pendingRevocationEffectiveAt, "2026-10-01T00:00:00.001Z");

  // Exactly at the evaluation instant: in effect.
  const exact = revoke({ effective_at: EVALUATED_AT, superseding_ref: null });
  assert.equal(exact.revocationStatus, "revoked");
  assert.equal(exact.pendingRevocationEffectiveAt, undefined);

  // An offset spelling of the same instant is the same instant.
  const offset = revoke({ effective_at: "2026-09-30T23:00:00.000-01:00", superseding_ref: null });
  assert.equal(offset.revocationStatus, "revoked");
});

test("AR-031 the evaluation instant is an input and appears in the output", () => {
  const early = verifyAttestationBundle(validBundle(), { verificationKeys: KEYRING, evaluatedAt: "2026-08-15T00:00:00.000Z" });
  assert.equal(early.verdict, "not_yet_valid");
  assert.equal(early.evaluatedAt, "2026-08-15T00:00:00.000Z");

  const late = verifyAttestationBundle(validBundle(), { verificationKeys: KEYRING, evaluatedAt: "2027-01-01T00:00:00.000Z" });
  assert.equal(late.verdict, "expired");
  assert.equal(late.evaluatedAt, "2027-01-01T00:00:00.000Z");
});

test("ES-034 a bundle whose elements are out of canonical order is refused", () => {
  const records = baseRecords();
  const descending = [...records]
    .map((record) => Buffer.from(canonicalize(record)))
    .sort((left, right) => right.compare(left));
  const wire = new Uint8Array(Buffer.concat([Buffer.from("["), Buffer.from(descending.map((element) => element.toString("utf8")).join(",")), Buffer.from("]")]));

  assert.deepEqual(refuseCodes(wire), ["bundle.element_order"]);
});

test("ES-S-023 a non-canonical bundle fails naming the canonical form, not a signature", () => {
  const padded = new Uint8Array(Buffer.concat([Buffer.from("[ "), Buffer.from(validBundle()).subarray(1)]));
  const codes = refuseCodes(padded);
  assert.deepEqual(codes, ["bundle.non_canonical"]);
  assert.equal(codes[0]?.startsWith("signature."), false);
});

test("ES-034 a keyed container is refused even where its keys agree with its contents", () => {
  const records = baseRecords();
  const keyed = new TextEncoder().encode(canonicalStringify({
    attestation: records.find((record) => record.record_type === "AttestationWindow")!,
    boundary: records.find((record) => record.record_type === "AssuranceBoundary")!,
  }));
  assert.deepEqual(refuseCodes(keyed), ["bundle.container_invalid"]);
});

test("ES-034 the AttestationWindow cardinality is exactly one", () => {
  const records = baseRecords();
  const attestation = records.find((record) => record.record_type === "AttestationWindow")!;

  const none = signAll(records.filter((record) => record.record_type !== "AttestationWindow"));
  assert.deepEqual(refuseCodes(none), ["bundle.cardinality_invalid"]);

  const second = { ...structuredClone(attestation), record_id: "01890f47-2f58-7cc0-98c4-000000000999", stream_id: "attestation-2" };
  assert.deepEqual(refuseCodes(signAll([...records, second])), ["bundle.cardinality_invalid"]);
});

test("ES-021 a tampered element does not survive re-canonicalisation of the container", () => {
  // Signed, then edited: the container is still canonical and still ordered,
  // so only the signature stands between the claim and acceptance.
  const signed = signedRecords(baseRecords());
  const tampered = signed.map((record) => (record.record_type === "AttestationWindow" ? { ...record, body: { ...(record.body as JsonObject), coverage_ratio: "1.0000" } } : record));

  const codes = refuseCodes(assembleBundle(tampered));
  assert.equal(codes.length, 1);
  assert.equal(codes[0]?.startsWith("signature."), true, `expected a signature refusal, got ${codes[0]}`);
});

test("CM-013 a coverage_ratio the carried evidence does not produce is refused", () => {
  const wire = mutateAttestation((body) => {
    body.coverage_ratio = "0.9000";
  });
  assert.deepEqual(refuseCodes(wire), ["coverage.ratio_mismatch"]);
});

test("CM-012 the six counts must conserve the enumerated population at an enumerable class", () => {
  const wire = mutateAttestation((body) => {
    const counts = body.counts as JsonObject;
    counts.matched = 2;
    body.coverage_ratio = "0.6666";
  });
  assert.deepEqual(refuseCodes(wire), ["coverage.count_conservation"]);
});

test("CM-008 a coverage level above the denominator class ceiling is refused", () => {
  const wire = mutateAttestation((body) => {
    body.denominator_class = "C4";
    body.coverage_level = "reconciled";
    body.coverage_ratio = null;
  });
  assert.deepEqual(refuseCodes(wire), ["coverage.level_exceeds_class"]);
});

test("AR-003 an assertion outside the catalogue is refused, and a catalogue payload is unchecked", () => {
  assert.deepEqual(refuseCodes(mutateAttestation((body) => {
    body.assertions = [{ assertion_id: "A-99" }];
  })), ["assertion.outside_catalogue"]);

  const withinCatalogue = verifyAttestationBundle(mutateAttestation((body) => {
    body.assertions = [{ assertion_id: "A-01", basis: "whatever the caller wrote here" }];
  }), { verificationKeys: KEYRING, evaluatedAt: EVALUATED_AT });
  assert.equal(withinCatalogue.accepted, true);
  // AR-003 closes the IDs; no normative schema defines the rest of an
  // assertion, so calling those members verified would invent that rule.
  assert.deepEqual(withinCatalogue.unchecked, ["assertion.payload:A-01"]);
});

test("CM-014 a signed CoverageGap omitted from the attestation's gaps is refused", () => {
  const vector = requireVector("coverage-gap-is-an-explicit-interval");
  const records = decodeBundle(hexToBytes(vector.bundle_utf8_hex as string));
  const withoutAnnouncement = records.map((record) => {
    if (record.record_type !== "AttestationWindow") return record;
    return { ...record, body: { ...(record.body as JsonObject), gaps: [] } };
  });
  assert.deepEqual(refuseCodes(signAll(withoutAnnouncement)), ["coverage.gap_unreported"]);
});

test("ES-034 selective disclosure leaves an undisclosed link unchecked, not broken", () => {
  // ES-026: a bundle carries slices. A qualification the boundary references
  // and the bundle does not disclose leaves the class in force uncheckable.
  const records = baseRecords().filter((record) => record.record_type !== "QualificationRecord");
  const result = verifyAttestationBundle(signAll(records), { verificationKeys: KEYRING, evaluatedAt: EVALUATED_AT });
  assert.equal(result.accepted, true);
  assert.deepEqual(result.unchecked, ["qualification.class_in_force"]);
  assert.equal(result.verdict, "unchecked_revocation");
});

// --- helpers -------------------------------------------------------------

function requireVector(id: string): ConformanceVector {
  const vector = BUNDLE_VECTORS.find((candidate) => candidate.id === id);
  assert.ok(vector !== undefined, `vector ${id} is not published`);
  return vector;
}

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, "hex"));
}

function decodeBundle(wire: Uint8Array): JsonObject[] {
  return parseCanonicalJson(new TextDecoder().decode(wire)) as JsonObject[];
}

/** The published valid bundle's records, stripped of their vector signatures. */
function baseRecords(): JsonObject[] {
  const vector = requireVector("bundle-valid-offline");
  return decodeBundle(hexToBytes(vector.bundle_utf8_hex as string));
}

function signedRecords(records: readonly JsonObject[]): JsonObject[] {
  return records.map((record) => {
    const unsigned = { ...structuredClone(record) };
    delete unsigned.signature;
    const namespace = primarySignerNamespace(record.record_type);
    const keyId = namespace === "evidence" ? "E1" : "I1";
    const seed = namespace === "evidence" ? EVIDENCE_SEED : ISSUER_SEED;
    const signed = signRecord(unsigned as never, keyId, seed);
    // ES-023: an AttestationWindow also carries the issuer counter-signature.
    return (record.record_type === "AttestationWindow" ? addIssuerSignature(signed as never, "I1", ISSUER_SEED) : signed) as unknown as JsonObject;
  });
}

function signAll(records: readonly JsonObject[]): Uint8Array {
  return assembleBundle(signedRecords(records));
}

function validBundle(): Uint8Array {
  return signAll(baseRecords());
}

function attestationId(): string {
  return baseRecords().find((record) => record.record_type === "AttestationWindow")!.record_id as string;
}

function mutateAttestation(mutate: (body: JsonObject) => void): Uint8Array {
  const records = structuredClone(baseRecords());
  const attestation = records.find((record) => record.record_type === "AttestationWindow")!;
  mutate(attestation.body as JsonObject);
  return signAll(records);
}

function refuseCodes(wire: Uint8Array): readonly string[] {
  const result = verifyAttestationBundle(wire, { verificationKeys: KEYRING, evaluatedAt: EVALUATED_AT });
  assert.equal(result.accepted, false, `expected a refusal, got verdict ${result.verdict}`);
  assert.equal(result.verdict, "invalid");
  assert.equal(result.coverageRatio, null);
  return result.errorCodes;
}

function revocationRecord(bodyMembers: Record<string, JsonValue>, keyId = "I1", seed = ISSUER_SEED): JsonObject {
  const unsigned: JsonObject = {
    record_id: "01890f47-2f58-7cc0-98c4-000000000195",
    record_type: "RevocationRecord",
    schema_version: "1.0.0",
    tenant_id: "tenant-1",
    boundary_ref: "boundary-1",
    stream_id: "revocation-1",
    sequence: 1,
    prev_digest: null,
    source: { collector: "sdk-typescript-test", version: "1.0.0" },
    clocks: { source_time: "2026-09-02T00:00:00.000Z" },
    body: { reason: "computation defect", issuer: { name: "issuer-1" }, relying_party_notification_status: "sent", ...bodyMembers },
  };
  return signWithoutBodyValidation(unsigned, keyId, seed);
}

/**
 * Sign exactly the record given, including one the §5 body rules reject.
 *
 * `signRecord` validates the body first, which is right for an emitter and
 * useless here: a probe for a rule about a *missing* member cannot be built by
 * a signer that refuses to produce the record, and signing a complete record
 * and then deleting the member afterwards would break the signature and prove
 * only that a broken signature is refused.
 */
function signWithoutBodyValidation(unsigned: JsonObject, keyId: string, seed: Uint8Array): JsonObject {
  const canonical = canonicalize(unsigned);
  return {
    ...unsigned,
    signature: {
      alg: "ed25519",
      key_id: keyId,
      sig: encodeBase64Url(signEd25519(sha256Bytes(canonical), seed)),
      signed_digest: digestBytes(canonical),
    },
  };
}

function revoke(bodyMembers: Record<string, JsonValue>): ReturnType<typeof verifyAttestationBundle> {
  const record = revocationRecord({ attestation_ref: attestationId(), ...bodyMembers });
  return verifyAttestationBundle(validBundle(), {
    verificationKeys: KEYRING,
    evaluatedAt: EVALUATED_AT,
    revocationResponse: { status_code: 200, body: canonicalize(record) },
  });
}
