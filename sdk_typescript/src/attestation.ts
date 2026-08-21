/**
 * Offline verification of a signed attestation bundle.
 *
 * `parseBundle` decides what the container *is* (ES-034). This module decides
 * what it *claims*: the coverage ratio recomputed from the carried population
 * (ES-011, ES-012, ES-017, CM-013), the admissibility lattice re-checked
 * against the denominator class (CM-008, CM-009), the assertion catalogue
 * (AR-003), the qualification in force for the window, validity at the
 * evaluation instant, and revocation under AR-029 through AR-031.
 *
 * Two states that a less careful verifier collapses are kept apart throughout.
 * A claim this verifier *checked and confirmed* is not the same as one it
 * *could not check* — an incomplete stream slice, a conservation identity that
 * only holds for an independently enumerable denominator, an assertion payload
 * no normative schema defines. The second kind is reported by name in
 * `unchecked` rather than being reported as either verified or broken
 * (ES-034, TM-014).
 */

import { digestBytes } from "./crypto.ts";
import { EvidenceError, refuse } from "./errors.ts";
import { canonicalize, canonicalStringify, parseCanonicalJson, type JsonObject, type JsonValue } from "./json.ts";
import { parseBundle, ofType, type Bundle } from "./bundle.ts";
import { isObject, validateRecord } from "./schema.ts";
import type { VerificationKeyring } from "./types.ts";
import { parseTimestampNanoseconds, verifyCanonicalEvidenceRecordWire, verifyContinuity } from "./verification.ts";
import { requirePublishedMethodologyVersion, requirePublishedSchemaVersion } from "./versions.ts";

/** AR-003 closes the assertion catalogue at A-01 through A-10. */
export const ASSERTION_CATALOGUE: ReadonlySet<string> = new Set(
  Array.from({ length: 10 }, (_, index) => `A-${String(index + 1).padStart(2, "0")}`),
);

/** CM-012's exhaustive classification. A residual bucket is a defect. */
const COUNT_FIELDS = ["matched", "unmatched_with_evidence", "unmatched_without_evidence", "duplicate", "ambiguous", "out_of_scope"] as const;

const LEVEL_ORDER = ["observed", "intercepted", "enforced", "reconciled"] as const;

/** The §6 admissibility lattice: denominator class caps the claimable level. */
const CLASS_CEILING: Readonly<Record<string, (typeof LEVEL_ORDER)[number]>> = Object.freeze({
  C1: "reconciled",
  C2: "reconciled",
  C3: "enforced",
  C4: "observed",
  C5: "observed",
});

const CLASS_RANK: Readonly<Record<string, number>> = Object.freeze({ C1: 0, C2: 1, C3: 2, C4: 3, C5: 4 });

/** Classes whose denominator the destination can enumerate independently (CM-009). */
const INDEPENDENTLY_ENUMERABLE: ReadonlySet<string> = new Set(["C1", "C2", "C3"]);

export type RevocationStatus = "unchecked" | "valid" | "revoked" | "superseded";

/** One AR-029 endpoint answer, already fetched. */
export interface RevocationResponse {
  status_code: number;
  body?: Uint8Array | undefined;
}

export interface RevocationResult {
  status: RevocationStatus;
  checked: boolean;
  effectiveAt: string | undefined;
  supersedingRef: string | undefined;
  pending: boolean;
}

export interface BundleVerificationResult {
  accepted: boolean;
  verdict: string;
  evaluatedAt: string;
  attestationId: string | undefined;
  revocationStatus: RevocationStatus;
  coverageRatio: string | null;
  errorCodes: readonly string[];
  unchecked: readonly string[];
  pendingRevocationEffectiveAt: string | undefined;
  supersedingRef: string | undefined;
}

export interface BundleVerificationOptions {
  verificationKeys: VerificationKeyring;
  /** AR-031 requires the evaluation instant to be an input and to appear in the output. */
  evaluatedAt: string;
  revocationResponse?: RevocationResponse | undefined;
}

/** Verify a bundle from its canonical wire bytes and return a closed verdict. */
export function verifyAttestationBundle(wire: Uint8Array, options: BundleVerificationOptions): BundleVerificationResult {
  const instant = parseTimestampNanoseconds(options.evaluatedAt);
  const evaluatedAt = renderInstant(instant);

  let attestationId: string | undefined;
  let unchecked: string[];
  let ratio: string | null;
  let validity: string;
  let revocation: RevocationResult;
  try {
    const bundle = parseBundle(wire, options.verificationKeys);
    // Only now is the identity authenticated; before this point there is
    // nothing to name in a refusal.
    attestationId = typeof bundle.attestation.record_id === "string" ? bundle.attestation.record_id : undefined;

    // CM-025 before any conclusion is read from the attestation, so an
    // unimplemented methodology is refused rather than recomputed under this
    // verifier's newest rules — which is precisely what CM-023 forbids.
    requirePublishedMethodologyVersion(body(bundle.attestation).methodology_version);

    unchecked = streamChecks(bundle, options.verificationKeys);
    const coverage = ratioChecks(bundle);
    ratio = coverage.ratio;
    unchecked.push(...coverage.unchecked);
    unchecked.push(...assertionChecks(bundle.attestation));
    unchecked.push(...latticeChecks(bundle.attestation));
    gapChecks(bundle);
    unchecked.push(...qualificationChecks(bundle));
    validity = validityStatus(bundle.attestation, instant);
    revocation = checkRevocation(bundle.attestation, {
      response: options.revocationResponse,
      verificationKeys: options.verificationKeys,
      evaluatedAt: options.evaluatedAt,
    });
  } catch (error) {
    if (!(error instanceof EvidenceError)) throw error;
    return {
      accepted: false,
      verdict: "invalid",
      evaluatedAt,
      attestationId,
      revocationStatus: "unchecked",
      coverageRatio: null,
      errorCodes: [error.code],
      unchecked: [],
      pendingRevocationEffectiveAt: undefined,
      supersedingRef: undefined,
    };
  }

  let verdict: string;
  if (validity !== "current") verdict = validity;
  else if (revocation.status === "revoked" || revocation.status === "superseded") verdict = revocation.status;
  else if (!revocation.checked) verdict = "unchecked_revocation";
  else if (unchecked.length > 0) verdict = "unchecked";
  else verdict = "valid";

  return {
    accepted: true,
    verdict,
    evaluatedAt,
    attestationId,
    revocationStatus: revocation.status,
    coverageRatio: ratio,
    errorCodes: [],
    unchecked: [...new Set(unchecked)].sort(),
    pendingRevocationEffectiveAt: revocation.pending ? revocation.effectiveAt : undefined,
    supersedingRef: revocation.supersedingRef,
  };
}

/** The ES-029 vector projection: members carrying nothing are absent, not null. */
export function toVectorResult(result: BundleVerificationResult): JsonObject {
  const vector: JsonObject = {
    accepted: result.accepted,
    verdict: result.verdict,
    evaluated_at: result.evaluatedAt,
    revocation_status: result.revocationStatus,
    coverage_ratio: result.coverageRatio,
    unchecked: [...result.unchecked],
  };
  if (result.attestationId !== undefined) vector.attestation_id = result.attestationId;
  if (result.errorCodes.length > 0) vector.error_codes = [...result.errorCodes];
  if (result.pendingRevocationEffectiveAt !== undefined) vector.pending_revocation_effective_at = result.pendingRevocationEffectiveAt;
  if (result.supersedingRef !== undefined) vector.superseding_ref = result.supersedingRef;
  return vector;
}

/**
 * Classify one AR-029 endpoint answer.
 *
 * Only 404 and an authenticated `RevocationRecord` naming this attestation
 * establish anything. Everything else — a redirect, a captive portal, a body
 * that parses but is not the record asked about — is `unchecked`, never
 * `valid`, because data the verifier cannot authenticate is not evidence of
 * the issuer having published nothing.
 */
export function checkRevocation(attestation: JsonObject, options: { response?: RevocationResponse | undefined; verificationKeys: VerificationKeyring; evaluatedAt: string }): RevocationResult {
  // AR-031 compares parsed instants, never strings.
  const evaluatedAt = parseTimestampNanoseconds(options.evaluatedAt);
  const unresolved: RevocationResult = { status: "unchecked", checked: false, effectiveAt: undefined, supersedingRef: undefined, pending: false };
  const response = options.response;
  if (response === undefined) return unresolved;
  if (response.status_code === 404) {
    return { status: "valid", checked: true, effectiveAt: undefined, supersedingRef: undefined, pending: false };
  }
  if (response.status_code !== 200 || response.body === undefined) return unresolved;

  let effective: bigint;
  let effectiveAt: string;
  let supersedingRef: string | null;
  try {
    const parsed = parseCanonicalJson(new TextDecoder("utf-8", { fatal: true }).decode(response.body));
    if (!isObject(parsed) || parsed.record_type !== "RevocationRecord") return unresolved;
    const record = parsed;
    requirePublishedSchemaVersion(record.schema_version);
    // Canonical wire form plus the primary issuer-namespace signature ES-033
    // requires of this type.
    verifyCanonicalEvidenceRecordWire(response.body, options.verificationKeys);
    // AR-030: `superseding_ref` is required and nullable, so an *absent*
    // member is a non-conformant record and must not be read as either state.
    validateRecord(record, { requireSignature: true, validateBody: true });
    if (body(record).attestation_ref !== attestation.record_id) return unresolved;
    const candidate = body(record).superseding_ref;
    if (candidate !== null && typeof candidate !== "string") return unresolved;
    supersedingRef = candidate;
    effectiveAt = asString(body(record).effective_at, "effective_at");
    effective = parseTimestampNanoseconds(effectiveAt);
  } catch (error) {
    if (!(error instanceof EvidenceError)) throw error;
    return unresolved;
  }

  // AR-031: the boundary is exact. Only a strictly later effective_at leaves
  // the attestation valid; equality means the revocation is in effect.
  if (effective > evaluatedAt) {
    return { status: "valid", checked: true, effectiveAt, supersedingRef: supersedingRef ?? undefined, pending: true };
  }
  if (supersedingRef === null) {
    return { status: "revoked", checked: true, effectiveAt, supersedingRef: undefined, pending: false };
  }
  return { status: "superseded", checked: true, effectiveAt, supersedingRef, pending: false };
}

/**
 * ES-006a links across the bundle's slice of each stream.
 *
 * ES-034 preserves ES-026 selective disclosure, so a bundle is expected to
 * carry slices rather than whole streams, and a verifier must not require one
 * to be complete or anchored at sequence 1. Where two records sit at
 * consecutive sequences the link is checkable and is checked; across an
 * omission it is reported unchecked.
 */
function streamChecks(bundle: Bundle, keyring: VerificationKeyring): string[] {
  const grouped = new Map<string, JsonObject[]>();
  for (const record of bundle.records) {
    const streamId = asString(record.stream_id, "stream_id");
    const group = grouped.get(streamId);
    if (group === undefined) grouped.set(streamId, [record]);
    else group.push(record);
  }

  const unchecked: string[] = [];
  for (const streamId of [...grouped.keys()].sort()) {
    const ordered = [...grouped.get(streamId)!].sort((left, right) => (left.sequence as number) - (right.sequence as number));
    const positions = new Map<number, JsonObject>();
    for (const record of ordered) {
      const sequence = record.sequence as number;
      const priorAtPosition = positions.get(sequence);
      if (priorAtPosition !== undefined && digestBytes(canonicalize(priorAtPosition)) !== digestBytes(canonicalize(record))) {
        refuse("chain.fork", `stream ${streamId} has two distinct records at sequence ${sequence}`);
      }
      positions.set(sequence, record);
    }

    const unique = [...positions.keys()].sort((left, right) => left - right).map((sequence) => positions.get(sequence)!);
    let previous = unique[0]!;
    if (previous.sequence === 1 && previous.prev_digest !== null) {
      refuse("chain.prev_digest_mismatch", "sequence 1 must carry a null prev_digest");
    }
    if ((previous.sequence as number) > 1) unchecked.push(`chain:${streamId}:before:${previous.sequence}`);
    let previousKeyId = signingKeyId(previous);
    let previousNamespace = registeredKey(keyring, previousKeyId).namespace;

    for (const current of unique.slice(1)) {
      const currentKeyId = signingKeyId(current);
      const currentNamespace = registeredKey(keyring, currentKeyId).namespace;
      if ((current.sequence as number) !== (previous.sequence as number) + 1) {
        // Not checkable from the bundle, so neither verified nor broken.
        unchecked.push(`chain:${streamId}:${previous.sequence}:${current.sequence}`);
      } else {
        if (current.prev_digest !== digestBytes(canonicalize(previous))) {
          refuse("chain.prev_digest_mismatch", `stream ${streamId} has a broken link at sequence ${current.sequence}`);
        }
        if (currentNamespace !== previousNamespace) {
          refuse("key.namespace_mismatch", `stream ${streamId} changes primary-signer namespace`);
        }
        const continuity = (current.signature as JsonObject).key_continuity;
        if (currentKeyId !== previousKeyId) {
          if (continuity === undefined) refuse("continuity.missing", `stream ${streamId} changes key without continuity`);
          verifyContinuity(continuity, current, previousKeyId, currentKeyId, keyring, currentNamespace);
        } else if (continuity !== undefined) {
          refuse("continuity.no_key_change", "key continuity is present without a key change");
        }
      }
      previous = current;
      previousKeyId = currentKeyId;
      previousNamespace = currentNamespace;
    }
  }
  return unchecked;
}

/** ES-011, ES-012, ES-017 and CM-009: recompute the ratio from carried evidence. */
function ratioChecks(bundle: Bundle): { ratio: string | null; unchecked: string[] } {
  const attestation = bundle.attestation;
  const attestationBody = body(attestation);
  const denominatorClass = asString(attestationBody.denominator_class, "denominator_class");
  if (!Object.hasOwn(CLASS_RANK, denominatorClass)) {
    refuse("coverage.class_invalid", `unknown denominator class ${denominatorClass}`);
  }

  const refs = attestationBody.population_record_refs;
  if (!Array.isArray(refs)) refuse("coverage.population_missing", "population_record_refs must be an array");
  if (new Set(refs.map((ref) => canonicalStringify(ref))).size !== refs.length) {
    refuse("coverage.population_ref_duplicate", "population_record_refs must not repeat");
  }

  const byId = new Map(bundle.records.map((record) => [record.record_id as string, record]));
  const population: JsonObject[] = [];
  for (const ref of refs) {
    const record = typeof ref === "string" ? byId.get(ref) : undefined;
    if (record === undefined || record.record_type !== "PopulationRecord") {
      refuse("coverage.population_missing", `population reference ${canonicalStringify(ref)} is not carried by the bundle`);
    }
    if (record.tenant_id !== attestation.tenant_id || record.boundary_ref !== attestation.boundary_ref) {
      refuse("coverage.scope_mismatch", `population reference ${ref} is outside the attestation's scope`);
    }
    population.push(record);
  }

  const counts = readCounts(attestationBody);
  const total = population.reduce((sum, record) => sum + requireCount(body(record).count), 0);
  const independentlyEnumerable = INDEPENDENTLY_ENUMERABLE.has(denominatorClass);
  const countTotal = COUNT_FIELDS.reduce((sum, field) => sum + counts[field], 0);
  if (independentlyEnumerable && countTotal !== total) {
    refuse("coverage.count_conservation", `the six reconciliation counts total ${countTotal}; the enumerated population is ${total}`);
  }

  const denominator = total - counts.out_of_scope;
  const truncated = population.some((record) => body(record).result_cap_hit === true || body(record).pagination_complete !== true);
  // A ratio is emitted only where the denominator is independently enumerable
  // (CM-009), the enumeration was neither capped nor incomplete (ES-011,
  // ES-012), and the denominator is non-zero (ES-017).
  const ratio = !independentlyEnumerable || truncated || denominator === 0 ? null : formatRatio(counts.matched, denominator);
  if (attestationBody.coverage_ratio !== ratio) {
    refuse("coverage.ratio_mismatch", `coverage_ratio is ${canonicalStringify(attestationBody.coverage_ratio ?? null)}; the recomputed value is ${ratio === null ? "null" : ratio}`);
  }
  // Where the destination cannot enumerate the population, the identity
  // between the six counts and the denominator has nothing to be checked
  // against; saying so is not the same as having checked it.
  return { ratio, unchecked: independentlyEnumerable ? [] : ["coverage.count_conservation"] };
}

/** ES-017: four decimal places always, truncating toward zero. */
function formatRatio(matched: number, denominator: number): string {
  const scaled = (BigInt(matched) * 10_000n) / BigInt(denominator);
  return `${scaled / 10_000n}.${String(scaled % 10_000n).padStart(4, "0")}`;
}

type Counts = Record<(typeof COUNT_FIELDS)[number], number>;

function readCounts(attestationBody: JsonObject): Counts {
  const raw = attestationBody.counts;
  if (!isObject(raw) || Object.keys(raw).length !== COUNT_FIELDS.length || !COUNT_FIELDS.every((field) => Object.hasOwn(raw, field))) {
    refuse("coverage.counts_invalid", "counts must contain exactly the six CM-012 classes");
  }
  const counts = Object.fromEntries(COUNT_FIELDS.map((field) => {
    const value = raw[field];
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
      refuse("coverage.counts_invalid", `counts.${field} must be a non-negative integer`);
    }
    return [field, value];
  })) as Counts;
  return counts;
}

function requireCount(value: JsonValue | undefined): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    refuse("coverage.population_count_invalid", "a PopulationRecord count must be a non-negative integer");
  }
  return value;
}

/** AR-003: no assertion outside the catalogue may be emitted. */
function assertionChecks(attestation: JsonObject): string[] {
  const assertions = body(attestation).assertions;
  if (!Array.isArray(assertions)) refuse("assertion.invalid", "assertions must be an array");
  const unchecked: string[] = [];
  for (const [index, assertion] of assertions.entries()) {
    if (!isObject(assertion)) refuse("assertion.invalid", `assertion ${index} is not an object`);
    const assertionId = assertion.assertion_id;
    if (typeof assertionId !== "string" || !ASSERTION_CATALOGUE.has(assertionId)) {
      refuse("assertion.outside_catalogue", `assertion ${index} names the non-catalogue ID ${canonicalStringify(assertionId ?? null)}`);
    }
    // AR-003 closes the IDs, but no normative wire schema defines the
    // remaining members of a catalogue assertion. Claiming those
    // caller-authored members were verified would invent that missing rule.
    unchecked.push(`assertion.payload:${assertionId}`);
  }
  return unchecked;
}

/** CM-008: the claimed level is the minimum of evidence and class ceiling. */
function latticeChecks(attestation: JsonObject): string[] {
  const attestationBody = body(attestation);
  const claimed = attestationBody.coverage_level;
  const ceiling = CLASS_CEILING[asString(attestationBody.denominator_class, "denominator_class")]!;
  if (typeof claimed !== "string" || !LEVEL_ORDER.includes(claimed as (typeof LEVEL_ORDER)[number])) {
    refuse("coverage.level_invalid", `unknown coverage level ${canonicalStringify(claimed ?? null)}`);
  }
  const claimedRank = LEVEL_ORDER.indexOf(claimed as (typeof LEVEL_ORDER)[number]);
  const ceilingRank = LEVEL_ORDER.indexOf(ceiling);
  if (claimedRank > ceilingRank) {
    refuse("coverage.level_exceeds_class", `${claimed} exceeds the ${ceiling} ceiling of ${attestationBody.denominator_class}`);
  }
  const capped = attestationBody.capped_by_class;
  if (capped !== undefined && typeof capped !== "boolean") {
    refuse("coverage.capped_by_class_invalid", "capped_by_class must be a boolean");
  }
  if (claimedRank < ceilingRank && capped === true) {
    refuse("coverage.capped_by_class_invalid", "a claim below the class ceiling is determinately not capped by class");
  }
  // At the ceiling the field is unfalsifiable from the bundle alone: the claim
  // and the cap coincide whether or not the evidence would have supported
  // more. ES-018 and §5.13 disagree about the member and no vector arbitrates,
  // so it is reported unchecked rather than guessed at.
  return claimedRank === ceilingRank ? ["coverage.capped_by_class"] : [];
}

/** CM-014: a gap is an explicit interval, and a signed gap is never dropped. */
function gapChecks(bundle: Bundle): void {
  const announced = new Set<string>();
  const gaps = body(bundle.attestation).gaps;
  if (!Array.isArray(gaps)) refuse("coverage.gap_invalid", "attestation gaps must be an array");
  for (const [index, value] of gaps.entries()) {
    if (!isObject(value)) refuse("coverage.gap_invalid", `attestation gap ${index} is not an object`);
    const start = value.gap_start ?? value.start;
    const end = value.gap_end ?? value.end;
    if (typeof start !== "string" || typeof end !== "string" || value.cause === undefined || value.affected_scope === undefined) {
      refuse("coverage.gap_invalid", `attestation gap ${index} must state its interval, scope, and cause`);
    }
    if (parseTimestampNanoseconds(end) <= parseTimestampNanoseconds(start)) {
      refuse("coverage.gap_invalid", `attestation gap ${index} has an empty interval`);
    }
    announced.add(gapKey(value));
  }
  for (const record of ofType(bundle, "CoverageGap")) {
    if (!announced.has(gapKey(body(record)))) {
      refuse("coverage.gap_unreported", `signed CoverageGap ${record.record_id} is omitted from the attestation's gaps`);
    }
  }
}

function gapKey(value: JsonObject): string {
  return canonicalStringify([value.gap_start ?? value.start ?? null, value.gap_end ?? value.end ?? null, value.cause ?? null, value.affected_scope ?? null]);
}

/**
 * The denominator class claimed for the window must be the one in force for it.
 *
 * A qualification is evidence about the destination system from the moment it
 * was taken, not before it: a record qualified at or after `window_start`
 * cannot establish what was true at the window's opening instant. Where the
 * bundle does not disclose the qualifications the boundary references, the
 * class in force is not checkable from the bundle and is reported as such
 * rather than assumed to be the one claimed.
 */
function qualificationChecks(bundle: Bundle): string[] {
  const attestation = bundle.attestation;
  const attestationBody = body(attestation);
  const boundary = bundle.boundary;
  if (boundary === undefined) return ["qualification.class_in_force"];
  if (boundary.record_id !== attestationBody.boundary_ref && boundary.boundary_ref !== attestationBody.boundary_ref) {
    refuse("qualification.boundary_mismatch", "the carried AssuranceBoundary is not the one the attestation names");
  }

  const refs = body(boundary).qualification_refs;
  if (!Array.isArray(refs)) refuse("qualification.reference_invalid", "qualification_refs must be an array");
  const byId = new Map(bundle.records.map((record) => [record.record_id as string, record]));
  const referenced: JsonObject[] = [];
  let undisclosed = false;
  for (const ref of refs) {
    const record = typeof ref === "string" ? byId.get(ref) : undefined;
    if (record === undefined) {
      undisclosed = true;
      continue;
    }
    if (record.record_type !== "QualificationRecord") {
      refuse("qualification.reference_invalid", `qualification reference ${ref} names a ${record.record_type as string}`);
    }
    referenced.push(record);
  }
  if (referenced.length === 0 || undisclosed) return ["qualification.class_in_force"];

  const claimed = asString(attestationBody.denominator_class, "denominator_class");
  const windowStart = parseTimestampNanoseconds(asString(attestationBody.window_start, "window_start"));
  const windowEnd = parseTimestampNanoseconds(asString(attestationBody.window_end, "window_end"));
  const histories = new Map<string, JsonObject[]>();
  for (const record of referenced) {
    const scope = canonicalStringify([body(record).action_family ?? null, body(record).destination_system ?? null]);
    const history = histories.get(scope);
    if (history === undefined) histories.set(scope, [record]);
    else history.push(record);
  }

  for (const scope of [...histories.keys()].sort()) {
    const history = histories.get(scope)!;
    const qualifiedAt = (record: JsonObject): bigint => parseTimestampNanoseconds(asString(body(record).qualified_at, "qualified_at"));
    const before = history.filter((record) => qualifiedAt(record) < windowStart);
    if (before.length === 0) {
      refuse("qualification.postdates_window", `no qualification for ${scope} predates the window it is claimed for`);
    }
    const governing = before.reduce((latest, record) => (qualifiedAt(record) > qualifiedAt(latest) ? record : latest));
    const inWindow = history.filter((record) => qualifiedAt(record) >= windowStart && qualifiedAt(record) < windowEnd);
    const inForceRank = Math.max(...[governing, ...inWindow].map((record) => classRank(body(record).assigned_class)));
    if (classRank(claimed) < inForceRank) {
      // A record that would support the weaker claim, but only from a moment
      // inside the window, is a dating problem rather than a class problem —
      // and saying so names the defect the issuer can actually act on.
      const laterSupport = history.some((record) => classRank(body(record).assigned_class) <= classRank(claimed) && qualifiedAt(record) >= windowStart);
      if (laterSupport) refuse("qualification.postdates_window", `the qualification supporting ${claimed} for ${scope} postdates the window`);
      refuse("qualification.class_unsupported", `the claimed class ${claimed} exceeds the class in force for ${scope}`);
    }
  }
  return [];
}

function classRank(value: JsonValue | undefined): number {
  if (typeof value !== "string" || !Object.hasOwn(CLASS_RANK, value)) {
    refuse("qualification.class_invalid", `unknown denominator class ${canonicalStringify(value ?? null)}`);
  }
  return CLASS_RANK[value]!;
}

function validityStatus(attestation: JsonObject, evaluatedAt: bigint): string {
  const attestationBody = body(attestation);
  const from = parseTimestampNanoseconds(asString(attestationBody.validity_from, "validity_from"));
  const until = parseTimestampNanoseconds(asString(attestationBody.validity_until, "validity_until"));
  if (until <= from) refuse("validity.interval_invalid", "validity_until must follow validity_from");
  if (evaluatedAt < from) return "not_yet_valid";
  // The interval is half-open: an attestation is expired at the instant its
  // validity_until names, not one millisecond after it.
  if (evaluatedAt >= until) return "expired";
  return "current";
}

/** AR-031: the evaluation instant appears in the output, at millisecond precision. */
function renderInstant(nanoseconds: bigint): string {
  return new Date(Number(nanoseconds / 1_000_000n)).toISOString();
}

function body(record: JsonObject): JsonObject {
  if (!isObject(record.body)) refuse("schema.body_invalid", "record body must be an object");
  return record.body;
}

function signingKeyId(record: JsonObject): string {
  if (!isObject(record.signature) || typeof record.signature.key_id !== "string") {
    refuse("signature.missing_customer_member", "record signature is missing key_id");
  }
  return record.signature.key_id;
}

function registeredKey(keyring: VerificationKeyring, keyId: string): { namespace: "evidence" | "issuer"; public_key: string } {
  const key = keyring[keyId];
  if (key === undefined) refuse("signature.key_unknown", `unknown signing key ${keyId}`);
  return key;
}

function asString(value: JsonValue | undefined, field: string): string {
  if (typeof value !== "string") refuse("schema.missing_body_field", `${field} must be a string`);
  return value;
}
