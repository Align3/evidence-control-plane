/**
 * The attestation bundle container (ES-034).
 *
 * A bundle is a JSON *array* of complete signed records, and every routing
 * decision here is taken from the record's own `record_type` under the closed
 * ES-033 dispatch. Nothing reads a record's role from where it sits, so the
 * parser cannot be handed a role that disagrees with the signature covering
 * the record — an array has no second statement to disagree with. A container
 * that is not an array is therefore refused, including one whose keys would
 * have been consistent with its contents.
 */

import { EvidenceError, refuse } from "./errors.ts";
import { canonicalize, parseCanonicalJson, type JsonObject, type JsonValue } from "./json.ts";
import { isObject, validateRecord } from "./schema.ts";
import type { VerificationKeyring } from "./types.ts";
import { verifyCanonicalEvidenceRecordWire } from "./verification.ts";
import { requirePublishedSchemaVersion } from "./versions.ts";

/** ES-034 cardinality. Every other §5 type may appear any number of times. */
export const REQUIRED_SINGLETON = "AttestationWindow";
export const OPTIONAL_SINGLETON = "AssuranceBoundary";

export interface Bundle {
  /** The array exactly as received. */
  readonly records: readonly JsonObject[];
  /** A derived index; every entry was placed by reading the record's own `record_type`. */
  readonly byType: Readonly<Record<string, readonly JsonObject[]>>;
  readonly canonicalBytes: Uint8Array;
  readonly attestation: JsonObject;
  readonly boundary: JsonObject | undefined;
}

/**
 * Parse and verify an ES-034 attestation bundle from its wire bytes.
 *
 * The order of refusals is itself normative: shape, canonical form and element
 * order are decided before any signature is examined, because ES-S-023
 * requires a non-canonical bundle to fail naming the canonical form rather
 * than a signature a producer would then hunt for in vain.
 */
export function parseBundle(wire: Uint8Array, keyring: VerificationKeyring): Bundle {
  const decoded = decodeArray(wire);

  const canonical = canonicalize(decoded);
  if (!Buffer.from(canonical).equals(Buffer.from(wire))) {
    refuse("bundle.non_canonical", "received bundle bytes differ from the canonical form of the same content");
  }

  // RFC 8785 sorts object members but never reorders array elements, so
  // canonicalizing the container is not sufficient to make a bundle
  // byte-identical. ES-034 supplies the missing total order.
  const elementBytes = decoded.map((element) => canonicalize(element));
  for (let index = 1; index < elementBytes.length; index += 1) {
    if (Buffer.from(elementBytes[index]!).compare(Buffer.from(elementBytes[index - 1]!)) < 0) {
      refuse("bundle.element_order", `bundle element ${index} sorts before element ${index - 1}; ES-034 orders elements by canonical bytes, lexicographic ascending`);
    }
  }

  const records: JsonObject[] = [];
  for (const [index, element] of decoded.entries()) {
    if (!isObject(element)) {
      refuse("bundle.container_invalid", `bundle element ${index} is not a JSON object; every element is one complete signed record`);
    }
    verifyElement(element, elementBytes[index]!, keyring);
    records.push(element);
  }

  const byType: Record<string, JsonObject[]> = {};
  for (const record of records) {
    // The only routing statement in this module, and it reads the record.
    (byType[record.record_type as string] ??= []).push(record);
  }

  const attestations = byType[REQUIRED_SINGLETON] ?? [];
  if (attestations.length !== 1) {
    refuse("bundle.cardinality_invalid", `bundle carries ${attestations.length} ${REQUIRED_SINGLETON} records; ES-034 requires exactly one`);
  }
  const boundaries = byType[OPTIONAL_SINGLETON] ?? [];
  if (boundaries.length > 1) {
    refuse("bundle.cardinality_invalid", `bundle carries ${boundaries.length} ${OPTIONAL_SINGLETON} records; ES-034 permits at most one`);
  }

  return {
    records,
    byType,
    canonicalBytes: canonical,
    attestation: attestations[0]!,
    boundary: boundaries[0],
  };
}

/** Records whose own `record_type` is `recordType`. */
export function ofType(bundle: Bundle, recordType: string): readonly JsonObject[] {
  return bundle.byType[recordType] ?? [];
}

function decodeArray(wire: Uint8Array): JsonValue[] {
  let source: string;
  try {
    source = new TextDecoder("utf-8", { fatal: true }).decode(wire);
  } catch {
    return refuse("bundle.container_invalid", "bundle wire is not UTF-8");
  }
  let decoded: JsonValue;
  try {
    // Token-level parsing, so a duplicate member, a float, or a NaN token is
    // refused during decoding rather than normalized into a second canonical
    // form the signature was never taken over.
    decoded = parseCanonicalJson(source);
  } catch (error) {
    if (!(error instanceof EvidenceError)) throw error;
    return refuse("bundle.container_invalid", `bundle carries a non-conformant JSON value: ${error.message}`);
  }
  if (!Array.isArray(decoded)) {
    return refuse("bundle.container_invalid", "ES-034 defines the container as an array of complete signed records; a keyed container would state each record's role a second time outside the signature that covers it");
  }
  return decoded;
}

function verifyElement(element: JsonObject, elementCanonical: Uint8Array, keyring: VerificationKeyring): void {
  // ES-035 before any version-dependent rule is applied to the record, so an
  // unpublished version is refused rather than read under a neighbour's rules.
  requirePublishedSchemaVersion(element.schema_version);
  // ES-005's closed envelope and the §5 body for this record's own type: an
  // element of a bundle is a *complete* record, not merely a signed one.
  validateRecord(element, { requireSignature: true, validateBody: true });
  // ES-033 origin dispatch plus, for an AttestationWindow, the ES-023
  // counter-signature. Dispatch is on record_type inside this call.
  verifyCanonicalEvidenceRecordWire(elementCanonical, keyring);
}

/**
 * Serialize records into the ES-034 canonical container.
 *
 * Ordering is applied here, before assembly, so one record set produces one
 * artifact regardless of the order a producer happened to hold it in. RFC 8785
 * would not supply that on its own, and QA-008's byte-identical gate would
 * otherwise report two conformant emissions of the same evidence as a
 * divergence between implementations that agree about everything that matters.
 */
export function assembleBundle(records: readonly JsonObject[]): Uint8Array {
  const elements = records
    .map((record) => Buffer.from(canonicalize(record)))
    .sort((left, right) => left.compare(right));
  const parts: Buffer[] = [Buffer.from("[")];
  for (const [index, element] of elements.entries()) {
    if (index > 0) parts.push(Buffer.from(","));
    parts.push(element);
  }
  parts.push(Buffer.from("]"));
  return new Uint8Array(Buffer.concat(parts));
}
