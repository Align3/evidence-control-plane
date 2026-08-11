import { decodeBase64Url, digestBytes, sha256Bytes, verifyEd25519 } from "./crypto.ts";
import { EvidenceError, refuse } from "./errors.ts";
import { canonicalize, canonicalStringify, parseCanonicalJson, type JsonObject, type JsonValue } from "./json.ts";
import { isObject, validateRecord } from "./schema.ts";
import { verifyAttestationSignatures, verifyCustomerSignature } from "./signing.ts";
import type { VerificationKeyring } from "./types.ts";

const CONTINUITY_REQUIRED = ["alg", "predecessor_key_id", "new_key_id", "new_public_key", "tenant_id", "stream_id", "sig"] as const;
const CONTINUITY_ALLOWED: ReadonlySet<string> = new Set(CONTINUITY_REQUIRED);

export function verifyEvidenceRecordSignature(record: JsonObject, keyring: VerificationKeyring): string {
  if (!isObject(record.signature) || typeof record.signature.key_id !== "string") {
    refuse("signature.missing_customer_member", "record signature is missing key_id");
  }
  const keyId = record.signature.key_id;
  const key = keyring[keyId];
  if (key === undefined) refuse("signature.key_unknown", `unknown evidence key ${keyId}`);
  if (key.namespace !== "evidence") refuse("key.namespace_mismatch", `${keyId} is not an evidence key`);
  return verifyCustomerSignature(record, { [keyId]: key.public_key });
}

export function verifyCanonicalEvidenceRecordWire(wire: Uint8Array, keyring: VerificationKeyring): { recordDigest: string } {
  let parsed: JsonValue;
  try {
    parsed = parseCanonicalJson(new TextDecoder("utf-8", { fatal: true }).decode(wire));
  } catch (error) {
    if (error instanceof EvidenceError) throw error;
    return refuse("wire.invalid_utf8", "record wire is not UTF-8");
  }
  if (!isObject(parsed)) refuse("schema.record_invalid", "record must be an object");
  const canonical = canonicalize(parsed);
  if (!Buffer.from(canonical).equals(Buffer.from(wire))) refuse("wire.non_canonical", "received bytes are not canonical JSON");

  // Signature composition is checked before body completeness so a missing
  // AttestationWindow counter-signature cannot be hidden by another defect.
  validateRecord(parsed, { requireSignature: true, validateBody: false });
  if (parsed.record_type === "AttestationWindow") {
    if (!isObject(parsed.signature) || !isObject(parsed.signature.issuer)) {
      refuse("signature.missing_issuer_member", "AttestationWindow requires issuer counter-signature");
    }
    const evidenceKeys: Record<string, string> = {};
    const issuerKeys: Record<string, string> = {};
    for (const [keyId, key] of Object.entries(keyring)) {
      (key.namespace === "evidence" ? evidenceKeys : issuerKeys)[keyId] = key.public_key;
    }
    verifyAttestationSignatures(parsed, evidenceKeys, issuerKeys);
  } else {
    verifyEvidenceRecordSignature(parsed, keyring);
  }
  return { recordDigest: digestBytes(canonical) };
}

export interface StreamVerificationResult {
  startSequence: number;
  endSequence: number;
  lastDigest: string;
  lastKeyId: string;
}

export function verifyStream(records: JsonObject[], keyring: VerificationKeyring): StreamVerificationResult {
  if (records.length === 0) refuse("chain.empty", "stream is empty");
  const streamId = records[0]!.stream_id;
  if (typeof streamId !== "string") refuse("chain.stream_id_mismatch", "stream_id is missing");
  if (records.some((record) => record.stream_id !== streamId)) refuse("chain.stream_id_mismatch", "records have mixed stream_id values");

  const seen = new Map<number, string>();
  for (const record of records) {
    if (!Number.isSafeInteger(record.sequence)) refuse("chain.sequence_gap", "record sequence is invalid");
    const sequence = record.sequence as number;
    const priorId = seen.get(sequence);
    if (priorId !== undefined && priorId !== record.record_id) {
      refuse("chain.fork", `authenticated fork at sequence ${sequence}`, { break_sequence: sequence, attestation_permitted: false });
    }
    if (typeof record.record_id === "string") seen.set(sequence, record.record_id);
  }

  let priorRecord: JsonObject | undefined;
  let priorKeyId: string | undefined;
  let priorDigest: string | undefined;
  let expectedSequence = 1;
  for (const record of records) {
    const sequence = record.sequence as number;
    if (sequence !== expectedSequence) {
      const details: Record<string, unknown> = { break_sequence: sequence };
      if (expectedSequence > 1) details.valid_through_sequence = expectedSequence - 1;
      refuse("chain.sequence_gap", `expected sequence ${expectedSequence}, received ${sequence}`, details);
    }
    if (!isObject(record.signature) || typeof record.signature.key_id !== "string") {
      refuse("signature.missing_customer_member", `missing signature at sequence ${sequence}`);
    }
    const signature = record.signature;
    const keyIdValue = signature.key_id;
    if (typeof keyIdValue !== "string") refuse("signature.missing_customer_member", `missing signature key_id at sequence ${sequence}`);
    const keyId = keyIdValue;
    const continuity = signature.key_continuity;
    if (sequence === 1 && continuity !== undefined) {
      refuse("continuity.first_record_forbidden", "sequence 1 cannot carry continuity", { break_sequence: 1 });
    }
    const registered = keyring[keyId];
    if (registered === undefined) refuse("signature.key_unknown", `unknown key ${keyId}`);
    if (registered.namespace !== "evidence") refuse("key.namespace_mismatch", `${keyId} is not an evidence key`);

    if (priorRecord !== undefined) {
      if (record.prev_digest !== priorDigest) {
        refuse("chain.prev_digest_mismatch", `prev_digest mismatch at sequence ${sequence}`, { break_sequence: sequence, valid_through_sequence: sequence - 1 });
      }
      if (keyId === priorKeyId && continuity !== undefined) {
        refuse("continuity.no_key_change", "continuity supplied without a key change", { break_sequence: sequence, valid_through_sequence: sequence - 1 });
      }
      if (keyId !== priorKeyId && continuity === undefined) {
        refuse("continuity.missing", "key rotation lacks continuity", { break_sequence: sequence, valid_through_sequence: sequence - 1 });
      }
      if (continuity !== undefined) {
        try {
          verifyContinuity(continuity, record, priorKeyId!, keyId, keyring);
        } catch (error) {
          if (!(error instanceof EvidenceError)) throw error;
          const details: Record<string, unknown> = { break_sequence: sequence };
          if (error.code === "continuity.signature_invalid") details.valid_through_sequence = sequence - 1;
          throw new EvidenceError(error.code, error.message, details);
        }
      }
    } else if (record.prev_digest !== null) {
      refuse("chain.prev_digest_mismatch", "sequence 1 prev_digest must be null");
    }

    verifyCustomerSignature(record, { [keyId]: registered.public_key });
    priorDigest = digestBytes(canonicalize(record));
    priorRecord = record;
    priorKeyId = keyId;
    expectedSequence += 1;
  }
  return {
    startSequence: 1,
    endSequence: records.length,
    lastDigest: priorDigest!,
    lastKeyId: priorKeyId!,
  };
}

function verifyContinuity(value: JsonValue, record: JsonObject, predecessorKeyId: string, newKeyId: string, keyring: VerificationKeyring): void {
  if (!isObject(value)) refuse("continuity.missing_member", "continuity must be an object");
  for (const key of Object.keys(value)) {
    if (!CONTINUITY_ALLOWED.has(key)) refuse("continuity.unknown_member", `unknown continuity member: ${key}`);
  }
  for (const key of CONTINUITY_REQUIRED) {
    if (!Object.hasOwn(value, key)) refuse("continuity.missing_member", `missing continuity member: ${key}`);
  }
  if (value.tenant_id !== record.tenant_id) refuse("continuity.tenant_mismatch", "continuity tenant_id does not match record");
  if (value.stream_id !== record.stream_id) refuse("continuity.stream_mismatch", "continuity stream_id does not match record");
  if (value.alg !== "ed25519") refuse("continuity.algorithm_unsupported", "continuity algorithm must be ed25519");
  if (value.predecessor_key_id !== predecessorKeyId || value.new_key_id !== newKeyId) {
    refuse("continuity.key_mismatch", "continuity key identifiers do not match rotation");
  }
  if (typeof value.new_public_key !== "string" || typeof value.sig !== "string") {
    refuse("continuity.missing_member", "continuity key/signature types are invalid");
  }
  const newKey = keyring[newKeyId];
  const predecessorKey = keyring[predecessorKeyId];
  if (newKey === undefined || predecessorKey === undefined) refuse("signature.key_unknown", "continuity key is not registered");
  if (newKey.namespace !== "evidence" || predecessorKey.namespace !== "evidence") refuse("key.namespace_mismatch", "continuity keys must be evidence keys");
  if (value.new_public_key !== newKey.public_key) refuse("continuity.new_public_key_mismatch", "continuity public key does not match keyring");
  const signed = { ...value };
  delete signed.sig;
  if (!verifyEd25519(canonicalize(signed), decodeBase64Url(value.sig, 64, "continuity.encoding_invalid"), decodeBase64Url(predecessorKey.public_key, 32, "continuity.encoding_invalid"))) {
    refuse("continuity.signature_invalid", "continuity signature is invalid");
  }
}

export interface IngestionReceipt {
  canonical_utf8_hex: string;
  key_id: string;
  signature: string;
}

export interface ReceiptVerificationResult {
  canonicalJson: string;
  digest: string;
  measuredClockSkewMs: number;
  payload: JsonObject;
  recordDigest: string;
}

export function verifyIngestionReceipt(record: JsonObject, receipt: IngestionReceipt, keyring: VerificationKeyring): ReceiptVerificationResult {
  const key = keyring[receipt.key_id];
  if (key === undefined) refuse("signature.key_unknown", `unknown receipt key ${receipt.key_id}`);
  if (key.namespace !== "issuer") refuse("key.namespace_mismatch", `${receipt.key_id} is not an issuer key`);
  if (!/^(?:[0-9a-f]{2})+$/.test(receipt.canonical_utf8_hex)) refuse("receipt.encoding_invalid", "receipt canonical bytes must be lowercase hex");
  const bytes = new Uint8Array(Buffer.from(receipt.canonical_utf8_hex, "hex"));
  let payloadValue: JsonValue;
  try {
    payloadValue = parseCanonicalJson(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return refuse("receipt.payload_invalid", "receipt payload is not canonical JSON");
  }
  if (!isObject(payloadValue)) refuse("receipt.payload_invalid", "receipt payload must be an object");
  const payload = payloadValue;
  const fields = Object.keys(payload).sort();
  if (fields.join(",") !== "clock_skew_ms,ingest_time,record_digest") refuse("receipt.payload_invalid", "receipt payload member set is not exact");
  if (!Buffer.from(canonicalize(payload)).equals(Buffer.from(bytes))) refuse("receipt.non_canonical", "receipt bytes are not canonical");
  if (!verifyEd25519(bytes, decodeBase64Url(receipt.signature, 64, "receipt.encoding_invalid"), decodeBase64Url(key.public_key, 32, "receipt.encoding_invalid"))) {
    refuse("receipt.signature_invalid", "receipt signature is invalid", { customer_record_bytes_unchanged: true });
  }
  const recordDigest = digestBytes(canonicalize(record));
  if (payload.record_digest !== recordDigest) refuse("receipt.record_mismatch", "receipt is bound to another complete record");
  if (typeof payload.ingest_time !== "string" || !Number.isSafeInteger(payload.clock_skew_ms)) {
    refuse("receipt.payload_invalid", "receipt clock fields have invalid types");
  }
  if (!isObject(record.clocks) || typeof record.clocks.source_time !== "string") {
    refuse("schema.source_time_required", "customer record source_time is required");
  }
  const measured = Number((parseTimestampNanoseconds(payload.ingest_time) - parseTimestampNanoseconds(record.clocks.source_time)) / 1_000_000n);
  if (payload.clock_skew_ms !== measured) refuse("receipt.clock_skew_mismatch", "receipt clock_skew_ms is not measured from source_time");
  return {
    canonicalJson: canonicalStringify(payload),
    digest: digestBytes(bytes),
    measuredClockSkewMs: measured,
    payload,
    recordDigest,
  };
}

/** Exact RFC 3339 parsing so sub-millisecond source timestamps are retained. */
export function parseTimestampNanoseconds(value: string): bigint {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{3,9})(Z|([+-])(\d{2}):(\d{2}))$/.exec(value);
  if (match === null) refuse("schema.timestamp_invalid", "timestamp must carry 3-9 fractional digits and an explicit offset");
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number);
  const epochMilliseconds = Date.UTC(year!, month! - 1, day!, hour!, minute!, second!, 0);
  const check = new Date(epochMilliseconds);
  if (check.getUTCFullYear() !== year || check.getUTCMonth() !== month! - 1 || check.getUTCDate() !== day || check.getUTCHours() !== hour || check.getUTCMinutes() !== minute || check.getUTCSeconds() !== second) {
    refuse("schema.timestamp_invalid", "timestamp contains an invalid calendar value");
  }
  const fractionNanoseconds = BigInt(match[7]!.padEnd(9, "0"));
  let offsetMinutes = 0;
  if (match[8] !== "Z") {
    offsetMinutes = Number(match[10]) * 60 + Number(match[11]);
    if (Number(match[10]) > 23 || Number(match[11]) > 59) refuse("schema.timestamp_invalid", "timestamp offset is invalid");
    if (match[9] === "-") offsetMinutes *= -1;
  }
  return BigInt(epochMilliseconds - offsetMinutes * 60_000) * 1_000_000n + fractionNanoseconds;
}
