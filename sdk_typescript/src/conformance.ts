import { digestBytes } from "./crypto.ts";
import { EvidenceError, refuse } from "./errors.ts";
import { canonicalize, canonicalizeJson, canonicalStringify, type JsonObject } from "./json.ts";
import { validateRecord } from "./schema.ts";
import { signRecord, verifyAttestationSignatures, verifyCustomerSignature } from "./signing.ts";
import { primarySignerNamespace } from "./origin.ts";
import { verifyCanonicalEvidenceRecordWire, verifyEvidenceRecordSignature, verifyIngestionReceipt, verifyRecordOriginSignature, verifyStream } from "./verification.ts";

export interface ConformanceVector extends JsonObject {
  id: string;
  operation: string;
  expected: JsonObject;
}

/** Execute one language-neutral ES-029 vector through the public primitives. */
export function runConformanceVector(vector: ConformanceVector): JsonObject {
  try {
    switch (vector.operation) {
      case "canonicalize": {
        const bytes = canonicalizeJson(requiredString(vector, "input_json"));
        return {
          accepted: true,
          canonical_json: new TextDecoder().decode(bytes),
          canonical_utf8_hex: Buffer.from(bytes).toString("hex"),
          digest: digestBytes(bytes),
        };
      }
      case "sign_record": {
        const record = signRecord(requiredObject(vector, "unsigned_record") as never, requiredString(vector, "key_id"), requiredString(vector, "private_key_seed"));
        return {
          accepted: true,
          signature: record.signature,
          signed_digest: record.signature.signed_digest,
          signed_record: record,
          signed_record_digest: digestBytes(canonicalize(record)),
        };
      }
      case "verify_signature": {
        const keyId = verifyCustomerSignature(requiredObject(vector, "record"), stringMap(vector, "public_keys"));
        return { accepted: true, key_id: keyId, record_digest: digestBytes(canonicalize(requiredObject(vector, "record"))) };
      }
      case "verify_attestation_signatures": {
        const result = verifyAttestationSignatures(requiredObject(vector, "record"), stringMap(vector, "evidence_public_keys"), stringMap(vector, "issuer_public_keys"));
        return { accepted: true, evidence_key_id: result.evidenceKeyId, issuer_key_id: result.issuerKeyId, record_digest: result.recordDigest };
      }
      case "verify_stream": {
        const records = requiredArray(vector, "records") as JsonObject[];
        const result = verifyStream(records, requiredObject(vector, "verification_keys") as never);
        const output: JsonObject = { accepted: true, start_sequence: result.startSequence, end_sequence: result.endSequence, last_digest: result.lastDigest, last_key_id: result.lastKeyId };
        const firstKey = isObjectValue(records[0]?.signature) ? records[0]?.signature.key_id : undefined;
        const secondKey = isObjectValue(records[1]?.signature) ? records[1]?.signature.key_id : undefined;
        if (records.length >= 2 && firstKey === secondKey) output.sequence_2_prev_digest = records[1]!.prev_digest!;
        if (records.length >= 2 && firstKey === secondKey && records[0] !== undefined && isObjectValue(records[0].signature) && typeof records[0].signature.signed_digest === "string") {
          output.signature_excluded_digest_must_differ = records[0].signature.signed_digest;
        }
        return output;
      }
      case "verify_ingestion_receipt": {
        const result = verifyIngestionReceipt(requiredObject(vector, "record"), requiredObject(vector, "receipt") as never, requiredObject(vector, "verification_keys") as never);
        return {
          accepted: true,
          canonical_json: result.canonicalJson,
          digest: result.digest,
          measured_clock_skew_ms: result.measuredClockSkewMs,
          payload: result.payload,
          record_digest: result.recordDigest,
        };
      }
      case "verify_evidence_record_signature": {
        const record = requiredObject(vector, "record");
        const keyId = verifyEvidenceRecordSignature(record, requiredObject(vector, "verification_keys") as never);
        return { accepted: true, key_id: keyId, record_digest: digestBytes(canonicalize(record)) };
      }
      case "verify_record_origin_signature": {
        const record = requiredObject(vector, "record");
        const keyId = verifyRecordOriginSignature(record, requiredObject(vector, "verification_keys") as never);
        return { accepted: true, key_id: keyId, namespace: primarySignerNamespace(record.record_type) };
      }
      case "verify_canonical_evidence_record": {
        const result = verifyCanonicalEvidenceRecordWire(Buffer.from(requiredString(vector, "received_wire_utf8_hex"), "hex"), requiredObject(vector, "verification_keys") as never);
        return { accepted: true, record_digest: result.recordDigest };
      }
      case "validate_record":
        validateRecord(requiredObject(vector, "record"), { validateBody: false });
        return { accepted: true };
      default:
        return refuse("vector.operation_unknown", `unknown vector operation ${vector.operation}`);
    }
  } catch (error) {
    if (error instanceof EvidenceError) return { accepted: false, error_code: error.code, ...error.details } as JsonObject;
    throw error;
  }
}

function requiredString(object: JsonObject, key: string): string {
  const value = object[key];
  if (typeof value !== "string") refuse("vector.invalid", `${key} must be a string`);
  return value;
}

function requiredObject(object: JsonObject, key: string): JsonObject {
  const value = object[key];
  if (value === null || typeof value !== "object" || Array.isArray(value)) refuse("vector.invalid", `${key} must be an object`);
  return value;
}

function requiredArray(object: JsonObject, key: string): unknown[] {
  const value = object[key];
  if (!Array.isArray(value)) refuse("vector.invalid", `${key} must be an array`);
  return value;
}

function stringMap(object: JsonObject, key: string): Record<string, string> {
  const value = requiredObject(object, key);
  for (const item of Object.values(value)) if (typeof item !== "string") refuse("vector.invalid", `${key} values must be strings`);
  return value as Record<string, string>;
}

function isObjectValue(value: unknown): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
