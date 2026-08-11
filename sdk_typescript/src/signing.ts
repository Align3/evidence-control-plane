import { decodeBase64Url, digestBytes, encodeBase64Url, sha256Bytes, signEd25519, verifyEd25519 } from "./crypto.ts";
import { refuse } from "./errors.ts";
import { canonicalize, type JsonObject } from "./json.ts";
import { isObject, validateRecord } from "./schema.ts";
import type { CustomerSignature, SignedEvidenceRecord, UnsignedEvidenceRecord } from "./types.ts";

const CUSTOMER_REQUIRED = ["alg", "key_id", "sig", "signed_digest"] as const;
const CUSTOMER_ALLOWED = new Set([...CUSTOMER_REQUIRED, "key_continuity", "issuer"]);
const ISSUER_REQUIRED = ["alg", "key_id", "sig", "signed_digest"] as const;
const ISSUER_ALLOWED = new Set(ISSUER_REQUIRED);

export function signRecord<T extends UnsignedEvidenceRecord>(record: T, keyId: string, privateKeySeed: Uint8Array | string): SignedEvidenceRecord {
  const unsigned = { ...record } as JsonObject;
  delete unsigned.signature;
  validateRecord(unsigned, { validateBody: true });
  const canonical = canonicalize(unsigned);
  const digest = sha256Bytes(canonical);
  const signature: CustomerSignature = {
    alg: "ed25519",
    key_id: keyId,
    sig: encodeBase64Url(signEd25519(digest, normalizeSeed(privateKeySeed))),
    signed_digest: digestBytes(canonical) as `sha256:${string}`,
  };
  return { ...record, signature } as SignedEvidenceRecord;
}

export function verifyCustomerSignature(record: JsonObject, publicKeys: Record<string, string>): string {
  if (!isObject(record.signature)) refuse("signature.missing_customer_member", "signature object is required");
  const signature = record.signature;
  validateClosedMembers(signature, CUSTOMER_REQUIRED, CUSTOMER_ALLOWED, "customer");
  if (Object.hasOwn(signature, "issuer") && record.record_type !== "AttestationWindow") {
    refuse("signature.unknown_customer_member", "only AttestationWindow may carry an issuer counter-signature");
  }
  if (signature.key_continuity === null) {
    refuse("schema.optional_null_forbidden", "key_continuity must be absent rather than null");
  }
  if (signature.alg !== "ed25519") refuse("signature.algorithm_unsupported", "only ed25519 is supported");
  if (typeof signature.key_id !== "string" || typeof signature.sig !== "string" || typeof signature.signed_digest !== "string") {
    refuse("signature.missing_customer_member", "customer signature fields have invalid types");
  }
  const publicKey = publicKeys[signature.key_id];
  if (publicKey === undefined) refuse("signature.key_unknown", `unknown customer key ${signature.key_id}`);
  const signatureBytes = decodeBase64Url(signature.sig, 64);
  const publicKeyBytes = decodeBase64Url(publicKey, 32);
  const unsigned = { ...record };
  delete unsigned.signature;
  const canonical = canonicalize(unsigned);
  const expectedDigest = digestBytes(canonical);
  if (signature.signed_digest !== expectedDigest) refuse("signature.digest_mismatch", "signed_digest does not match record");
  if (!verifyEd25519(sha256Bytes(canonical), signatureBytes, publicKeyBytes)) {
    refuse("signature.invalid", "customer signature is invalid");
  }
  return signature.key_id;
}

export function addIssuerSignature(record: SignedEvidenceRecord<"AttestationWindow">, keyId: string, privateKeySeed: Uint8Array | string): SignedEvidenceRecord<"AttestationWindow"> {
  const customer = { ...record.signature };
  delete customer.issuer;
  const issuerInput = { ...record, signature: customer } as JsonObject;
  const canonical = canonicalize(issuerInput);
  const digest = sha256Bytes(canonical);
  return {
    ...record,
    signature: {
      ...customer,
      issuer: {
        alg: "ed25519",
        key_id: keyId,
        sig: encodeBase64Url(signEd25519(digest, normalizeSeed(privateKeySeed))),
        signed_digest: digestBytes(canonical),
      },
    },
  } as SignedEvidenceRecord<"AttestationWindow">;
}

export function verifyAttestationSignatures(record: JsonObject, evidenceKeys: Record<string, string>, issuerKeys: Record<string, string>): { evidenceKeyId: string; issuerKeyId: string; recordDigest: string } {
  if (!isObject(record.signature)) refuse("signature.missing_customer_member", "signature object is required");
  const signature = record.signature;
  validateClosedMembers(signature, CUSTOMER_REQUIRED, CUSTOMER_ALLOWED, "customer");
  if (!isObject(signature.issuer)) refuse("signature.missing_issuer_member", "AttestationWindow requires issuer signature");
  validateClosedMembers(signature.issuer, ISSUER_REQUIRED, ISSUER_ALLOWED, "issuer");

  const evidenceKeyId = verifyCustomerSignature(record, evidenceKeys);
  const issuer = signature.issuer;
  if (issuer.alg !== "ed25519") refuse("signature.algorithm_unsupported", "only ed25519 is supported");
  if (typeof issuer.key_id !== "string" || typeof issuer.sig !== "string" || typeof issuer.signed_digest !== "string") {
    refuse("signature.missing_issuer_member", "issuer signature fields have invalid types");
  }
  const publicKey = issuerKeys[issuer.key_id];
  if (publicKey === undefined) refuse("signature.key_unknown", `unknown issuer key ${issuer.key_id}`);
  const issuerInput = { ...record, signature: { ...signature } } as JsonObject;
  delete (issuerInput.signature as JsonObject).issuer;
  const canonical = canonicalize(issuerInput);
  if (issuer.signed_digest !== digestBytes(canonical)) refuse("signature.issuer_digest_mismatch", "issuer signed_digest does not match record");
  if (!verifyEd25519(sha256Bytes(canonical), decodeBase64Url(issuer.sig, 64), decodeBase64Url(publicKey, 32))) {
    refuse("signature.issuer_invalid", "issuer signature is invalid");
  }
  return { evidenceKeyId, issuerKeyId: issuer.key_id, recordDigest: digestBytes(canonicalize(record)) };
}

function validateClosedMembers(object: JsonObject, required: readonly string[], allowed: ReadonlySet<string>, kind: "customer" | "issuer"): void {
  for (const key of Object.keys(object)) {
    if (!allowed.has(key)) refuse(`signature.unknown_${kind}_member`, `unknown ${kind} signature member: ${key}`);
  }
  for (const key of required) {
    if (!Object.hasOwn(object, key)) refuse(`signature.missing_${kind}_member`, `missing ${kind} signature member: ${key}`);
  }
}

function normalizeSeed(seed: Uint8Array | string): Uint8Array {
  return typeof seed === "string" ? decodeBase64Url(seed, 32, "signature.private_key_invalid") : seed;
}
