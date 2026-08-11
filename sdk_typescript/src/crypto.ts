import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { EvidenceError, refuse } from "./errors.ts";
import { canonicalize, type JsonValue } from "./json.ts";

const ED25519_PRIVATE_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const ED25519_PUBLIC_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function sha256Bytes(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(bytes).digest());
}

export function digestBytes(bytes: Uint8Array): string {
  return `sha256:${Buffer.from(sha256Bytes(bytes)).toString("hex")}`;
}

export function digestJson(value: JsonValue): string {
  return digestBytes(canonicalize(value));
}

export function encodeBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

export function decodeBase64Url(value: string, expectedLength?: number, code = "signature.encoding_invalid"): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) refuse(code, "base64url must be unpadded");
  let decoded: Buffer;
  try {
    decoded = Buffer.from(value, "base64url");
  } catch {
    throw new EvidenceError(code, "invalid base64url");
  }
  if (decoded.toString("base64url") !== value || (expectedLength !== undefined && decoded.length !== expectedLength)) {
    refuse(code, "invalid base64url length or encoding");
  }
  return new Uint8Array(decoded);
}

export function publicKeyFromSeed(seed: Uint8Array): Uint8Array {
  if (seed.length !== 32) refuse("signature.private_key_invalid", "Ed25519 seed must be 32 bytes");
  const privateKey = createPrivateKey({
    key: Buffer.concat([ED25519_PRIVATE_PREFIX, Buffer.from(seed)]),
    format: "der",
    type: "pkcs8",
  });
  const der = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  return new Uint8Array(der.subarray(ED25519_PUBLIC_PREFIX.length));
}

export function signEd25519(message: Uint8Array, seed: Uint8Array): Uint8Array {
  if (seed.length !== 32) refuse("signature.private_key_invalid", "Ed25519 seed must be 32 bytes");
  const privateKey = createPrivateKey({
    key: Buffer.concat([ED25519_PRIVATE_PREFIX, Buffer.from(seed)]),
    format: "der",
    type: "pkcs8",
  });
  return new Uint8Array(sign(null, Buffer.from(message), privateKey));
}

export function verifyEd25519(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean {
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  try {
    const key = createPublicKey({
      key: Buffer.concat([ED25519_PUBLIC_PREFIX, Buffer.from(publicKey)]),
      format: "der",
      type: "spki",
    });
    return verify(null, Buffer.from(message), key, Buffer.from(signature));
  } catch {
    return false;
  }
}
