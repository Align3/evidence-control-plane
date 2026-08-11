import assert from "node:assert/strict";
import { test } from "node:test";
import {
  MAX_JSON_NESTING_DEPTH,
  canonicalize,
  canonicalizeJson,
  digestBytes,
  parseCanonicalJson,
  type JsonObject,
  type JsonValue,
} from "../src/index.ts";

test("__proto__ is canonicalized as an own data member", () => {
  const input = '{"__proto__":"x","a":1}';
  const parsed = parseCanonicalJson(input) as JsonObject;
  const canonical = canonicalizeJson(input);

  assert.equal(Object.getPrototypeOf(parsed), Object.prototype);
  assert.equal(Object.hasOwn(parsed, "__proto__"), true);
  assert.equal(parsed.__proto__, "x");
  assert.equal(new TextDecoder().decode(canonical), input);
  assert.equal(digestBytes(canonical), "sha256:c93e23c5dbc318beed9c7bbcb73f47bb1a78ae39d0c6e8169f9de5e5013bdf43");
});

test("token parsing refuses excessive nesting with a stable code", () => {
  const input = `${"[".repeat(MAX_JSON_NESTING_DEPTH + 1)}0${"]".repeat(MAX_JSON_NESTING_DEPTH + 1)}`;
  assert.throws(() => canonicalizeJson(input), { code: "canonicalization.nesting_too_deep" });
});

test("programmatic values refuse excessive nesting with a stable code", () => {
  let value: JsonValue = 0;
  for (let depth = 0; depth <= MAX_JSON_NESTING_DEPTH; depth += 1) value = [value];
  assert.throws(() => canonicalize(value), { code: "canonicalization.nesting_too_deep" });
});
