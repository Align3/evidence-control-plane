import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { runConformanceVector, type ConformanceVector, type JsonObject, type JsonValue } from "../src/index.ts";

const corpusPath = resolve(import.meta.dirname, "../../tests/vectors/vectors-v0.1.json");
const corpus = JSON.parse(readFileSync(corpusPath, "utf8")) as {
  vectors: ConformanceVector[];
  adversarial_vectors: ConformanceVector[];
};

let count = 0;
for (const vector of [...corpus.vectors, ...corpus.adversarial_vectors]) {
  const actual = runConformanceVector(vector);
  assertExpectedResult(vector.id, vector.expected, actual);
  count += 1;
}

console.log(`TypeScript reproduced ${count} ES-029 conformance vectors`);

function assertExpectedResult(id: string, expected: JsonObject, actual: JsonObject): void {
  assert.deepEqual(actual, expected, `${id}: complete result differs`);
}
