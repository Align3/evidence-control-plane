import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { CONFORMANCE_OPERATIONS, runConformanceVector, type ConformanceVector, type JsonObject, type JsonValue } from "../src/index.ts";

const corpusPath = resolve(import.meta.dirname, "../../tests/vectors/vectors-v0.1.json");
const corpus = JSON.parse(readFileSync(corpusPath, "utf8")) as {
  vectors: ConformanceVector[];
  adversarial_vectors: ConformanceVector[];
};

const all = [...corpus.vectors, ...corpus.adversarial_vectors];

// ES-029 makes the corpus normative, so an operation published there and not
// implemented here is TypeScript drifting out of conformance -- not a corpus
// defect. Naming the operations before running anything reports that as the
// missing entry point it is, rather than as whichever vector happens to be
// reached first.
const published = [...new Set(all.map((vector) => vector.operation))].sort();
const missing = published.filter((operation) => !CONFORMANCE_OPERATIONS.includes(operation));
assert.deepEqual(missing, [], `published vector operations with no TypeScript runner: ${missing.join(", ")}`);

let count = 0;
const perOperation = new Map<string, number>();
for (const vector of all) {
  const actual = runConformanceVector(vector);
  assert.notEqual(actual.error_code, "vector.operation_unknown", `${vector.id}: ${vector.operation} is listed as implemented but is not dispatched`);
  assertExpectedResult(vector.id, vector.expected, actual);
  count += 1;
  perOperation.set(vector.operation, (perOperation.get(vector.operation) ?? 0) + 1);
}

const breakdown = [...perOperation.entries()].sort().map(([operation, total]) => `${operation}=${total}`).join(" ");
console.log(`TypeScript reproduced ${count} ES-029 conformance vectors across ${perOperation.size} operations (${breakdown})`);

function assertExpectedResult(id: string, expected: JsonObject, actual: JsonObject): void {
  assert.deepEqual(actual, expected, `${id}: complete result differs`);
}
