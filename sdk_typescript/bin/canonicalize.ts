import { readFileSync } from "node:fs";
import { canonicalizeJson, digestBytes } from "../src/index.ts";

const source = process.argv[2] === undefined ? readFileSync(0, "utf8") : readFileSync(process.argv[2], "utf8");
try {
  const canonical = canonicalizeJson(source);
  process.stdout.write(canonical);
  process.stderr.write(`digest ${digestBytes(canonical)}\n`);
} catch (error) {
  const code = error !== null && typeof error === "object" && "code" in error ? String(error.code) : "canonicalization.failed";
  process.stderr.write(`${code}\n`);
  process.exitCode = 1;
}
