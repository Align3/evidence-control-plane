// Independent RFC 8785 (JCS) reference used only by the differential test.
//
// This is NOT an implementation we ship, and it is deliberately not derived
// from sdk_python/evidence/canonical.py. It is built straight out of
// ECMAScript primitives that RFC 8785 is itself defined in terms of:
//
//   * Array.prototype.sort() on strings compares UTF-16 code units (ECMA-262
//     7.2.13), which is exactly the property ordering RFC 8785 3.2.3 requires.
//   * JSON.stringify(aString) is the string-escaping function RFC 8785 3.2.2.2
//     delegates to.
//   * String(aNumber) is Number::toString, the RFC 8785 3.2.2.3 number form.
//
// Its purpose is to catch a canonicalizer that is deterministic, stable, and
// self-consistent while being wrong -- the failure mode no self-referential
// property test can see. It stands in for the Go verifier's independent
// reproduction (AG-011) until EV-05 lands. It does not weaken AC-011: nothing
// here is shared with, or reachable from, the Python or Go implementations.

function jcs(v) {
  if (v === null) return "null";
  const t = typeof v;
  if (t === "boolean") return v ? "true" : "false";
  if (t === "number") {
    if (!Number.isFinite(v)) throw new Error("non-finite number");
    return Object.is(v, -0) ? "0" : String(v);
  }
  if (t === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(jcs).join(",") + "]";
  if (t === "object") {
    const keys = Object.keys(v).sort(); // UTF-16 code-unit order
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + jcs(v[k])).join(",") + "}";
  }
  throw new Error("unsupported type " + t);
}

let buf = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (d) => (buf += d));
process.stdin.on("end", () => {
  const out = JSON.parse(buf).map((c) => {
    try {
      return jcs(c);
    } catch (e) {
      return "ERROR:" + e.message;
    }
  });
  process.stdout.write(JSON.stringify(out));
});
