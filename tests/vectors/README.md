# Evidence conformance vectors v0.1

`vectors-v0.1.json` is normative under ES-029. A conforming implementation
consumes every entry in both `vectors` and `adversarial_vectors` according to
its `operation` and reaches the exact `expected` result. The file is UTF-8
JSON; binary values use unpadded base64url and canonical byte strings are also
published as lowercase hexadecimal.

The two collections answer different questions:

- `vectors` are agreement vectors. They pin exact behavior independently
  across implementations, but agreement is not proof of correctness: two
  implementations built from the same incomplete specification can accept the
  same attack.
- `adversarial_vectors` are refusal probes, held separately so their purpose
  cannot be mistaken for divergence detection. They are created by attempting
  to make a complete public entry point accept an invalid artifact, especially
  where a correct primitive can be bypassed by a weaker composition path. A
  **regression probe** must record, per implementation and against a named
  revision, what each did with the same subject before the fix; at least one
  must have accepted it. A **new-rule probe** cannot truthfully record a prior
  acceptance because no implementation was then obliged to perform the check.
  It instead records the requirement ID and the full commit that introduced
  that requirement. A probe must carry exactly one of those provenance forms.

The corpus deliberately contains private Ed25519 seeds. They are deterministic
test material only, never deployment keys. Including them lets an independent
writer reproduce the expected signatures rather than merely verify bytes
produced by Python.

Object member names are always data. In particular, `__proto__` MUST survive
parsing and canonicalization as an enumerable own member. Assigning parsed
members into a normal JavaScript object with `result[key] = value` invokes the
legacy inherited prototype setter for that name and silently drops signed
content. `canonical-prototype-key` fixes the required bytes and digest for this
JavaScript-specific interoperability trap.

Operations:

- `canonicalize`: parse `input_json`, then produce JCS bytes and an ES-003
  digest, or reject the prohibited input.
- `sign_record`: sign `unsigned_record` with the supplied seed and reproduce
  the complete `signed_record` byte-for-byte.
- `verify_signature`: validate a primary signature cryptographically and its closed member set.
- `verify_attestation_signatures`: validate the structurally distinct customer
  and issuer signatures and both closed member sets.
- `verify_stream`: validate chain links, authenticated forks, sequence gaps,
  per-stream trust anchors, context-bound key rotation, and the ES-033
  record-origin namespace of every active key. Every stream vector carries
  `verification_keys`; a harness must not infer namespaces from `public_keys`.
- `verify_record_origin_signature`: validate a complete primary proof and
  dispatch its required namespace from the closed record-type map.
- `verify_canonical_evidence_record`: run the complete canonical-wire,
  record-origin, and type-specific signature path. Adversarial namespace
  substitutions use this operation rather than stopping at a primitive.
- `verify_bundle`: validate an ES-034 bundle from the exact UTF-8 bytes in
  `bundle_utf8_hex`, at the explicit evaluation instant, and reproduce the
  complete structured verdict. Optional `revocation_response` contains the
  issuer endpoint's HTTP status and exact response bytes.

Regression adversarial vectors carry structured `pre_fix.implementations`
results. Every result states the shipping entry point, whether it accepted,
and the observed result at `pre_fix.revision`. At least one shipping entry
point must have accepted the subject. Harness-only observations are recorded
separately and do not satisfy that provenance requirement. New-rule probes
carry `new_rule.requirement` and `new_rule.introduced_by` instead.

`requirement_coverage` is the QA-019 declared-absence register. `covered` maps
each attributed requirement to the vectors that exercise it;
`declared_absent` names every defined requirement with no attributed vector,
and `declared_absent_count` repeats the count so a consumer can report it
without silently treating an omitted collection as zero. The test harness
recomputes and checks all three.

Rejected vectors return stable dotted `error_code` values, not Python exception
names or English messages. The first component identifies the rule family
(`canonicalization`, `signature`, `chain`, or `continuity`) and the remainder
identifies the refusal reason. Implementations may use any native error type and
wording while agreeing on that semantic result.

`generate.py` is deterministic. Regeneration is not an approval mechanism: a
changed vector is a normative format change and its byte diff must be reviewed.
`test_vectors.py` refuses drift and executes every stored vector through the
Python implementation. The Go conformance package independently executes the
same corpus and refuses an operation for which it has no runner.

## Implementer note: sub-millisecond `source_time`

`clock_skew_ms` truncates the sub-millisecond remainder **toward zero**
(ES-030). That is not a floor, and the difference is only observable when the
collector clock ran ahead of ours:

| exact skew | truncate (correct) | floor (wrong) |
|---|---|---|
| `-500 us` | `0` | `-1` |
| `-1000500 us` | `-1000` | `-1001` |
| `+999500 us` | `999` | `999` |

Positive skews cannot distinguish the two, so an implementation tested only on
late-arriving records will look correct. `receipt-negative-sub-millisecond-skew-truncates-to-zero`
and `receipt-negative-skew-truncates-toward-zero-not-downward` exist for this
and nothing else.

Two traps for a port:

* Python's `//` floors. `-1 // 2 == -1`, not `0`. Go's `/` truncates. A
  direct transliteration in either direction is wrong on one of them.
* The remainder can only originate in `source_time`, which the customer
  supplies -- `ingest_time` is quantised to whole milliseconds before the
  measurement. An implementation whose time type is millisecond-resolution
  cannot represent these inputs at all and will silently compute a different
  skew. JavaScript `Date` is such a type: `Date.parse` collapses
  `12:00:00.0005` and `12:00:00.000` to the same instant. Parse the fractional
  field exactly rather than through a millisecond clock.
