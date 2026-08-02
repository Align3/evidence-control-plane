# Evidence conformance vectors v0.1

`vectors-v0.1.json` is normative under ES-029. A conforming implementation
consumes every entry according to its `operation` and reaches the exact
`expected` result. The file is UTF-8 JSON; binary values use unpadded base64url
and canonical byte strings are also published as lowercase hexadecimal.

The corpus deliberately contains private Ed25519 seeds. They are deterministic
test material only, never deployment keys. Including them lets an independent
writer reproduce the expected signatures rather than merely verify bytes
produced by Python.

Operations:

- `canonicalize`: parse `input_json`, then produce JCS bytes and an ES-003
  digest, or reject the prohibited input.
- `sign_record`: sign `unsigned_record` with the supplied seed and reproduce
  the complete `signed_record` byte-for-byte.
- `verify_signature`: validate a customer signature and its closed member set.
- `verify_attestation_signatures`: validate the structurally distinct customer
  and issuer signatures and both closed member sets.
- `verify_stream`: validate chain links, authenticated forks, sequence gaps,
  per-stream trust anchors, and context-bound key rotation.

Rejected vectors return stable dotted `error_code` values, not Python exception
names or English messages. The first component identifies the rule family
(`canonicalization`, `signature`, `chain`, or `continuity`) and the remainder
identifies the refusal reason. Implementations may use any native error type and
wording while agreeing on that semantic result.

`generate.py` is deterministic. Regeneration is not an approval mechanism: a
changed vector is a normative format change and its byte diff must be reviewed.
`test_vectors.py` refuses drift and executes every stored vector through the
Python implementation. EV-05 must implement the same operations independently
in Go; until that happens, AG-011 remains explicitly unsatisfied.
