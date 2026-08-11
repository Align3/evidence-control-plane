# Evidence Control Plane TypeScript SDK

Independent EV-10 implementation of `docs/evidence-spec.md`. It does not use a
standard JSON parser on signed source text: `canonicalizeJson()` retains number
token spelling and rejects exponents, fractions, unsafe integers, non-JSON
numeric tokens, duplicate keys, and lone surrogates before canonicalization.

The package has no runtime dependencies and targets Node 22.6 or newer. Run:

```sh
npm test
npm run test:vectors
```

## Emission

`EvidenceEmitter` exposes one method for every record type in specification
section 5. It signs locally with a client-held 32-byte Ed25519 seed, advances a
per-stream sequence, and derives each `prev_digest` from the complete preceding
record including its signature. `emitCoverageGap()` performs no network I/O.

## ES-013 review instrumentation

`ReviewSurfaceInstrumentation` takes only a callback that reads the rendered
client surface. `capture()` invokes that callback after a browser paint and
digests the exact returned UTF-8 bytes (or supplied byte array). It returns
`evidence_shown_provenance: "client_rendered"`.

When actual rendered bytes are unavailable, use
`serverReconstructedEvidence()`. It always labels the result
`evidence_shown_provenance: "server_reconstructed"`; callers must not upgrade
that claim. The SDK does not attempt to reconstruct what a client should have
shown.

## Specification findings

EV-10 exposed one ES-013 ambiguity without consulting either incumbent: the
specification defines the digest algorithm but not the representation of a
rendered surface (visible text, DOM serialization, accessibility tree, or
pixels). This SDK therefore makes the representation explicit at its API
boundary and hashes the exact UTF-8/byte snapshot returned by the client after
paint, without normalization. A future specification revision should name the
representation and publish a normative review-surface vector.

Outside EV-10's schema-1 emission scope, ES-031 describes a schema-2 boundary
self-reference as `{tenant}:{name}:{version}`, but the section-5
`AssuranceBoundary` body has no boundary-name member. The SDK does not invent
one or claim full schema-2 self-reference validation.
