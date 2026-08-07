# Agent Evidence Specification

**Version:** 0.1 draft
**Repo location:** `docs/evidence-spec.md`
**Status:** unstable. Field names and semantics may change until v1.0. Do not build external integrations against this version without coordination.
**Audience:** implementers of collectors, gateways, verifiers, and destination connectors — including third parties.
**Depends on:** `coverage-methodology.md`
**Drives:** `architecture.md`, `api.md`, `verifier-conformance.md`

---

## 0. Nature of this document

This is the artifact we publish. It is the abstraction boundary of the entire system: everything upstream (collection) and downstream (reconciliation, coverage, attestation, verification) plugs into it. It is also the moat, in the sense that adoption of the schema by parties other than us is the thing that makes the company hard to displace.

It follows that this document is written to be implemented by someone who does not work here and cannot ask us questions.

Conformance keywords MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are used per RFC 2119.

Requirements carry IDs `ES-nnn`. Scenarios in §12 reference them.

---

## 1. Design goals

1. **Independently verifiable.** A relying party with the bundle, the public keys, and a verifier MUST be able to reach the same conclusion we do, offline.
2. **Honest about gaps.** The schema MUST be able to express what was not captured. A format that can only describe what happened is unfit for purpose.
3. **Language-neutral.** No construct may depend on the serialization behaviour of a particular runtime.
4. **Stable under versioning.** Records written under v0.1 MUST remain verifiable after v1.0 ships.
5. **Minimal by default.** Sensitive content is referenced by digest unless explicitly configured otherwise.

### 1.1 Non-goals

Not a telemetry or tracing format — no spans, no sampling, no performance instrumentation. Not a policy language. Not a transport specification.

---

## 2. Canonical form

**ES-001** — Records MUST be serialized as JSON canonicalized per RFC 8785 (JCS) for the purposes of hashing and signing. An ingestion endpoint MUST compare the received wire bytes with the canonical form of the parsed record and reject any difference as `wire.non_canonical`; it MUST NOT silently normalize the request and report an invalid-signature error instead.

**ES-002** — Numbers MUST NOT be represented as IEEE-754 floats anywhere in a signed record. Monetary and quantity values MUST be strings with an accompanying unit or currency field. Timestamps MUST be RFC 3339 with explicit offset and at least millisecond precision.

**ES-002a** — It follows that every JSON number appearing in a signed record MUST be an integer in the interoperable range −(2^53−1) to 2^53−1 inclusive. A conformant canonicalizer MUST **reject** — not serialize — any JSON number carrying a fraction or an exponent, any integer outside that range, and the non-JSON tokens `NaN`, `Infinity`, and `-Infinity`. The ECMAScript number-serialization rules that RFC 8785 §3.2.2.3 inherits from `Number::toString` therefore never execute against conformant input, and implementations are not required to agree on floating-point formatting because no conformant record contains a floating-point value.

> **Why this is stated normatively rather than left implied.** ES-002 alone constrains what a record *author* may write. Without ES-002a an implementer could reasonably read it as silent on what a *canonicalizer* must do with a number it nonetheless encounters, and implement full RFC 8785 number serialization. Two implementations would then disagree the first time any producer emitted `1.5` — and because ES-S-007 compares only the vectors, the disagreement would surface as an unexplained verification failure long after the fact. Values requiring more precision or range than a safe integer are carried as strings per ES-002.

**ES-002b** — A member that this specification marks *optional* is encoded by **absence**. Serializing such a member with the value `null` MUST be rejected, so that one record has exactly one canonical form. This is distinct from a member that is required but nullable — `coverage_ratio` (ES-017), `reversible_until`, `compensation_ref`, `reversal_ref`, `superseding_ref`, and `actions_during_gap` — where the explicit `null` is a claim about the world and MUST be present. Rejection is performed during schema validation, not during canonicalization: canonicalization remains pure RFC 8785 and never adds, removes, or rewrites a member, so that a verifier may use an unmodified JCS library.

**ES-003** — Digests are SHA-256, lowercase hex, prefixed `sha256:`.

**ES-004** — Identifiers are UUIDv7, rendered lowercase. UUIDv7 is specified for the embedded timestamp ordering, which aids operational debugging; ordering guarantees for verification derive from the sequence field, not the identifier.

> **Implementer note.** Canonicalization is the most common source of cross-implementation divergence. Two implementations that agree on semantics but disagree on byte-level serialization will fail verification for reasons that are extremely hard to debug. The conformance vectors in `verifier-conformance.md` exist primarily to catch this.

> **Implementer note — parse at the token level, not through your standard library.** Conformance to §2 generally cannot be reached by handing input to a general-purpose JSON parser and inspecting the result, because the rules here constrain the *source token* and most standard libraries have already discarded it by the time you see a value.
>
> Two concrete losses, both silent:
>
> * **The fraction and exponent ban is a property of the token.** ES-002a refuses any number carrying a fraction or an exponent, which is why `1e0` is refused even though its value is the integer 1. Once a token has become a double there is nothing left to distinguish `1e0` from `1`, and an implementation that checks the parsed value instead of the token accepts input this specification refuses.
> * **Surrogate handling is usually normalized away.** ES requires an unpaired surrogate to be **rejected**. Go's `encoding/json` substitutes U+FFFD; JavaScript's `JSON.parse` admits lone surrogates into strings that later encode as U+FFFD; Python's `json` accepts them and defers the failure to encoding time. Each turns a refusal into a different byte string, and whatever is signed afterwards inherits that substitution.
>
> The practical consequence is that an implementer who reaches for the obvious library will usually produce something that passes casual testing, fails the vectors on a handful of inputs, and — if the vectors are skipped — interoperates until the first record containing one of these constructions. Run the vectors. They are normative under ES-029 precisely because this class of defect is invisible without them.

---

## 3. Record envelope

Every record shares an envelope.

| Field | Type | Required | Meaning |
|---|---|---|---|
| `record_id` | uuid7 | yes | Unique within tenant |
| `record_type` | string | yes | One of §5 |
| `schema_version` | string | yes | Semver of this spec |
| `tenant_id` | string | yes | Issuing tenant |
| `boundary_ref` | string | yes | Assurance boundary version this record falls under |
| `stream_id` | string | yes | Chain this record belongs to (§4) |
| `sequence` | integer | yes | Monotonic within `stream_id`, starting at 1, no gaps |
| `prev_digest` | digest \| null | yes | Digest of the previous record in the stream; `null` at sequence 1 |
| `source` | object | yes | Collector identity, implementation, version, deployment |
| `clocks` | object | yes | Customer-observed clocks: `source_time` and optional `authoritative_time`; hosted receipt clocks are in §6 |
| `body` | object | yes | Type-specific payload |
| `signature` | object | yes | §7 |

**ES-005** — Unknown envelope fields MUST cause verification failure. Unknown fields inside `body` MUST be preserved for digest computation and MUST NOT cause failure, permitting forward-compatible extension of payloads but not of the envelope.

---

## 4. Chains and streams

**ES-006** — A stream is an append-only sequence of records sharing a `stream_id`, linked by `prev_digest`. Streams MUST NOT fork: two records with the same `stream_id` and `sequence` and differing `record_id` are a fatal integrity failure and MUST be reported as such rather than resolved.

The ingestion response distinguishes `integrity.stream_fork`, `ingestion.replay`, and `integrity.content_substitution`. A rejected fork is retained as a tenant-visible append-only integrity event rather than being lost with the rejected ledger transaction. Whether that operational event should later acquire its own signed evidence record representation is an open specification question; v0.1 adds no evidence record type for it.

**ES-006a** — `prev_digest` is the digest of the **complete** previous record, including its `signature` member, over the RFC 8785 canonical form of the whole record. This differs deliberately from `signed_digest` (ES-021), which excludes `signature`. Including the signature makes the chain commit to the authentication of each link: replacing a signature, or altering anything carried inside the `signature` member, MUST break the chain at the following record. Implementations MUST NOT use the signature-excluded form for `prev_digest`.

**ES-006b — refusal precedence.** Where more than one integrity failure is independently determinable at a single stream position, a verifier MUST report **all** of them, ordered by chain traversal: the link (ES-006a) before the key state (ES-024). It MUST NOT emit one and suppress the others. A verifier MAY designate the traversal-order first failure as the primary code for interfaces that carry only one, provided the remainder are still reported alongside it.

> **Non-testable (deferred) — EV-30.** No acceptance scenario yet. Demonstrating it requires both implementations to report the full set, and the Python side reports a single code today (EV-28); a scenario written before that lands would assert cross-implementation agreement that does not exist. EV-30 writes the scenario once EV-28 has made it satisfiable.

> **This is a behavioural rule, not a clarification.** A re-signed predecessor breaks the link *and* presents an unauthenticated key change, and an implementation that returns on the first check it happens to run reports one of the two. Which one then depends on the verifier's internal ordering rather than on the evidence, so two conformant verifiers describe the same attack differently and a relying party comparing them sees a disagreement that is not there. Collapsing distinct failures into one signal is the same defect as an undifferentiated conflict response in the ingestion path, and it runs against the rule this methodology applies everywhere else: what is wrong or unknown stays visible instead of being absorbed into whatever is reported next to it.

**ES-007** — A single boundary MAY have multiple streams — typically one per collector instance. Cross-stream ordering is established by clocks (§6), never by sequence.

**ES-008** — A sequence gap is detectable and MUST produce a `CoverageGap` record on detection. Per `coverage-methodology.md` CM-017, an unexplained chain break terminates the attestation window at the break.

---

## 5. Record types

### 5.1 AssuranceBoundary

Declares scope. Signed, versioned, and referenced by every other record. Boundary changes create a new version; they never mutate.

Body: `boundary_version`, `tenant`, `deployment`, `agent_identities[]`, `action_families[]`, `destination_systems[]`, `enforcement_points[]`, `policy_refs[]`, `window_start`, `window_end`, `collection_modes[]`, `fail_behaviour` (per family), `qualification_refs[]`.

**ES-009** — Every `action_families[]` entry MUST carry a `qualification_ref` pointing to a `QualificationRecord`. A boundary declaring a family without qualification is invalid.

### 5.2 QualificationRecord

The denominator qualification output from `coverage-methodology.md` §7. This record is what entitles a window to claim anything above `observed`.

Body: `action_family`, `destination_system`, `enumeration` (api, scoping params, ordering guarantee, pagination, result_cap), `identity_isolation` (attribute, vendor_settable, partial_notes), `confirmation` (api, permission_set, independent_of_enumeration), `temporal` (authoritative_timestamp_source, measured_settlement_lag), `retention_period`, `mutability` (deletion_possible, backdating_possible, trace_available), `assigned_class` (C1|C2|C3|C4|C5), `class_evidence`, `trial` (window, match_rate, unmatched_explanations), `qualified_at`, `revalidation_cadence`.

**ES-010** — `assigned_class` MUST NOT be increased by amending an existing record. A stronger class requires a new `QualificationRecord` with a later `qualified_at`, and per CM-004 applies only to windows beginning after that date.

### 5.3 PopulationRecord

The enumeration snapshot from the destination system. **This is the denominator, and it is a distinct record type precisely because the methodology forbids conflating it with the population** (CM-002).

Body: `action_family`, `destination_system`, `window_start`, `window_end`, `enumeration_query` (as executed), `record_identifiers[]` or `identifier_digest` for large populations, `count`, `pagination_complete` (boolean), `result_cap_hit` (boolean), `retrieved_at`, `authoritative_timestamps` (min/max observed).

**ES-011** — `result_cap_hit: true` MUST prevent any coverage ratio being emitted for the affected window. A truncated enumeration is not a denominator.

**ES-012** — `pagination_complete: false` MUST be treated identically to `result_cap_hit: true`.

### 5.4 AgentIdentity

Body: `agent_id`, `deployment`, `runtime`, `tenant_scope`, `service_identity`, `model_versions[]`, `tool_versions[]`, `credential_ref` (the attribute used for identity isolation).

### 5.5 ActionProposal

Body: `action_family`, `action_id`, `tool`, `parameters_digest`, `parameters` (optional, per data-minimisation config), `purpose`, `target_ref`, `risk_class`, `proposed_at`.

### 5.6 AuthorityDecision

Body: `action_id`, `decision` (`grant`|`deny`|`review_required`), `policy_ref`, `policy_version`, `constraints[]`, `decided_by` (policy engine or reviewer identity), `decided_at`.

### 5.7 HumanReview

The differentiating record. Captures whether oversight was real, not merely that it nominally occurred.

Body: `action_id`, `reviewer_identity`, `reviewer_authority` (role and whether authorised for this risk class), `surface` (which UI, which version), `evidence_shown` (digest of what was actually rendered, not what was available), `evidence_shown_refs[]`, `options_offered[]` (approve|deny|modify|escalate|stop|reverse|compensate), `time_available_ms`, `time_taken_ms`, `decision`, `modifications`, **`action_state_at_review`** (proposed|dispatched|accepted|committed|reversible|irreversible), `decided_at`.

**ES-013** — `evidence_shown` MUST be a digest of what was rendered client-side. A server-side reconstruction of what *should* have been rendered is not conformant and MUST be labelled `evidence_shown_provenance: "server_reconstructed"` if used, which caps the oversight claim.

**ES-014** — `action_state_at_review` is mandatory. A review recorded against an action already in state `committed` or `irreversible` MUST NOT be reported as effective oversight regardless of the decision recorded.

> This field is the difference between oversight and oversight theatre. It is the single most consequential field in the specification.

### 5.8 ExecutionReceipt

Body: `action_id`, `dispatch_attempt`, `connector_identity`, `connector_version`, `destination_response_digest`, `destination_record_ref`, `status`, `dispatched_at`, `responded_at`.

### 5.9 ExternalConfirmation

Body: `action_id`, `destination_system`, `destination_record_id`, `destination_record_digest`, `authoritative_timestamp`, `reconciliation_status` (`matched`|`unmatched_with_evidence`|`unmatched_without_evidence`|`duplicate`|`ambiguous`|`out_of_scope`), `retrieved_at`.

**ES-015** — `reconciliation_status` is a closed enumeration. Per CM-012, no residual or default bucket exists; an unclassifiable record is a defect, not a status.

### 5.10 FinalityRecord

Body: `action_id`, `state` (per lifecycle), `reversible_until`, `compensation_ref`, `settled_at`.

### 5.11 OutcomeRecord

Body: `action_id`, `outcome_contract_ref`, `authoritative_source`, `result`, `finalised_at`, `disputed`, `reversal_ref`.

### 5.12 CoverageGap

Body: `gap_start`, `gap_end`, `affected_scope` (families, identities, systems), `cause` (`collector_unreachable`|`fail_open`|`sequence_break`|`denominator_unavailable`|`clock_skew`|`key_discontinuity`), `detection_source`, `exposure` (`known`|`estimated_bounds`|`unknown`), `actions_during_gap` (count if determinable, else null).

**ES-016** — A `CoverageGap` MUST be signable and emittable by the SDK without contacting hosted infrastructure. If gap emission depends on our availability, our outage erases the evidence of our outage. Offline-signed gap markers are the integrity mechanism, not an optimisation.

### 5.13 AttestationWindow

Body: `boundary_ref`, `window_start`, `window_end`, `methodology_version`, `denominator_class`, `population_record_refs[]`, `coverage_level`, `verification_status` (`self_computed`|`independently_reproduced`), `coverage_ratio` (nullable), `counts` (matched, unmatched_with_evidence, unmatched_without_evidence, duplicate, ambiguous), `gaps[]`, `assertions[]`, `exclusions[]`, `relying_parties`, `validity_from`, `validity_until`, `liability_ref`, `issued_at`, `issuer`, `verifier_version`.

**ES-017** — `coverage_ratio` MUST be `null` where `denominator_class` is C4 or C5 (CM-009). Serializing zero, or omitting the field, are both non-conformant — the null is a claim about the world and must be explicit.

**ES-018** — `coverage_level` MUST equal `min(evidence_supported_level, class_admissible_level)` per CM-008, and the record MUST include `capped_by_class` (boolean) so a relying party can see when the cap bound.

### 5.14 RevocationRecord

Body: `attestation_ref`, `reason`, `issuer`, `effective_at`, `superseding_ref`, `relying_party_notification_status`.

---

## 6. Clocks

**ES-019** — Every customer-signed record carries `source_time` (the emitting component) and, where applicable, `authoritative_time` (the destination's timestamp relayed by the collector). `ingest_time` is observed by the hosted ingestion service and `clock_skew_ms` is derived from that observation and `source_time`; neither may appear in the customer-signed record. On accepted ingestion both MUST instead be recorded in the issuer-signed ingestion receipt defined by ES-030. A verifier MUST reject a customer record that supplies either hosted field.

**ES-020** — Where `authoritative_time` is present it governs reconciliation ordering. Where it is absent, and the issuer-signed receipt's measured skew exceeds the boundary's declared threshold, affected records are excluded from the numerator and counted as unknown per CM-018. A collector-provided skew value has no standing.

---

## 7. Signatures

**ES-021** — Ed25519. The `signature` object carries `alg`, `key_id`, `sig` (base64url, unpadded), and `signed_digest` (digest of the JCS-canonical record excluding the `signature` field). `sig` is the Ed25519 signature over the **bare 32-byte SHA-256 digest** of that canonical signature-excluded form — the same bytes `signed_digest` renders as `sha256:<hex>`, not the ASCII of `signed_digest` and not the canonical bytes themselves.

> **Recorded from the vectors rather than concluded here.** This sentence states what `sign-customer-record` already establishes; ES-029 makes that vector authoritative and it has been normative since EV-04. Until EV-05 nothing had implemented ES-021 from the prose alone, and the prose named `signed_digest` without ever saying what `sig` covered. An independent implementer had at least two readings — sign the canonical bytes, or sign their digest — with nothing in the specification to choose between them, and the vector is the only reason the second is discoverable. The vector decides; this records the decision so the next implementer does not need to reverse-engineer it.

**ES-021a** — The `signature` member is closed. Its customer-signature members are exactly `alg`, `key_id`, `sig`, and `signed_digest`, plus `key_continuity` only when a rotation is asserted under ES-024a. An `AttestationWindow` MAY additionally carry the `issuer` counter-signature required by ES-023; that nested object contains exactly `alg`, `key_id`, `sig`, and `signed_digest`. No other member is permitted at either level. A verifier MUST reject an unknown or missing member rather than ignore it.

**ES-022** — Algorithm agility: `alg` is present so that a future migration is possible, but v0.1 verifiers MUST reject any value other than `ed25519` rather than attempting negotiation.

**ES-023** — Two-signature model. Record signatures are produced by the customer's key. The `AttestationWindow` carries an additional counter-signature from the issuer. This is what permits the claim that we cannot modify customer evidence. The issuer's `signed_digest` and `sig` are computed over the record carrying the customer signature but with `signature.issuer` itself excluded, under the ES-021 rule: `signed_digest` is the digest of that canonical form and `sig` is the Ed25519 signature over its bare 32-byte SHA-256 digest. The counter-signature cannot commit to its own bytes, so what it covers is everything else, customer signature included.

> **Also recorded from the vectors.** `verify-customer-and-issuer-signatures` establishes this. As with ES-021 the prose named the counter-signature without stating its signing input, which left the excluded member ambiguous — an implementer could equally have read it as covering the whole record, which is unsatisfiable, or as covering the signature-excluded form, which would leave the customer signature uncountersigned.

**ES-024** — Key rotation MUST be accompanied by a `KeyContinuity` assertion: the new key signed by the old, recorded in-stream. Rotation without continuity is a chain break under ES-008 and CM-017. Where a record both breaks its link and presents an unauthenticated key change, both are reported under ES-006b rather than the first found standing in for the second.

**ES-024a** — v0.1 defines no `KeyContinuity` record type. The continuity assertion is carried under `signature.key_continuity` on the first record signed by the new key. It is an object with exactly `alg`, `predecessor_key_id`, `new_key_id`, `new_public_key` (base64url, unpadded, 32 bytes), `tenant_id`, `stream_id`, and `sig` (base64url, unpadded, 64 bytes). `tenant_id` and `stream_id` MUST match the envelope of the carrying record, and `new_key_id` MUST match that record's signature key. `sig` is the predecessor key's Ed25519 signature over the RFC 8785 canonical form of the other six members. A verifier MUST reject any other member set or any context mismatch. Because the assertion sits inside `signature`, the carrying record's own `signed_digest` does not cover it; the predecessor signature authenticates it, and the following record's `prev_digest` commits it under ES-006a. A continuity assertion on a record that is not the first record after a real key change MUST be rejected. Sequence 1 establishes a per-stream trust anchor from the verifier's trusted keyring and MUST NOT carry `key_continuity`, because no predecessor exists in that stream; starting a new stream after a tenant key rotation does not prove continuity with an earlier stream, and a verifier MUST NOT infer such continuity.

> **Honest limit, stated here because implementers will ask.** The two-signature model prevents us forging evidence. It does not prevent us *withholding* it. The mitigation is that the customer holds their own copy and the verifier runs offline, making withholding detectable rather than impossible. See `threat-model.md` §5.

---

## 8. Data minimisation

**ES-025** — `parameters` and any free-text field default to digest-only. Inclusion of cleartext content is per-action-family configuration, recorded in the boundary, and visible to the relying party.

**ES-026** — Selective disclosure MUST be possible: a relying party can be given a bundle proving a claim without receiving cleartext inputs, by verifying digests against separately-disclosed content.

---

## 9. Versioning

**ES-027** — `schema_version` is semver. Verifiers MUST support every published version. Records are never migrated in place.

**ES-028** — A breaking change increments major and requires a new verifier release supporting both. Historical attestations remain verifiable under the version that produced them (CM-023).

---

## 10. Conformance

An implementation is conformant if it produces records that our reference verifier accepts, and accepts records our reference implementation produces. Both directions are required.

**ES-029** — Test vectors are published alongside this specification and are normative. Where this prose and a vector disagree, the vector is authoritative and the prose is a defect.

**ES-030** — Every durably accepted customer record has an ingestion receipt produced by the hosted ingestion service and appended atomically with it. The receipt payload contains exactly `record_digest`, `ingest_time`, and `clock_skew_ms`, where `record_digest` identifies the complete JCS-canonical customer record received on the wire, **including its `signature` member**. This receipt binding is distinct from the customer's `signed_digest`, which excludes `signature` under ES-021: DM-023 governs what the customer signs, while the receipt attests which complete artifact the service observed. `ingest_time` is the service's RFC 3339 receipt time at millisecond precision, and `clock_skew_ms` is the signed integer difference `ingest_time - source_time` in whole milliseconds, truncating sub-millisecond remainder toward zero. The payload is RFC 8785 canonicalized and signed with an issuer-namespace Ed25519 key; its canonical bytes, raw signature, and key ID are stored separately from the customer record. No acknowledgment may be returned unless both record and receipt committed in the same transaction. Changing a receipt field or substituting the customer's signature MUST invalidate the binding and MUST make the hosted clock observation unusable for ES-020. `authoritative_time` remains in the customer-signed record as a relayed claim about the destination response; it is not represented as an observation made by the collector.

---

## 11. Open questions requiring input

| Question | Why it matters | Default if unanswered |
|---|---|---|
| Include a transparency-log anchor in v0.1? | Would strengthen the withholding limit in §7, at real cost | No — defer to a higher assurance level post-MVP |
| Support hardware-backed keys at MVP? | Enterprise buyers may ask | No — client-held software keys only |
| Publish v0.1 or wait for v1.0? | Early publication invites feedback and adoption; also invites being wrong in public | Wait until first design partner has implemented against it |

---

## 12. Acceptance criteria

### ES-S-001 — Fork detection *(ES-006)*

```gherkin
Given a stream containing a record at sequence 42
When a second record with the same stream_id and sequence 42 is submitted
Then verification fails with "stream fork"
And no attestation may be issued covering that stream
```

### ES-S-002 — Truncated enumeration blocks ratio *(ES-011, ES-012)*

```gherkin
Given a PopulationRecord with result_cap_hit true
When an attestation window is generated
Then coverage_ratio is null
And the attestation states that enumeration was truncated
```

### ES-S-003 — Review after commitment is not effective oversight *(ES-014)*

```gherkin
Given a HumanReview with action_state_at_review "committed"
And decision "approve"
When oversight effectiveness is evaluated
Then the review is not counted as effective oversight
And the attestation records it as "review after commitment"
```

### ES-S-004 — Offline gap emission *(ES-016)*

```gherkin
Given hosted ingestion is unreachable
When the SDK detects a collection gap
Then a signed CoverageGap record is produced locally
And it is accepted on reconnection with its original signature intact
```

### ES-S-005 — Rotation without continuity breaks the chain *(ES-024)*

```gherkin
Given records signed with key K1
When subsequent records are signed with K2 and no KeyContinuity assertion exists
Then verification reports a chain break at the rotation point
And the attestation window terminates there
```

### ES-S-006 — Null ratio is explicit, not omitted *(ES-017)*

```gherkin
Given denominator_class C5
When an AttestationWindow is serialized
Then coverage_ratio is present with value null
And the record does not omit the field
```

### ES-S-007 — Cross-implementation canonicalization *(ES-001)*

```gherkin
Given the published conformance vectors
When the Python writer and the Go verifier each canonicalize them
Then both produce byte-identical output
And both compute identical digests
```

### ES-S-008 — Unknown envelope field rejected *(ES-005)*

```gherkin
Given a record carrying an unrecognised field in its envelope
When the verifier validates it
Then verification fails with "unknown envelope field"
```

### ES-S-009 — Unknown body field preserved *(ES-005)*

```gherkin
Given a record carrying an unrecognised field inside body
When the verifier validates it
Then verification succeeds
And the unknown field is included in the digest computation
```

### ES-S-010 — Previous authentication is chain-linked *(ES-006a)*

```gherkin
Given two records linked after the first record is signed
When the first record is replaced by an independently valid re-signature
Then verification fails with "prev_digest mismatch" at sequence 2
```

### ES-S-011 — Unknown signature member rejected *(ES-021a)*

```gherkin
Given a valid signed terminal record
When an unknown member is added to its signature object
Then verification fails with "unknown signature member"
```

### ES-S-012 — Continuity proof is bound to its tenant and stream *(ES-024a)*

```gherkin
Given a valid key-continuity assertion bound to tenant A and stream X
When it is replayed into tenant B on stream X
Then verification fails with "continuity tenant_id does not match"
And the rotated record is not accepted
```

### ES-S-013 — Collector cannot suppress measured skew *(ES-019, ES-030, DM-005, DM-024, TM-006)*

```gherkin
Given an issuer-signed ingestion receipt whose measured clock_skew_ms is non-zero
When clock_skew_ms is replaced with a collector-reported value of 0
Then receipt verification fails
And the customer-signed record bytes remain unchanged
```

### ES-S-014 — Measured skew withholds numerator eligibility *(ES-020, TM-006)*

```gherkin
Given a record without authoritative_time
And its issuer-signed ingestion receipt exceeds the boundary clock-skew threshold
When coverage eligibility is evaluated
Then the record is excluded from the numerator
And the affected interval is counted as unknown
```
