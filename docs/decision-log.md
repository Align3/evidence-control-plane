# Decision Log

**Repo location:** `docs/decision-log.md`
**Audience:** reviewers, and anyone deciding how much weight to place on a requirement.
**Governed by:** `agent-working-agreement.md` AG-018.

---

## 0. What this file is, and why it is separate

AG-018 permits a builder to write a missing requirement when no requirement covers a structural decision needed to proceed and no prior implementation exists to consult. It imposes four obligations, and two of them pull against each other:

- **(2)** record any rejected alternative and why, so the choice reads as a choice rather than an inevitability;
- **(4)** the requirement stays UNCONFIRMED until a second, independent implementation is built **cold** against it.

Satisfying (2) inside the specification defeats (4). A rationale that says *"a keyed container was built first and was wrong because a record could be misfiled"* hands the next implementer the answer, the mechanism, and the fix. Whatever they then build avoids the defect because the text told them to, not because they derived it — so the cold build can no longer test whether the requirement is *necessary* rather than merely *unambiguously communicated*.

This was not predicted. It was found by running the first cold build, which reported that its own reading materials had defeated the experiment before it wrote a line of code.

So the rationale lives here instead. The specification carries the rule; this file carries why. **No requirement anywhere points at this file**, because a pointer is itself a signal: "a choice was made here, go and find what is suspicious about it" is most of what the rationale would have told them. The only reference to this file in the corpus is the single sentence in AG-018 that establishes it and requires cold-build prompts to exclude it.

**If you are assembling a cold-build prompt, this file is excluded. Always. No exceptions, no per-prompt judgement.**

---

## 0.1 Leaked and unleaked briefs — concrete examples

AG-018a states the rule and deliberately carries no example, because `agent-working-agreement.md` is on every cold-build reading list and an illustration naming a real rejected alternative would put the leak into the one file the builder is always told to read. The examples live here instead.

Both leaks below are real. Neither author was careless; both were trying to help.

**Leak 1 — the specification itself.** ES-034 originally carried a subsection headed *"Why an array rather than named members"*, narrating the keyed container, the misfiled `CoverageGap`, and the fix. The first cold build read it as instructed and reported that its assigned reading had defeated the experiment before it wrote a line of code. Fixed by moving the rationale to this file.

**Leak 2 — the story brief.** With the specification clean, the brief for the same story said, in its build instructions, *"the array container, records routed by their own record_type, not by container position or a keyed structure"*, and added a paragraph headed *"WATCH SPECIFICALLY FOR THE DEFECT THE ORIGINAL BUILDER FOUND AND FIXED"* describing the keyed container, the misfiling mechanism, and the correct shape — closing with the assertion *"you have not been told about it in your reading materials"*, which was true of the reading materials and false of the brief. The second cold build reported it could not have arrived at a keyed structure after reading that, so its not arriving at one was worth nothing as evidence.

**What the brief should have said.** Name the requirement, not the answer:

> Build bundle parsing per ES-034.
>
> Required test: construct an adversarial input that attempts to make a record be treated as something other than what ES-034's routing rule says it is, and show it is refused.

That commissions the identical adversarial test and demonstrates the identical property, while leaving the builder to discover from ES-034's own text what the routing rule is and what violating it would look like. If the builder cannot construct the adversarial input from the requirement alone, *that is the finding* — it means the requirement does not state its own failure mode, which is exactly what obligation (4) exists to detect.

**The general shape.** A leak is any sentence that would let a reader who has never seen this file reconstruct what was rejected or why. Warnings leak. Comparisons leak. "Not X" leaks as surely as "X". Test obligations phrased over the requirement's own normative text do not.

---

## 1. Requirements originated under AG-018

Every entry is **UNCONFIRMED** until a second independent implementation is built cold against it and reports.

| Requirement | Document | Originated in | Status |
|---|---|---|---|
| ES-034 | `evidence-spec.md` §10.1 | EV-19 | UNCONFIRMED |
| ES-035 | `evidence-spec.md` §9 | EV-19 | UNCONFIRMED |
| AR-029 | `attestation-reliance.md` §5 | EV-19 | UNCONFIRMED |
| AR-030 | `attestation-reliance.md` §5 | EV-19 | UNCONFIRMED |
| AR-031 | `attestation-reliance.md` §5 | EV-19 | UNCONFIRMED |
| CM-025 | `coverage-methodology.md` §14 | EV-19 | UNCONFIRMED |
| ES-036 | `evidence-spec.md` §5.13 | EV-41 | UNCONFIRMED |

Two further decisions were originated under AG-018 inside requirements that already existed, and are recorded here for the same reason: ES-017's rounding direction and its zero-denominator rule, and §5.13's schema version for `capped_by_class`.

## ES-036 — assertion element routing

The Go verifier accepted a bare assertion ID or an object member named `id`; the cold Python verifier read an object member named `assertion_id`. The documents named `assertions[]` and required per-assertion scope and counts but specified no wire member that selected the catalogue row. The EV-41 agreement vector exposed the divergence.

The routing member is `assertion_id`, matching the catalogue term and avoiding a generic `id` whose namespace is unclear inside an open payload object. Only routing and catalogue closure are decided. The remaining payload stays unchecked until its schema is specified, so this decision cannot promote an uninterpreted assertion to a verified claim.

**Rejected:** retain both the bare-string and `{\"id\": ...}` encodings. Multiple encodings would give the same assertion more than one canonical wire shape and would preserve rather than settle the cross-implementation divergence.

---

## ES-034 — the attestation bundle container

### Rejected: a keyed object container

A container with named members — `attestation`, `population_records`, `gap_records`, `boundary` — was designed and built first. It reads better, it makes the required members explicit, and it allows a closed member set so an unrecognised container member can be refused.

It is wrong, and the reason was found by building it rather than by reasoning about it.

A keyed container states each record's role **independently of the record**, so the two can disagree. A validly signed `CoverageGap` placed under `population_records` parsed, authenticated, and reached the coverage engine as a population. It was counted in the wrong place and was simultaneously absent from the gap set CM-014 conservation is checked against. Every signature on that bundle was valid. It is a gap-hiding path assembled entirely out of well-formed records — the exact overclaim class the specification exists to prevent — and the implementation that shipped it had a test suite that passed.

An array cannot express that failure, because there is no filing to get wrong. ES-033 already makes `record_type` a closed dispatch, so the closure a keyed container would add is inherited rather than invented, and adding a record type needs no container change.

The normative text carries the rule as a single clause: *a record's role is read from its own `record_type` under the closed ES-033 dispatch and from nowhere else*. The first cold reader of that clause judged it sufficient on its own to rule out both keyed filing and positional routing.

### Rejected: canonicalization alone as the byte-identity mechanism

The first version of ES-034 asserted that requiring the container to be RFC 8785 canonical *"makes QA-008's byte-identical bundle a property of the whole artifact rather than of its parts."*

That claim was false, and it survived review, a full test suite and a merge-ready pull request. RFC 8785 sorts the members of an object; it does not reorder the elements of an array. Two emissions of the same record set in different order are both canonical, both conformant, both accepted, and have different digests — demonstrated, not argued:

```
digest A  sha256:66adffecc73bc0cac71cff61e472f741566c9949cf7bc762ce0c49a2b8c59f95
digest B  sha256:155ef51f5e55df31b28dd34ac2b4375ec1817790dea1ddd596ee49a6b0138c12
```

QA-008 fails CI on any bundle diff, so the gate would have reported divergence between two implementations that agreed about everything substantive. The defect was found by an independent reader of the text, not by the author or by the tests.

**Rejected orderings.** Sorting by `record_id` depends on a member every type happens to carry but which nothing in ES-034 requires it to sort meaningfully. Sorting by `(stream_id, sequence)` orders within a stream but not across streams, and a bundle spans several. Preserving producer order and dropping the QA-008 claim was available and was rejected because QA-008 is the mechanism that makes verifier reproducibility a continuous check rather than an aspiration.

Sorting by the canonical bytes themselves is total, needs no member that any record type might omit, and is identical in every implementation that can already canonicalize — which every conformant implementation must.

---

## ES-035, CM-025 — the published version registries

### Rejected: inferring the published set from observed records

ES-027 and CM-023 both oblige a verifier to support "every published version" of a set no document enumerated. `coverage-methodology.md` carried no version number in its body at all — only "Draft v0.1" in its status line, a different namespace from the `methodology_version` values attestations carry.

The alternative to writing the registries was to let each implementation infer the supported set from whichever records it had seen. That is how two verifiers come to disagree about whether an artifact is verifiable at all, and the disagreement appears as a verification failure with no diagnosable cause.

The sets were taken from the normative vector corpus, which ES-029 makes authoritative, rather than from either implementation's defaults.

**Known weakness, recorded rather than solved:** both registries are prose tables. Nothing machine-readable exists, so drift between implementations stays invisible until someone adds a version.

---

## AR-029, AR-030, AR-031 — the revocation protocol

### Rejected: treating an unrecognised response as "nothing published"

AR-013 obliged a verifier to check "the issuer endpoint" and said nothing about how — no path, no request shape, no response shape, and no way to spell *nothing published* as distinct from *I could not ask*.

The protocol had to be invented. The load-bearing decision inside it is the direction of the default: an unrecognised answer resolves to `unchecked`.

The alternative — treating anything that is not an authenticated revocation as evidence that none exists — is what an implementation naturally does if nobody decides. It turns every outage, misconfiguration, captive portal and wrong-endpoint deployment into a clean bill of health. A verifier pointed at a non-conforming endpoint under the chosen rule reports `unchecked`, which is wrong but safe; under the rejected rule it reports the attestation as good, which is wrong and fatal.

### Rejected: `reason` as the supersession discriminator

§5.14 gives `RevocationRecord` both a `reason` and a `superseding_ref` and never says which separates supersession from revocation. Reading the discriminator off `reason` would have made it a free-text comparison. `superseding_ref` is a structured reference and AR-011 already requires a superseding attestation to reference the original.

### Rejected: revocation effective at publication

Reporting `revoked` as soon as a record is published would misstate the issuer's own act, since the issuer chose an `effective_at` later than the publication. Reporting `valid` while silently discarding a published pending revocation would withhold the fact a relying party deciding today most needs. The rule keeps the status at `valid` and surfaces the pending revocation alongside it.

**Tie-break.** An `effective_at` exactly equal to the evaluation instant resolves to the revoked side. Between *revoked slightly early* and *trusted slightly too long*, the first is the safe failure for a relying party and the second is not.

---

## ES-017 — coverage ratio encoding

The formula, the denominator exclusion and the fixed four-decimal scale were ruled by the specification owner. Two sub-decisions were not, and were originated under AG-018.

### Rejected: round-half-up

Conventional in reporting and marginally more accurate. Rejected because it can round a measured shortfall away: `2/3` becomes `0.6667`, which asserts more matched evidence than exists. Truncation toward zero is the only direction that cannot overstate, and it follows the convention ES-030 already sets for `clock_skew_ms` rather than inventing a second one.

### Rejected: `"0.0000"` for a zero in-scope denominator

Arithmetically defensible and wrong as a claim. `"0.0000"` and `null` encode opposite statements — *we checked and matched nothing* against *there was nothing to check* — and collapsing them reintroduces the ES-017 problem the ratio rules exist to close: a number standing where an honest unknown belongs.

---

## §5.13 — `capped_by_class` schema version

### Rejected: requiring the member at schema 1.0.0

ES-018 has required `capped_by_class` since it was written; §5.13's body enumeration, the normative vector, the Python writer and the Go verifier all omitted it. Adding it to the enumeration makes those artifacts agree with ES-018.

Requiring it at 1.0.0 would refuse every attestation already issued, and the normative vector along with them. ES-028 classes that as a breaking change needing a major version, so the obligation attaches at 2.0.0 — the version ES-035 already reserves — and the member is optional by presence at 1.0.0. The rejected alternative was requiring it now and reissuing the corpus, which buys immediate uniformity at the cost of invalidating history the specification promises stays verifiable.
