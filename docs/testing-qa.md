# Testing and QA

**Version:** 0.1 draft
**Repo location:** `docs/testing-qa.md`
**Depends on:** every other document — this is where their requirements become executable
**Audience:** internal engineering; auditors evaluating whether the methodology is implemented as published

---

## 0. The organising idea

**Acceptance criteria and attestation assertions are the same objects viewed from two angles.**

When an attestation asserts "enforced coverage for family X over window W," that is a claim we must be able to demonstrate. A scenario is also a claim we must be able to demonstrate. It follows that:

> **No assertion enters `attestation-reliance.md` §2 without a corresponding scenario here. No requirement in any document is considered implemented without a passing scenario.**

The reliance framework and the test suite grow together or not at all.

---

## 1. Negative-first

Most products test that the system does the right thing. Here the dangerous failure is not a crash — it is a **false claim**. A system returning 500 is embarrassing. A system quietly reporting full enforced coverage across an interval where the collector was down is fatal to the company.

**QA-001** — For every coverage level, denominator class, and assertion, there MUST be at least one scenario proving the system **withholds** the claim under conditions that do not warrant it. Negative scenarios outnumber positive ones by design.

**QA-002** — A pull request adding a new claimable assertion without its withholding scenario fails review. This is a CI-enforceable check, not a convention.

---

## 2. The verifier is the oracle

Because the independent verifier reproduces an attestation's status from the bundle alone, almost every acceptance test reduces to one shape:

```
produce evidence → generate attestation → run verifier → assert verdict
```

One oracle, not scattered assertions. CI continuously proves the exact property we sell.

**QA-003** — Acceptance tests MUST assert through the verifier, not through internal state. A test that reaches into the coverage engine's intermediate values is a unit test, not an acceptance test, and MUST NOT be counted toward acceptance coverage.

**QA-004** — The verifier used in CI is the same artifact shipped to relying parties. No test-only build.

---

## 3. Test layers

| Layer | Scope | Tooling | Gate |
|---|---|---|---|
| **L1 Conformance vectors** | Canonicalisation, digests, signatures, chain rules. **Published.** | Language-neutral fixtures; run by Python writer and Go verifier | Every PR |
| **L2 Unit** | Pure functions: matching, classification, lattice application | pytest / Go test | Every PR |
| **L3 Property-based** | Chain and coverage invariants over generated inputs | Hypothesis (Py), gopter (Go) | Every PR |
| **L4 Integration** | End-to-end action → attestation → verify | pytest + ephemeral Postgres | Every PR |
| **L5 Adversarial** | Threat-model attacks | Dedicated suite, mapped to TM IDs | Every PR |
| **L6 Acceptance (BDD)** | Requirement scenarios from all documents | pytest-bdd against the verifier | Every PR |
| **L7 Golden** | Byte-identical attestation reproduction | Fixture comparison | Every PR |
| **L8 Restore drill** | Chain integrity after point-in-time restore | Scripted, recorded | Pre-release + quarterly |

---

## 4. Property-based targets

Where the subtle defects live. Example-based tests will not find these.

**QA-005** — Properties that MUST hold for any generated input:

1. **Chain agreement.** For any sequence of records including out-of-order arrival, duplicates, gaps, and mid-window key rotation, the verifier's conclusion matches the generator's ground truth.
2. **Lattice monotonicity.** Adding evidence never decreases the claimable level; weakening the denominator class never increases it.
3. **Cap enforcement.** For any evidence set and any denominator class, claimed level ≤ class-admissible level (CM-008).
4. **Classification exhaustiveness.** Every record in any generated population resolves to exactly one classification, with no residual (CM-012).
5. **Determinism.** Two computations over identical inputs produce byte-identical output (CM-013).
6. **Gap conservation.** The union of covered intervals and gap intervals equals the window, with no overlap and no uncovered remainder.

Property 6 is the one most likely to catch a real bug. An interval that is neither covered nor marked as a gap is exactly the silent-overclaim failure the product exists to prevent.

---

## 5. Adversarial suite

**QA-006** — Each attack in `threat-model.md` §4 has a corresponding executable test. The suite is run on every PR, not periodically.

| Attack | Test | Expected |
|---|---|---|
| Selective instrumentation (TM-001) | Instrument 60 of 100; C1 denominator | Ratio 60/100, not 100% |
| Boundary gerrymandering (TM-002) | Narrow scope between windows | Change visible in version history |
| Identity laundering (TM-004) | Shared credential | Qualification → C5 |
| Clock manipulation (TM-006) | Skewed source clock | Records excluded, counted unknown |
| Gap suppression (TM-007/9) | Clean collector stop | Denominator surfaces the actions |
| Replay (TM-010) | Resubmit records | Rejected on `record_id` |
| Key substitution (TM-011) | Rotate without continuity | Chain break, window terminates |
| Enumeration truncation (TM-012) | Cap the result set | Ratio null |
| Retroactive upgrade (TM-013) | Backdate a qualification | Verifier rejects |
| Forged attestation (TM-014) | Alter a signed bundle | Verification fails |

**QA-007** — The adversarial suite is the first thing to show a design partner's security reviewer. It should be readable by someone who does not know the codebase.

---

## 6. Golden attestations

**QA-008** — A set of fixed evidence fixtures produces byte-identical attestation bundles. Any diff fails CI and requires an explicit, reviewed fixture update with a stated cause.

**QA-009** — Golden fixtures MUST cover: each denominator class, each coverage level, a window with gaps, a window with a chain break, a superseded attestation, and a revoked attestation.

This is how verifier reproducibility becomes a continuous check rather than an aspiration.

---

## 7. Traceability

**QA-010** — Four-link chain, maintained automatically and **published**:

```
requirement ID → scenario ID → test ID → attestation assertion ID
   CM-008    →   CM-S-004   →  test_lattice_caps_level  →  A-06
```

On a normal project this matrix is internal QA hygiene. Here it is **evidence for the auditor** that the methodology is implemented as documented — precisely what they will ask for before agreeing to rely on anything.

**QA-011** — CI fails on: a requirement with no scenario, a scenario with no test, an assertion with no requirement, or a test referencing a retired requirement ID.

**QA-012** — The matrix is generated, never hand-maintained. A hand-maintained traceability matrix is wrong within a month and worse than none, because it invites misplaced confidence.

---

## 8. CI gates

**QA-013** — A PR merges only when: L1–L7 pass, the traceability matrix is complete, the adversarial suite passes, and — for changes to the schema, signing, canonicalisation, or coverage computation — the Go verifier independently reproduces the Python writer's output.

**QA-014** — Following the DamDam convention, promotion from `staging` to `main` requires a signoff artifact with a CI-enforced blocker, plus for this product a recorded independent verifier reproduction over staging evidence (IN-022).

**QA-015** — Coverage-of-code targets are secondary and deliberately unspecified here. Coverage of *requirements* is the metric that matters, and it is binary: every requirement has a passing scenario, or the build fails.

---

## 9. What we do not test, and why

**QA-016** — We do not test that agent actions are semantically correct, that reviewers exercised good judgement, or that destination systems are honest. These are outside the assertion catalogue (AR-005) and testing them would imply claims we explicitly disclaim.

**QA-017** — We do not use production customer evidence in tests. Fixtures are synthetic or drawn from partner sandbox environments with explicit permission.

---

## 10. Acceptance criteria for the test system itself

### QA-S-001 — Assertion without scenario fails CI *(QA-002)*

```gherkin
Given a new assertion added to the catalogue
And no scenario referencing it
When CI runs
Then the traceability check fails
And the failure names the unmapped assertion
```

### QA-S-002 — Gap conservation holds *(QA-005 property 6)*

```gherkin
Given any generated evidence set over window W
When coverage is computed
Then covered intervals and gap intervals partition W exactly
And no interval is both
And no interval is neither
```

### QA-S-003 — Golden diff blocks merge *(QA-008)*

```gherkin
Given a change to canonicalisation
When golden attestations are regenerated
And any bundle differs byte-for-byte from its fixture
Then CI fails
And the failure requires an explicit reviewed fixture update
```

### QA-S-004 — Cross-implementation reproduction *(QA-013)*

```gherkin
Given a PR touching the evidence schema
When CI runs
Then the Go verifier reproduces the Python writer's canonical output
And any divergence fails the build before merge
```

### QA-S-005 — Acceptance tests assert through the verifier *(QA-003)*

```gherkin
Given an acceptance test in layer L6
When it is executed
Then its assertions derive from verifier output
And it does not reference internal computation state
```

---

## 11. Input needed

| Question | Recommendation |
|---|---|
| BDD tooling | `pytest-bdd` for L6; plain Go tests for the verifier side. Behave and Cucumber add ceremony without benefit at this scale |
| Publish the adversarial suite? | **Yes, eventually.** It is the most persuasive artifact in the repository for a security reviewer. Hold until the spec is public so the two land together |
| Publish the traceability matrix? | Yes — it is the auditor's evidence. Generated output only, no customer content |
| Fuzzing the verifier | Worth it before the spec is published. A verifier that crashes on malformed input is a denial-of-service against relying parties |
