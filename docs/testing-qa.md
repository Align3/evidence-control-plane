# Testing and QA

**Version:** 0.1 draft
**Repo location:** `docs/testing-qa.md`
**Depends on:** every other document — this is where their requirements become executable
**Audience:** internal engineering; auditors evaluating whether the methodology is implemented as published

---

## 0. The organising idea

**Acceptance criteria and attestation assertions are the same objects viewed from two angles.**

When an attestation asserts "enforced coverage for family X over window W," that is a claim we must be able to demonstrate. A scenario is also a claim we must be able to demonstrate. It follows that:

**QA-018** — No assertion enters `attestation-reliance.md` §2 without a basis requirement that states the assertion's claim and a documented scenario that exercises that requirement. Every requirement is classified: runtime behaviour is scenario-bearing and is not demonstrated without a passing scenario; a structural, database, CI, deployment, or artefact rule is otherwise-verified and is not demonstrated without its named passing substitute check; only process, governance, and documentation requirements may be non-testable, with a stated reason. Scenarios live in the acceptance section of whichever document owns the requirement — scenarios are extracted from all of `docs/`, and the suite is the union of those sections, not this file alone.

The reliance framework and the test suite grow together or not at all.

**A citation is part of the claim.** The rule reads "a basis requirement that states the assertion's claim" because EV-25 found two assertions whose cited requirements were real, current, and scenario-bearing, yet stated something else — A-02 on ES-009, A-09 on CM-007. Read as a bare existence check, the rule was satisfied by both. What that buys is a green gate over a demonstration of a different claim, which is worse than a red one: AG-002 forbids weakening a scenario to make it pass, and nothing forbade moving the citation instead. The matrix cannot judge whether a requirement states a claim, so this half of QA-018 is enforced at review; what the matrix enforces is that the cited requirement exists and carries a scenario at all.

This was the organising idea of the whole document and it was unnumbered prose from version 0.1 until now — which meant EV-22's traceability matrix, built to enforce exactly this rule, could not see it. The matrix reads `**XX-nnn**` definitions; a blockquote is invisible to it, so the one rule every other requirement here elaborates was the only one nothing could trace, claim, or report an orphan against. It takes the next free number rather than a low one: renumbering to put it in sequence would silently rewrite every existing citation, and a stable ID is worth more than a tidy ordering.

---

## 1. Negative-first

Most products test that the system does the right thing. Here the dangerous failure is not a crash — it is a **false claim**. A system returning 500 is embarrassing. A system quietly reporting full enforced coverage across an interval where the collector was down is fatal to the company.

**QA-001** — For every coverage level, denominator class, and assertion, there MUST be at least one scenario proving the system **withholds** the claim under conditions that do not warrant it. Negative scenarios outnumber positive ones by design.

**QA-002** — A pull request adding a new claimable assertion without its withholding scenario fails review. This is a CI-enforceable check, not a convention. The review requirement is unconditional and applies now. Automatic CI enforcement of it follows the staged schedule in QA-011, which is the single source of those dates.

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

**Staged enforcement.** QA-011 was drafted before the requirement-to-scenario ratio was known. The first generated matrix (EV-22) found 222 requirements against 55 scenarios: 163 requirements had no scenario, and two catalogued assertions rested on requirements that had none. QA-011 as drafted was therefore unsatisfiable on the day its implementation landed, and a gate that cannot pass on day one is switched off rather than satisfied — which is strictly worse than no gate, because a disabled check still appears in the pipeline. Enforcement is staged by severity:

| Severity | Enforced on | Hard expiry |
|---|---|---|
| critical | A-02/A-09 basis repair (EV-25 target) | 8 August 2026 |
| high | claimed-requirement triage and landed-story defects (EV-26 target) | 1 September 2026 |
| medium | — | 1 October 2026 |
| low | — | 1 October 2026 |

**Expiry is by date, not by condition.** On each date CI begins failing at that severity whether or not the backfill is complete, whether or not the owning story has merged, and whether or not anyone has triaged the findings. Slipping EV-25 does not slip the gate. The schedule is compiled into the generator rather than passed on the command line, so deferring a date is a code change that appears in review and cannot be done by editing a CI argument.

**The ratchet is one-way.** A severity that has become enforced is never relaxed. Where a CI invocation requests a weaker threshold than the schedule mandates, the schedule wins and the request is ignored; where it requests a stronger one, the stronger one applies and cannot later be walked back below the mandated level.

**Staging applies to the existing backlog, never to regressions.** A change that makes the situation worse fails immediately at every stage, whatever the schedule currently mandates. Concretely, and per QA-S-001: an assertion that this change adds to the catalogue, or re-points onto a requirement nothing demonstrates, fails the build now. Backlog is what a schedule is for; a ratchet that lets the thing it is ratcheting get worse is decorative. The comparison is against the merge base, so CI requires full history, and where the previous state cannot be read the build fails rather than assuming nothing is new.

**Every build prints the orphan count and the severity breakdown**, at every stage, enforced or not. Staging changes only what fails the build. It never changes what is looked for, and never changes what is reported: an orphan that does not yet fail CI is still counted, still named, and still published in the matrix.

**Untested scenarios are classified by ownership, not treated as one backlog.** A story owns a scenario by listing it in its `Acceptance:` field. A story is landed when an `EV-nn:` implementation commit is reachable from the build's `HEAD`. An untested scenario owned by a landed story is a high-severity defect. One owned only by an unlanded story is medium-severity expected roadmap debt: shipping that story is what clears it. An untested scenario with no `Acceptance:` owner is high severity because the matrix cannot tell whether it is roadmap debt or an omitted implementation. **A scenario that does have a test still needs an owner**, at medium severity: demonstration and ownership are separate records, and a scenario nobody owns has nobody to answer for it when its test later regresses. Checking ownership only where a test was missing is what let EV-22's own `Acceptance:` field omit three of its scenarios with its own tool reporting nothing. If reachable Git history cannot be read, the check fails immediately rather than assuming every owner is unbuilt. This distinction makes the 1 September high gate enforce shipped commitments and completed triage without requiring EV-05 through EV-21 to have landed.

**Story references are closed over `prd.md`.** Any `EV-nn` token in `docs/` must have a matching `#### EV-nn` story heading **in `prd.md`**. Definedness is read from that one file and nowhere else: a `#### EV-nn` heading in any other document is a citation like any other, or a story would be conjured into existence by writing its heading wherever the reference happened to be convenient. This applies to ordinary prose and schedule annotations as well as structured deferral markers; a conditional trigger naming nonexistent work is a defect even when the date ratchet remains effective without it.

**No caller-supplied input may produce a more permissive verdict than the default invocation.** This covers command-line arguments and the Python-callable seams alike: redirecting the corpus, supplying a collection, choosing a different baseline ref, or supplying a calendar date. A supplied date may only bring a stage forward; a supplied baseline ref adds a comparison and never replaces the default one; a supplied collection is reported and published but does not clear a scenario's missing-test finding. There is no longer any input, from either surface, that skips the QA-S-001 regression gate. Where the tool cannot compare a run against the default invocation it withholds the verdict and fails, rather than reporting the run as clean. A corpus that is empty, or implausibly small beside the floor recorded from the last known good run, is an unknown and not a pass: the generator applies CM-001 and CM-009 to itself exactly as the coverage engine applies them to evidence. The property is asserted over the argument space, not argued from the list of flags that currently exist.

**QA-019 — A requirement with no vector coverage is recorded, not silently absent.** ES-029 makes the published vectors normative and makes them the authority where prose and implementation disagree. A requirement no vector exercises therefore has nothing behind it, and today that fact is invisible: the corpus states what it covers and says nothing about what it does not, so an uncovered requirement is indistinguishable from a covered one by inspection.

EV-19 made the cost concrete. Its entire subject — CM-008, CM-009, CM-013, CM-014, ES-017, ES-011/012, AR-003, TM-013, TM-014, AR-009, and ES-034, ES-035, AR-029 through AR-031 and CM-025 as added — has **no** vector coverage whatever. Both halves of it rest on prose alone, and ES-029 cannot arbitrate a disagreement between them because there is nothing to arbitrate with. That was discovered by building, not by reading, which is the definition of a gap the tooling should have surfaced.

The corpus MUST therefore carry a machine-readable statement of the requirements it does not cover, and that count MUST be reported alongside the QA-011 orphan counts at every stage. Reporting is unconditional; what fails the build follows the same staged schedule, because a gate that cannot pass on the day it lands is switched off rather than satisfied.

The corpus statement is `requirement_coverage`. Its `covered` object maps a requirement ID to the non-empty list of vector IDs attributed to it; `declared_absent` is the sorted, duplicate-free complement over defined requirements; and `declared_absent_count` MUST equal the length of that list. A consumer MUST reject a requirement named in both collections, an attributed vector ID absent from the corpus, or a count that disagrees with the named collection. An absent register is unknown, not zero.

**This does not license a substitute.** A vector executed by one implementation is not an agreement vector and MUST NOT be published as one. Agreement demonstrated against a single implementation is agreement with itself — the failure `agent-working-agreement.md` AG-017 exists to prevent, relocated from source code into the corpus — and it is worse there, because a published vector carries the authority of ES-029 to everyone who later implements against it. Where only one implementation exists the honest record is the declared absence above, and the vector waits for the second implementation rather than being manufactured from the first.

Refusal-probe provenance has two closed forms. A **regression probe** records the prior result from each implementation against a named revision and requires at least one shipping entry point to have accepted the subject. A **new-rule probe** is permitted only where the check did not exist before its requirement: it records that requirement ID and the full commit that introduced it instead. Requiring a fabricated prior acceptance for a rule that was not then normative would make the provenance tidier and false. Every refusal probe carries exactly one form; neither an unproven regression label nor an unbound new-rule label is accepted.

**QA-012** — The matrix is generated, never hand-maintained. A hand-maintained traceability matrix is wrong within a month and worse than none, because it invites misplaced confidence.

---

## 8. CI gates

**QA-013** — A PR merges only when: L1–L7 pass, the traceability matrix is complete to the severity QA-011 currently enforces, the adversarial suite passes, and — for changes to the schema, signing, canonicalisation, or coverage computation — the Go verifier independently reproduces the Python writer's output. "Complete" tightens on the staged schedule in QA-011 and is unconditional once its final stage is live. Every other clause here is unconditional now.

**QA-014** — Following the DamDam convention, promotion from `staging` to `main` requires a signoff artifact with a CI-enforced blocker, plus for this product a recorded independent verifier reproduction over staging evidence (IN-022).

**QA-015** — Coverage-of-code targets are secondary and deliberately unspecified here. Coverage of *requirements* is the metric that matters.

This requirement originally read: *"…and it is binary: every requirement has a passing scenario, or the build fails."* That was written before the requirement-to-scenario ratio was known, and it was unsatisfiable as drafted — the first generated matrix (EV-22) found 222 requirements against 55 scenarios. It is corrected here rather than quietly relaxed, and the original wording is quoted above so that a reader comparing versions can see we were wrong and fixed it, not that a standard was softened when it became inconvenient.

The binary framing was wrong in three specific ways. It confused runtime behaviour with structural checks, pushed real database and CI assertions toward “non-testable”, admitted no requirement that genuinely cannot carry a scenario, and admitted no interval during which known backlog is worked off. The replacement is the three-class policy above. Requirement coverage remains exact per requirement: scenario, named substitute check, or reasoned non-testable classification. There is no unclassified fourth state.

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

### QA-S-002 — Gap conservation holds, property 6 *(QA-005)*

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

### QA-S-006 — The four-link chain is generated and published *(QA-010)*

```gherkin
Given a requirement with a scenario, an implementing test, and an assertion citing it as basis
When the traceability matrix is generated
Then the matrix links the requirement to the scenario to the test to the assertion
And it is published in both human-readable and machine-readable form
```

### QA-S-007 — An orphaned requirement fails the traceability check *(QA-011)*

```gherkin
Given a requirement with no scenario and no non-testable marking
When the traceability check runs with that severity enforced
Then the check fails
And the failure names the requirement
```

### QA-S-008 — The matrix is generated, never hand-maintained *(QA-012)*

```gherkin
Given the traceability matrix generator
When it runs twice over unchanged inputs
Then both runs produce byte-identical output
And neither run writes a matrix into the repository for a human to edit
```

### QA-S-009 — A malformed non-testable marking exempts nothing *(QA-011)*

The reference is QA-011, not QA-015. QA-015 is about code-coverage targets
being secondary; it says nothing about exemption syntax. The marking grammar
exists to keep QA-011 satisfiable, so failing closed on a malformed marking is
QA-011's property.

```gherkin
Given a requirement with no scenario and a non-testable marking whose category is not in the closed enum
When the traceability matrix is generated
Then the marking exempts nothing
And the requirement is still reported as an orphan
```

### QA-S-010 — Every requirement and scenario is classified after triage *(QA-011)*

EV-26's acceptance. It is about the outcome of triage — that nothing is left
unclassified — not about the marking grammar, which EV-22 already built and
QA-S-009 already demonstrates.

```gherkin
Given the live corpus after triage
When the traceability matrix is generated
Then every requirement has a scenario, a reasoned non-testable marking, or a deferral to a story that prd.md defines
And every scenario is listed under the Acceptance field of a story, whether or not it has a test
And no requirement claimed by a story is reported without a scenario
And no scenario is reported as having no Acceptance owner
And untested scenarios owned by unlanded stories remain reported as roadmap debt
```

### Agreement is not correctness: adversarial conformance vectors

The published conformance corpus has two distinct categories because they
detect different failures. Agreement vectors (`vectors`) ask independent
implementations for the same exact result and expose divergence. Adversarial
vectors (`adversarial_vectors`) are refusal-only probes written by trying to
produce acceptance at a public verifier entry point. They are held separately,
and every adversarial vector records what each implementation did before the
fix, at the named branch base; otherwise a newly added refusal vector may
merely confirm behavior that was already correct. At least one shipping entry
point must have accepted, and the record states per implementation which did—a
vector whose subject one verifier already refused is still worth publishing,
but it must not be described as a shared defect.

ES-S-007 cross-implementation agreement is therefore a divergence check, not a
correctness oracle. Shared defects remain a real risk when implementations are
built from the same specification, because an omitted composition rule can be
implemented identically on both sides.

What EV-30 actually found, measured against the branch base `9e5904b`, was not
a shared defect. Python's ingestion entry point accepted an `AttestationWindow`
after its issuer proof was removed, and Python's stream entry point allowed an
issuer key to authenticate an evidence stream. Go refused both. The two
implementations had genuinely diverged, and ES-S-007 did not report it—because
the conformance harness built its Go keyring with `evidenceKeyring()`, which
stamped the evidence namespace onto every key in the vector. The custody fact
the Go verifier checks was never presented to it, so the harness could not
observe a namespace refusal from either side.

The transferable lesson is therefore about the harness, not the verifiers: a
conformance harness that synthesizes an input the corpus does not state will
agree with itself. Any field a verifier makes a trust decision on must come
from the vector, never from a default the harness supplies. Where a harness
must supply one, both implementations have to supply the identical value, and
the corpus should say so.

The adversarial category concentrates on composition paths. Its first question
is whether the complete record, stream, receipt, or future bundle entry point
can bypass a stricter primitive that already exists. EV-19 adds mostly
composition behavior, so its bundle, coverage, lattice, and revocation entry
points are reviewed with acceptance-seeking mutations in this category rather
than relying on primitive tests plus cross-implementation agreement.

EV-40 supplies the complementary shared-defect example. At base `4fbba6c`,
both shipping complete-record verifiers accepted an evidence-namespace key on
a `PopulationRecord` and an `ExternalConfirmation`. The implementations agreed
because the specification had no record-origin category from which either
could derive a different answer. The two refusal vectors record those measured
pre-fix results per implementation. This is why agreement remains necessary
but cannot establish correctness: adversarial vectors must also ask whether a
composition entry point accepts a claim by the wrong principal, especially
when the missing rule is common input to both implementations.

---

## 11. Input needed

| Question | Recommendation |
|---|---|
| BDD tooling | `pytest-bdd` for L6; plain Go tests for the verifier side. Behave and Cucumber add ceremony without benefit at this scale |
| Publish the adversarial suite? | **Yes, eventually.** It is the most persuasive artifact in the repository for a security reviewer. Hold until the spec is public so the two land together |
| Publish the traceability matrix? | Yes — it is the auditor's evidence. Generated output only, no customer content |
| Fuzzing the verifier | Worth it before the spec is published. A verifier that crashes on malformed input is a denial-of-service against relying parties |

**Requirement classification has the same forward gate.** Every requirement is exactly one of three classes. Scenario-bearing requirements describe runtime behaviour and require Gherkin; while backlogged they name a real PRD story that claims them. Otherwise-verified requirements are objectively testable through a structural, database, CI, deployment, or artefact assertion and name the exact substitute pytest check; naming no check, or a check that does not resolve, does not discharge them. Non-testable requirements are process, governance, or documentation and state why executable verification would be dishonest. A new or materially rewritten requirement without its complete classification fails immediately as `NEW_REQUIREMENT_UNCLASSIFIED`, outside the staged backlog schedule. This comparison uses the same fail-closed merge base and non-weakening input rules as QA-S-001.

## Verification classifications

> **Verification for QA-019 — scenario-bearing; deferred EV-41.** This is externally observable tooling behaviour; EV-41 owns its missing Gherkin scenario and executable acceptance proof, because the second implementation it builds is what makes the declared absences resolvable rather than permanent.

> **Verification for QA-001 — otherwise-verified; deferred EV-38.** `pytest:tests/traceability/test_policy_coverage.py::test_qa_001_each_level_class_and_assertion_has_a_withholding_scenario` — This requirement is verified by a structural, database, CI, or artifact check rather than a Gherkin product scenario.

> **Verification for QA-004 — otherwise-verified; deferred EV-38.** `pytest:tests/traceability/test_ci_controls.py::test_qa_004_ci_executes_the_shipped_verifier_artifact` — This requirement is verified by a structural, database, CI, or artifact check rather than a Gherkin product scenario.

> **Verification for QA-006 — otherwise-verified; deferred EV-38.** `pytest:tests/traceability/test_policy_coverage.py::test_qa_006_every_threat_model_attack_has_an_executable_ci_test` — This requirement is verified by a structural, database, CI, or artifact check rather than a Gherkin product scenario.

> **Verification for QA-007 — non-testable (documentation).** Readability for an external security reviewer requires human editorial judgement rather than an executable assertion.

> **Verification for QA-009 — otherwise-verified; deferred EV-38.** `pytest:tests/traceability/test_policy_coverage.py::test_qa_009_golden_manifest_covers_every_required_case` — This requirement is verified by a structural, database, CI, or artifact check rather than a Gherkin product scenario.

> **Verification for QA-014 — otherwise-verified; deferred EV-38.** `pytest:tests/traceability/test_ci_controls.py::test_qa_014_promotion_requires_signoff_and_independent_reproduction` — This requirement is verified by a structural, database, CI, or artifact check rather than a Gherkin product scenario.

> **Verification for QA-015 — non-testable (documentation).** This documents the deliberate absence of a code-coverage target and selection of a different metric.

> **Verification for QA-016 — non-testable (meta).** This explicitly defines matters outside the testable assertion catalogue.

> **Verification for QA-017 — non-testable (governance).** Test-data provenance and permission are governance facts a repository test cannot establish completely.
