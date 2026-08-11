# Coverage and Assurance Methodology

**Status:** Draft v0.1 — for design-partner and assurance-practitioner review
**Repo location:** `docs/coverage-methodology.md`
**Audience:** internal engineering, design partners' security reviewers, auditors and assurance practitioners evaluating whether to rely on an attestation
**Depends on:** nothing. This document leads.
**Drives:** `evidence-spec.md`, `architecture.md`, `reconciliation.md`, `testing-qa.md`, `attestation-reliance.md`

---

## 0. Reading guide

This document defines what we are entitled to claim and why. It is the methodology an external party evaluates before deciding whether our attestations are worth relying on. It is written to be published.

Sections 3 and 6 are the load-bearing ones: the denominator taxonomy and the admissibility lattice. Everything else follows from them. Section 12 states what this methodology does **not** establish, and it is not optional reading — an assurance practitioner will look for it first, and its absence is a red flag.

Requirements carry IDs of the form `CM-nnn`. Scenarios in §13 reference them. No requirement is considered implemented without at least one passing scenario, and no assertion may appear in `attestation-reliance.md` without a corresponding requirement here.

---

## 1. Purpose

An attestation makes claims about a population of agent actions over a time window. The central question this methodology answers is:

> On what basis do we know what the population *was*, as opposed to what we happened to record?

Everything defensible about this product rests on that distinction. A system that reports what it captured is a logging tool. A system that can state what it captured **relative to an independently established population**, and can name what it could not see, is assurance infrastructure.

### 1.1 Design commitment

**CM-001** — The methodology never converts an unknown into a percentage. Where the population cannot be independently established, no coverage ratio is emitted, and the attestation says so in those terms.

---

## 2. Definitions

| Term | Definition |
|---|---|
| **Assurance boundary** | The declared scope of an attestation: tenant, deployment, agent identities, action families, destination systems, enforcement points, policy versions, and time window. Claims are valid only inside it. |
| **Action family** | A class of consequential action with shared semantics, risk class, finality behaviour, and evidence requirements. E.g. `refund.issue`, `ticket.resolve`. |
| **Population** | The true set of in-scope actions that actually occurred in the window. Generally unknowable directly. |
| **Denominator** | Our best evidenced estimate of the population, derived from a **named source of a declared class**. Never a synonym for population. |
| **Numerator** | The set of in-scope actions for which we hold evidence satisfying a given coverage level. |
| **Enumeration** | A connector capability: list the population for a scope and window. |
| **Confirmation** | A connector capability: verify or retrieve the authoritative record for one action. |
| **Coverage level** | What our evidence establishes about an action or window (§5). |
| **Denominator class** | How strong the basis for our population estimate is (§3). |

**CM-002** — Population and denominator are distinct concepts and must be distinct fields in the evidence schema. Any code path or document that uses them interchangeably is a defect.

---

## 3. Denominator taxonomy

Five classes, descending in strength. The class is a property of the *(action family, destination system, deployment)* triple, not of the product.

### C1 — Destination-authoritative

The destination system can enumerate the true population for the declared scope directly. *All refunds issued against account X between T1 and T2*, queried from the system that owns refunds.

- **Strength:** highest. The population is established by a party with no incentive to flatter our coverage and no dependency on our instrumentation.
- **Requires:** an enumeration API scoped by time and by an identity or account attribute within the boundary; stable record identity; an authoritative timestamp.
- **Fails when:** enumeration is paginated without a stable ordering guarantee, is eventually consistent without a settlement bound, or is capped at a result limit that silently truncates.

**This is the target class.** Design-partner selection prioritises action families where C1 is available.

### C2 — Identity-scoped

The destination's audit log enumerates all actions performed by a specific principal, credential, or service account.

- **Strength:** near-C1 in practice, and often easier to obtain, since most enterprise systems expose per-principal audit trails even when they do not expose domain-level enumeration.
- **Requires:** the agent acts under a distinguishable identity (§4), and the audit log is retained at least as long as the attestation validity period.
- **Fails when:** the audit log is best-effort, sampled, or subject to retention shorter than the window; or when administrative action can delete audit entries without trace.

### C3 — Enforcement-authoritative

An enforcement point in the action path attests that it saw everything for the scope.

- **Strength:** only as strong as that enforcement point's own tamper-evidence and independence from the vendor. A third-party gateway is materially stronger than the vendor's own; this is an additional argument for third-party collection.
- **Requires:** authenticated, sequence-complete records from the enforcement point, with its identity and version bound to each record.
- **Fails when:** the enforcement point is bypassable by configuration the vendor controls, or when its completeness claim is itself unverifiable.

### C4 — Sequence-derived

Our own collector's monotonic sequence establishes that our records are internally complete.

- **Strength:** low. Proves we did not lose what we received. Cannot prove actions did not bypass us entirely.
- **Use:** never sufficient alone as a denominator. Valuable as a supplementary gap-detection signal at any class.

### C5 — None available

No enumerable population exists for the action family in this deployment.

- **Consequence:** enforced and reconciled coverage are permanently unclaimable. The attestation may still carry observed-level evidence and oversight records, clearly labelled.

**CM-003** — Every assurance boundary declares, per action family, the denominator source and its class. An attestation cannot be issued for a family whose denominator class is undeclared.

**CM-004** — Denominator class is established by evidence at qualification time (§7), re-verified on a declared cadence, and recorded in the attestation. A class may be downgraded mid-window; it may never be upgraded retroactively.

---

## 4. Identity isolation — the qualifying constraint

The failure mode that most often disqualifies an otherwise viable action family is not enumeration. It is attribution.

If the agent acts through a credential shared with human operators, or impersonates end users, then the destination can enumerate the population but cannot separate agent-originated actions from human-originated ones. The denominator is inflated by activity outside the assurance boundary and no engineering recovers it.

**CM-005** — For C1 or C2, the agent's actions must be distinguishable in the destination system by a stable attribute (service principal, API credential, actor ID, or equivalent) that human activity does not share. Where distinguishability is partial — for example an agent that impersonates users but stamps a client identifier — the attribute must be one the vendor cannot set arbitrarily per-request without detection.

**CM-006** — Where identity isolation cannot be established, the denominator class is C5 regardless of enumeration capability.

### 4.1 Practical consequence for qualification

This is a first-conversation question with a hard answer, and it is a better ICP filter than any general enquiry about procurement pain:

> *In your destination system, can you list everything your agent did last week, separately from what your human staff did?*

---

## 5. Coverage levels

What our evidence establishes about an action, and by aggregation about a window.

| Level | Claim |
|---|---|
| **Observed** | Instrumentation reported the event. No claim about routing or completeness. |
| **Intercepted** | A trusted checkpoint or collector received the request before execution. |
| **Enforced** | Execution required a valid authorisation decision within the declared boundary. |
| **Reconciled** | Destination-system records match our checkpoint or enforcement records. |
| **Unknown / gap** | Coverage cannot be established for an interval, source, identity, or action family. Always explicit; never absorbed into another level. |

### 5.1 Verification status is orthogonal

Earlier drafts listed *independently verified* as a fifth rung. It is not a rung. Independent verification is a property of whether a third party reproduced our computation, and it applies to any underlying level. Treating it as the top of a single ladder implies that an independently-verified-observed claim is stronger than a self-computed-reconciled claim, which is false.

**CM-007** — An attestation carries two orthogonal attributes: coverage level, and verification status (`self-computed` | `independently-reproduced`). Neither substitutes for the other.

---

## 6. Admissibility lattice

The binding rule of this methodology. Denominator class caps the coverage level claimable for a window, regardless of how complete our own records appear.

| Denominator class | Max claimable coverage level | Coverage ratio emitted? |
|---|---|---|
| C1 — destination-authoritative | Reconciled | Yes |
| C2 — identity-scoped | Reconciled | Yes |
| C3 — enforcement-authoritative | Enforced | Yes, qualified by enforcement-point independence |
| C4 — sequence-derived | Observed | **No** |
| C5 — none | Observed | **No** |

**CM-008** — Coverage computation returns the minimum of (level supported by the evidence) and (level admissible under the denominator class). This is enforced in code, not by convention, and is the subject of the negative scenarios in §13.

**CM-009** — A coverage ratio is emitted only at C1, C2, or C3. At C4 and C5 the attestation reports absolute counts of evidenced actions and states that the population is not independently enumerable.

---

## 7. Denominator qualification procedure

Run per *(action family, destination system, deployment)* before any attestation is issued for that family. Output is a signed qualification record referenced by the assurance boundary.

1. **Enumeration capability.** Can the destination list in-scope actions for a bounded window? Record the API, scoping parameters, ordering guarantee, pagination behaviour, and any result cap.
2. **Identity isolation.** Can agent-originated actions be separated from human-originated ones? Record the attribute and whether the vendor can set it per-request.
3. **Confirmation capability.** Can an individual action be retrieved or verified independently of enumeration? Record whether this uses a different API or permission set.
4. **Temporal integrity.** Does the destination provide an authoritative timestamp? What is its settlement lag — the maximum delay before a record becomes visible to enumeration?
5. **Retention.** Is the enumeration source retained at least as long as attestation validity?
6. **Mutability.** Can records be deleted or backdated by an actor the vendor controls, without trace?
7. **Class assignment**, with the evidence for it recorded.
8. **Live reconciliation trial.** At least one week of real production activity reconciled, with a documented match rate and a documented explanation for every unmatched record.

**CM-010** — Steps 1–3 are separate capabilities and are recorded separately. A connector possessing confirmation without enumeration supports reconciliation of individual actions but **cannot** support a coverage claim. This distinction is structural and appears in the connector interface.

---

## 8. Computation rules

**CM-011 — No imputation.** Unmatched, missing, or ambiguous records are never estimated, extrapolated, or statistically adjusted. They are counted and classified.

**CM-012 — Classification is exhaustive.** Every record in the denominator resolves to exactly one of: matched, unmatched-with-evidence, unmatched-without-evidence, duplicate, ambiguous, or out-of-scope. Residual buckets are defects.

**CM-013 — Purity.** Coverage computation is a pure function of the stored evidence ledger, the qualification record, and the declared boundary. Recomputation from the same inputs yields an identical result. No computation may mutate the ledger.

**CM-014 — Unknown is reported as an interval, not a number.** Gaps are expressed as time ranges with affected scope and cause, not folded into a percentage.

---

## 9. Gaps and downgrade

**CM-015** — A fail-open interval produces a signed gap record. The window containing it cannot claim enforced coverage for that interval. Actions executing during the gap are classified unknown unless subsequently reconciled against the destination, in which case they may reach reconciled but never enforced.

**CM-016** — Loss of the denominator source for part of a window renders that part unknown. The remainder may still carry its supported level, with the unknown interval stated adjacently — never in a footnote.

**CM-017** — A chain break (missing sequence, unverifiable signature, key rotation without continuity proof) terminates the window at the break. Evidence after the break belongs to a new window.

**CM-018** — Clock skew beyond the declared threshold flags affected records. Where the destination provides an authoritative timestamp, it governs; where it does not, skewed records are excluded from the numerator and counted as unknown.

---

## 10. Time, settlement, and late evidence

Three clocks are recorded for every record: source, ingestion, and destination. The destination clock is authoritative for reconciliation wherever available.

**CM-019** — Every action family declares a **settlement lag**: the maximum delay before a destination record becomes visible to enumeration. An attestation window may not be issued until the settlement lag has elapsed past the window's end.

**CM-020** — Evidence arriving after issuance never silently amends an issued attestation. It triggers a superseding attestation referencing the original, with relying-party notification per `attestation-reliance.md`.

---

## 11. Adversary assumption

Coverage methodology assumes the vendor benefits from favourable numbers. This is not an accusation; it is the only assumption under which a relying party should accept our output.

**CM-021** — No coverage claim may depend on vendor-reported completeness. Where a control's integrity rests on vendor configuration, the attestation states this as a limitation and the affected claim is capped accordingly.

Concretely, this rules out: vendor-declared population counts, vendor-controlled per-request identity attributes as the sole isolation mechanism, and enforcement-point completeness claims where the vendor can disable the enforcement point without a recorded trace.

---

## 12. What this methodology does not establish

Stated plainly because a relying party will look for it, and because overclaiming here is the failure that ends the company.

- **Not semantic correctness.** That a refund was issued is evidenced. That it *should* have been is not.
- **Not decision quality.** Oversight records establish that review occurred with recorded properties — reviewer, authority, evidence shown, timing relative to commitment. They do not establish that the review was competent or the judgement sound.
- **Not absence outside the boundary.** Nothing is claimed about actions in systems, identities, or families not declared in scope.
- **Not destination-system integrity.** We reconcile against the destination's records. If the destination is itself compromised or its audit log is falsifiable by a privileged actor, our reconciliation inherits that weakness. Where known, this is recorded in the qualification record.
- **Not a conformity assessment.** Nothing here constitutes certification or a statutory conformity assessment under any regime.
- **Not continuous unless stated.** An attestation covers its declared window. It says nothing about the period after it.

---

## 13. Acceptance criteria

Weighted deliberately toward negative cases: the dangerous defect in this system is not a crash but a false claim. Scenario IDs are `CM-S-nnn`.

### CM-S-001 — Coverage ratio withheld at insufficient denominator class *(CM-009)*

```gherkin
Given an action family "ticket.resolve" with denominator source class C4
When coverage is computed for window W
Then no coverage ratio is emitted
And the maximum claimable coverage level is "observed"
And the attestation states that the population is not independently enumerable
```

### CM-S-002 — Identity isolation failure forces C5 *(CM-005, CM-006)*

```gherkin
Given a destination connector that can enumerate all records in window W
And the agent acts under a credential also used by human operators
When denominator qualification runs for action family "ticket.resolve"
Then the denominator source is classified "C5"
And enforced and reconciled coverage are unclaimable for that family
And the qualification record states identity isolation as the disqualifying reason
```

### CM-S-003 — Fail-open interval cannot claim enforced coverage *(CM-015)*

```gherkin
Given a declared boundary for action family "refund.issue" at class C1
And the checkpoint is unreachable from 10:00 to 10:07
And 12 actions executed during that interval
When an attestation window covering 09:00-11:00 is generated
Then the window does not claim "enforced" for 10:00-10:07
And a signed gap record for that interval is present
And the 12 actions are classified unknown, or reconciled if destination-matched
And no action in that interval is classified enforced
```

### CM-S-004 — Admissibility caps evidence-supported level *(CM-008)*

```gherkin
Given evidence sufficient to support "reconciled" for every action in window W
And a denominator source of class C3
When coverage is computed
Then the claimed level is "enforced"
And the attestation records that the level was capped by denominator class
```

### CM-S-005 — Confirmation without enumeration blocks coverage *(CM-010)*

```gherkin
Given a connector that can confirm individual actions
And that cannot enumerate the population for a window
When an attestation is requested for that action family
Then per-action reconciliation results are available
And no window-level coverage claim is emitted
```

### CM-S-006 — Late evidence supersedes rather than amends *(CM-020)*

```gherkin
Given attestation A issued for window W with 3 unmatched records
When a destination confirmation matching one of them arrives after issuance
Then attestation A is not modified
And a superseding attestation A' is issued referencing A
And relying parties of A are notified
```

### CM-S-007 — Recomputation is deterministic *(CM-013)*

```gherkin
Given an evidence ledger state L, qualification record Q, and boundary B
When coverage is computed twice
Then both computations return identical results
And the ledger is unchanged
```

### CM-S-008 — Chain break terminates the window *(CM-017)*

```gherkin
Given a signed evidence chain for window W
And a sequence gap at position n with no continuity proof
When an attestation is generated for W
Then the window terminates at position n
And evidence after the break is assigned to a new window
And the attestation does not claim coverage past the break
```

### CM-S-009 — Denominator class cannot be upgraded retroactively *(CM-004)*

```gherkin
Given window W was recorded under denominator class C4
When the connector is later upgraded to support enumeration at class C1
Then attestations for W remain capped at the C4 admissible level
And only windows beginning after the qualification date may claim C1
```

### CM-S-010 — Unknown is not absorbed *(CM-014, CM-016)*

```gherkin
Given a window in which the denominator source was unavailable for 90 minutes
When the attestation is rendered
Then the unknown interval appears adjacent to the coverage claim
And it is expressed as a time range with cause and affected scope
And it is not expressed as a reduction in the coverage percentage alone
```

---

## 14. Versioning and change control

**CM-022** — This methodology is versioned independently of the evidence schema. Every attestation records the methodology version under which it was computed.

**CM-023** — A methodology change that would alter the level claimable for previously issued attestations does not retroactively apply. Historical attestations remain verifiable under the version that produced them; the verifier must support every published version.

**CM-024** — Changes affecting admissibility (§6) or the taxonomy (§3) are material and require the change log to state the effect on existing attestations. From V2 onward these pass through the independent technical committee.

---

## 15. Open items requiring design-partner data

Cannot be closed solo. Each blocks a specific downstream section.

| Item | Blocks | Resolution |
|---|---|---|
| First action family and destination system | `reconciliation.md`, concrete §7 worked example | Phase 0 partner selection |
| Settlement lag values per family | CM-019 thresholds | Measured against live production data |
| Clock skew threshold | CM-018 | Measured; provisional default 5s pending data |
| Result-cap and pagination behaviour of first destination API | C1 viability | API documentation review, then live trial |
| Whether any candidate destination permits trace-free audit deletion | C1/C2 downgrade rules | Vendor documentation plus live test |

---

## Appendix A — Qualification record fields

| Field | Content |
|---|---|
| Scope | Action family, destination system, deployment, agent identities |
| Enumeration | API, scoping parameters, ordering guarantee, pagination, result cap |
| Isolation | Attribute, vendor-settable (y/n), partial-isolation notes |
| Confirmation | API, permission set, independence from enumeration |
| Temporal | Authoritative timestamp source, measured settlement lag |
| Retention | Source retention period vs. attestation validity |
| Mutability | Deletion/backdating capability, trace availability |
| Class | Assigned class with evidence |
| Trial | Window reconciled, match rate, unmatched-record explanations |
| Validity | Qualification date, re-verification cadence, signature |

## Verification classifications

> **Verification for CM-001 — scenario-bearing; deferred EV-34.** This is externally observable runtime behaviour; EV-34 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for CM-002 — otherwise-verified; deferred EV-38.** `pytest:tests/traceability/test_structural_requirements.py::test_cm_002_population_and_denominator_are_distinct_schema_fields` — This requirement is verified by a structural, database, CI, or artifact check rather than a Gherkin product scenario.

> **Verification for CM-003 — scenario-bearing; deferred EV-34.** This is externally observable runtime behaviour; EV-34 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for CM-007 — scenario-bearing; deferred EV-34.** This is externally observable runtime behaviour; EV-34 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for CM-011 — scenario-bearing; deferred EV-34.** This is externally observable runtime behaviour; EV-34 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for CM-012 — scenario-bearing; deferred EV-34.** This is externally observable runtime behaviour; EV-34 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for CM-018 — scenario-bearing; deferred EV-34.** This is externally observable runtime behaviour; EV-34 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for CM-019 — scenario-bearing; deferred EV-34.** This is externally observable runtime behaviour; EV-34 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for CM-021 — scenario-bearing; deferred EV-34.** This is externally observable runtime behaviour; EV-34 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for CM-022 — non-testable (documentation).** The methodology has its own published version and change history; this requirement governs documents.

> **Verification for CM-023 — scenario-bearing; deferred EV-33.** This is externally observable runtime behaviour; EV-33 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for CM-024 — non-testable (governance).** Material methodology changes require change-log disclosure and committee governance rather than a product scenario.
