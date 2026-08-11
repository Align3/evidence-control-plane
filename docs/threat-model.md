# Threat Model

**Version:** 0.1 draft
**Repo location:** `docs/threat-model.md`
**Audience:** internal engineering; design partners' security reviewers; auditors assessing whether our claims are sound. **Written to be shared.**
**Depends on:** `coverage-methodology.md`, `evidence-spec.md`
**Drives:** `security.md`, `infrastructure.md`, `testing-qa.md`

---

## 0. Why this document is unusual

Most threat models defend a system against outsiders. This one has to defend a *claim* against everyone who benefits from it being wrong — and the party who benefits most is the customer paying us.

That is not an accusation. It is the only assumption under which a relying party should accept our output. An assurance product whose threat model omits its own customer is not assurance; it is a dashboard with cryptography attached.

Requirements carry IDs `TM-nnn`.

---

## 1. Assets

| Asset | Compromise means |
|---|---|
| **Evidence integrity** | Records altered, forged, or reordered after the fact |
| **Coverage truthfulness** | A window claims a level the underlying evidence does not support |
| **Attestation authenticity** | A relying party accepts an attestation we did not issue, or accepts a revoked one |
| **Action content confidentiality** | Parameters, customer data, or business logic exposed |
| **Methodology integrity** | Published rules diverge from implemented behaviour |

The second asset is the one that ends the company. Forged evidence is a security incident; a systematically overstated coverage claim relied upon by an auditor is an existential credibility failure.

---

## 2. Trust boundaries

```
[Agent runtime] ──┐
                  ├── B1 ──> [Collector / SDK] ── B2 ──> [Ingestion] ── B3 ──> [Ledger]
[Gateway] ────────┘                                                              │
                                                                                 B4
[Destination system] ── B5 ──> [Connector] ─────────────────────────────────────┘
                                                                                 │
                                                                        [Computation]
                                                                                 │
                                                                                B6
                                                                        [Attestation]
                                                                                 │
                                                                                B7
                                                                        [Relying party]
```

| Boundary | Crossing | Trust assumption |
|---|---|---|
| B1 | Agent → collector | Collector cannot verify the agent proposed everything it actually did |
| B2 | Collector → ingestion | Records are customer-signed; we authenticate the collector but do not vouch for completeness |
| B3 | Ingestion → ledger | Durable append before ack; no queue |
| B4 | Ledger → computation | Read-only; computation is pure |
| B5 | Destination → connector | Destination is authoritative but not necessarily honest (§4.4) |
| B6 | Computation → attestation | Counter-signed by issuer |
| B7 | Attestation → relying party | Verifiable offline; revocation checked online |

---

## 3. Adversary classes

**A1 — External attacker.** No credentials. Conventional.
**A2 — The customer (agent vendor).** Legitimate credentials, controls their own deployment, benefits from favourable coverage. *Primary adversary.*
**A3 — Malicious or compromised insider at us.** Can access infrastructure; must not be able to alter customer evidence.
**A4 — Compromised destination system.** Our reconciliation authority is itself untrustworthy.
**A5 — Compromised collector or gateway.** Sits in the evidence path.
**A6 — Hostile relying party.** Fabricates or misrepresents an attestation to create a claim against a vendor.

---

## 4. Attack catalogue

### 4.1 Selective instrumentation *(A2)*

Vendor instruments only workflows that perform well.

- **Detected by:** the denominator. If the destination enumerates the true population, uninstrumented actions appear as unmatched-without-evidence and depress coverage.
- **TM-001** — Coverage MUST never be computed from the instrumented set as its own denominator. This is the entire content of `coverage-methodology.md` §3 and the reason C4 exists as a named-and-rejected class.
- **Residual:** at C4/C5 this attack is undetectable, which is why those classes cannot claim above `observed`.

### 4.2 Boundary gerrymandering *(A2)*

Vendor narrows the assurance boundary to exclude failing families or identities, producing an honest attestation over a flattering scope.

- **TM-002** — Boundaries are signed, versioned, and immutable; changes create new versions with a visible history.
- **TM-003** — Attestations MUST render scope adjacent to the claim, never in an appendix. A relying party comparing two attestations MUST be able to see that scope narrowed.
- **Residual:** a first-time buyer with no prior attestation has no baseline. Partially mitigated by cross-vendor norms once the format is adopted; not solved. **Stated as a limitation.**

### 4.3 Identity laundering *(A2)*

Agent acts under an identity indistinguishable from human operators, inflating the denominator or hiding actions.

- **TM-004** — Identity isolation is a qualification precondition (CM-005/006). Where the isolating attribute is vendor-settable per request, the qualification record MUST note it and the class MUST be capped accordingly.
- **Residual:** an agent that perfectly impersonates a human user in a system with no client attribution cannot be isolated. Such families are C5. Correct outcome, but it excludes real business.

### 4.4 Destination compromise or audit falsification *(A4, A2 with privilege)*

The system we reconcile against is manipulated — records backdated, audit entries deleted.

- **TM-005** — Qualification MUST record whether the destination permits trace-free deletion or backdating by an actor the vendor controls. Where it does, the class is capped at C3 regardless of enumeration capability.
- **Residual:** we inherit the destination's integrity. Explicitly disclaimed in `coverage-methodology.md` §12.

### 4.5 Clock manipulation *(A2, A5)*

Source clocks shifted so actions fall inside or outside a favourable window.

- **TM-006** — Three clocks recorded; destination `authoritative_time` governs where present; skew beyond threshold excludes records from the numerator (ES-019/020).
- **Residual:** where no authoritative timestamp exists, ordering rests on our ingest clock, which bounds manipulation to the network delay window.

### 4.6 Gap suppression *(A2, A5)*

Collector is disabled during a period of bad behaviour, and the gap is never recorded.

- **TM-007** — Gap markers MUST be locally signable and emittable without hosted connectivity (ES-016).
- **TM-008** — Ingestion MUST detect sequence discontinuity independently of gap markers; a missing gap marker where a sequence break exists is itself a chain break.
- **TM-009** — Denominator enumeration covering the gap interval MUST surface actions that occurred during it as unmatched-without-evidence.
- **Residual:** a collector shut down cleanly at a stream boundary produces no sequence break. Detection then depends entirely on the denominator — reinforcing that C1/C2 is not merely preferable but load-bearing.

### 4.7 Replay and duplication *(A1, A2)*

Favourable records resubmitted; unfavourable ones duplicated to dilute ratios.

- **TM-010** — `record_id` uniqueness within tenant; sequence monotonicity; duplicate destination records classified explicitly rather than merged (ES-015).

### 4.8 Key substitution *(A1, A2, A5)*

Records signed with a key the customer later disclaims, or rotation used to orphan inconvenient history.

- **TM-011** — Rotation requires an in-stream continuity assertion (ES-024). Rotation without it is a chain break, which terminates the window rather than silently continuing.

### 4.9 Enumeration truncation *(A2, A4)*

Population query silently capped, producing a small denominator and a flattering ratio.

- **TM-012** — `result_cap_hit` and `pagination_complete` are mandatory and force `coverage_ratio` to null (ES-011/012). Truncation must fail loudly.

### 4.10 Retroactive qualification upgrade *(A2)*

Connector improved, then old windows re-attested at the stronger class.

- **TM-013** — Class applies only to windows beginning after the qualification date (CM-004, ES-010). Verifier enforces this independently.

### 4.11 Attestation forgery or stale reliance *(A1, A6)*

A fabricated or revoked attestation presented as current.

- **TM-014** — Issuer counter-signature; verifier checks revocation status against the issuer endpoint and MUST report `revocation_status: unchecked` when offline rather than assuming valid.

### 4.12 Evidence withholding by us *(A3)*

We suppress a bundle that would embarrass a customer, or lose it.

- **TM-015** — Customers hold their own copy; the verifier runs offline; attestations reference population records the customer can independently retrieve.
- **Residual:** we can decline to issue. We cannot silently alter. This asymmetry is the honest boundary of the two-signature model and is stated in `evidence-spec.md` §7.

### 4.13 Methodology drift *(A3, organisational)*

Implemented behaviour diverges from published rules.

- **TM-016** — Every published requirement has a scenario; the traceability matrix is published (`testing-qa.md` §7). Divergence becomes visible to anyone who reads both.

### 4.14 Content exposure *(A1, A3)*

Action parameters contain regulated or confidential data.

- **TM-017** — Digest-by-default; cleartext inclusion is per-family, boundary-recorded, and visible to relying parties (ES-025/026).

---

## 5. What this design does not defend against

Stated because an assurance practitioner will look for it, and because the credibility of everything above depends on this section being honest.

1. **Actions in systems outside the boundary.** No claim, ever.
2. **A destination system that lies.** Inherited weakness, disclosed.
3. **Perfect impersonation with no client attribution.** Produces C5, which is correct but is a limit, not a defence.
4. **Refusal to issue.** We cannot forge; we can decline. Mitigated by customer-held copies, not eliminated.
5. **Semantic correctness of any action.** Out of scope by construction.
6. **Competence of human reviewers.** We evidence that review occurred with recorded properties. Nothing about judgement quality.
7. **A collector cleanly stopped at a stream boundary in a C4/C5 family.** Undetectable. This is the strongest argument in the document for refusing C4/C5 business at anything above `observed`.

---

## 6. Acceptance criteria

### TM-S-001 — Uninstrumented actions surface as unmatched *(TM-001)*

```gherkin
Given denominator class C1 for action family "refund.issue"
And the vendor instruments only 60 of 100 refunds in window W
When coverage is computed
Then 40 actions are classified unmatched-without-evidence
And the coverage ratio reflects 60/100
And the attestation does not report 100% of the instrumented set
```

### TM-S-002 — Boundary narrowing is visible *(TM-002, TM-003)*

```gherkin
Given attestation A1 covering action families [X, Y]
When a later attestation A2 covers only [X]
Then A2 renders its scope adjacent to its coverage claim
And the boundary version history shows the removal of Y
```

### TM-S-003 — Clean collector stop is caught by the denominator *(TM-009)*

```gherkin
Given a collector stopped cleanly at a stream boundary at 14:00
And restarted at 15:00 with a new stream
And 30 actions executed between 14:00 and 15:00
When coverage is computed with a C1 denominator
Then those 30 actions appear as unmatched-without-evidence
And the window does not claim enforced coverage for 14:00-15:00
```

### TM-S-004 — Offline verifier reports unchecked revocation *(TM-014)*

```gherkin
Given the verifier is run without network access
When it validates an attestation bundle
Then signature and chain verification succeed
And revocation_status is reported as "unchecked"
And the output does not state that the attestation is valid
```

### TM-S-005 — Retroactive upgrade rejected by verifier *(TM-013)*

```gherkin
Given a QualificationRecord assigning class C1 dated 2026-09-01
And an attestation for a window starting 2026-08-01 claiming class C1
When the verifier validates it
Then verification fails with "qualification postdates window"
```

### TM-S-006 — Duplicate destination records not merged *(TM-010)*

```gherkin
Given two destination records with identical content and distinct identifiers
When reconciliation runs
Then both are classified "duplicate"
And neither is silently discarded
And the counts in the attestation reflect the duplication
```

## Verification classifications

> **Verification for TM-004 — scenario-bearing; deferred EV-34.** This is externally observable runtime behaviour; EV-34 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for TM-005 — scenario-bearing; deferred EV-34.** This is externally observable runtime behaviour; EV-34 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for TM-007 — scenario-bearing; deferred EV-36.** This is externally observable runtime behaviour; EV-36 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for TM-008 — scenario-bearing; deferred EV-36.** This is externally observable runtime behaviour; EV-36 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for TM-011 — scenario-bearing; deferred EV-33.** This is externally observable runtime behaviour; EV-33 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for TM-012 — scenario-bearing; deferred EV-34.** This is externally observable runtime behaviour; EV-34 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for TM-015 — scenario-bearing; deferred EV-37.** This is externally observable runtime behaviour; EV-37 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for TM-016 — otherwise-verified.** `pytest:tests/traceability/test_acceptance.py::test_qa_s_010_new_requirement_without_classification_fails_ci` — This requirement is verified by a structural, database, CI, or artifact check rather than a Gherkin product scenario.

> **Verification for TM-017 — scenario-bearing; deferred EV-37.** This is externally observable runtime behaviour; EV-37 owns its missing Gherkin scenario and executable acceptance proof.
