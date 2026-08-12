# Attestation and Reliance Framework

**Version:** 0.1 draft
**Repo location:** `docs/attestation-reliance.md`
**Status:** requires legal review before the first attestation — including the phase 0 concierge variant (§9)
**Audience:** relying parties, customers, counsel, auditors
**Depends on:** `coverage-methodology.md`, `evidence-spec.md`, `threat-model.md`

---

## 0. Why this exists before the MVP

Phase 0 puts manually-assembled evidence packs into live enterprise deals in month one. The moment a buyer relies on one, exposure exists — before any code ships, before any MVP freeze. This framework must therefore exist in a lightweight form now (§9) and in full before the first automated attestation.

Requirements carry IDs `AR-nnn`.

---

## 1. What an attestation is

A scoped, signed, machine-verifiable statement about a defined population of agent actions over a defined window, issued under a stated methodology version, intended for reliance by named parties for a named purpose.

### 1.1 What it is not

**AR-001** — An attestation MUST NOT be described as a certification, a conformity assessment, an audit opinion, an assurance opinion within the meaning of any professional standard, or a regulatory approval. The words "certified" and "audited" MUST NOT appear in issued artefacts referring to our own output.

**AR-002** — We produce **factual assertions about evidence**. Professional conclusions drawn from those assertions are reserved to auditors, assurance practitioners, and insurers. The separation is structural, not stylistic: it is what permits those parties to rely on us without an independence conflict.

---

## 2. Assertion catalogue

Every assertion an attestation may make, each traceable to a methodology requirement and a passing scenario. **AR-003** — No assertion outside this catalogue may be emitted.

| ID | Assertion | Basis |
|---|---|---|
| **A-01** | Records within this window form an unbroken, signature-valid chain | ES-006/021 |
| **A-02** | The declared assurance boundary was in force for the window | AR-027 |
| **A-03** | The denominator source was of class C, qualified on date D | CM-003/004 |
| **A-04** | Of the enumerated population of N actions, M were matched to evidence at level L | CM-008/011 |
| **A-05** | The following intervals are unknown, for the stated causes | CM-014/016 |
| **A-06** | Coverage level claimed is the minimum of evidence-supported and class-admissible | CM-008 |
| **A-07** | For P actions requiring human review, review records exist with the recorded properties | ES-013/014 |
| **A-08** | For Q of those, review occurred while the action was still reversible | ES-014 |
| **A-09** | Outcomes for R actions were confirmed against the named authoritative source | AR-028 |
| **A-10** | This computation is reproducible from the referenced bundle by the named verifier version | CM-013 |

**AR-004** — Each assertion carries its own scope and count. Aggregate scores, trust ratings, letter grades, and single-number summaries MUST NOT be issued. They invite reliance the evidence does not support.

### 2.1 Conditions on A-02 and A-09

Every other row in the table above points at a requirement that states the row's claim. Two did not, and were repaired here rather than re-pointed (EV-25).

**A-02** cited ES-009, which requires each declared `action_families[]` entry to carry a `qualification_ref`. That is a well-formedness rule about a boundary's contents; it says nothing about the period over which the boundary was in effect. **A-09** cited CM-007, which establishes that coverage level and verification status are orthogonal attributes. That is a rule about how two attributes relate to each other; outcome confirmation is a different subject entirely. In both cases the citation was adjacent to the claim and did not state it, so nothing in the corpus could be made to demonstrate either assertion without first writing the rule down.

Neither rule existed anywhere. Searching every numbered requirement in `coverage-methodology.md`, `evidence-spec.md`, `threat-model.md`, `architecture.md`, `security.md`, `infrastructure.md` and `data-model.md` found nothing stating that a boundary must span the window it is attested under, and nothing stating what entitles an action to be counted as outcome-confirmed. `AssuranceBoundary` carries `window_start` and `window_end` (`evidence-spec.md` §5.1) and `OutcomeRecord` carries `authoritative_source` (§5.11), but a field is not a requirement; nothing normative constrained either one. The closest statement of A-02's rule was the definition of *assurance boundary* in `coverage-methodology.md` §2 — "Claims are valid only inside it" — which carries no ID, so no assertion could cite it and the traceability matrix could not read it. That is the defect QA-018 was numbered to stop, appearing one level down.

Both rules are stated here, as conditions on issuance, because that is what they are: they govern whether an assertion may be emitted, which is this document's subject. They are not schema rules and do not constrain what a conformant record may contain.

**AR-027** — A boundary version's effective interval begins at the later of its declared `window_start` and its signed envelope `clocks.ingest_time`, so a boundary recorded after the fact cannot be backdated into force. It ends at the earlier of its declared `window_end` and the effective start of the next version of the same boundary, if one exists. A-02 MUST NOT be asserted unless that effective interval encloses the attestation window in full. Where the attestation begins before it or ends after it, A-02 is withheld and the uncovered interval is reported with its bounds. A later version does not extend the interval of the version the attestation references: the attestation MUST reference one version that was in force for its whole window. A narrower restatement of A-02 over the covered sub-interval MUST NOT be emitted in its place, because silently re-scoping the assertion is the overclaim this catalogue exists to prevent.

> **Why this is not TM-002.** TM-002 makes boundaries signed, versioned, and immutable, and TM-S-002 demonstrates that narrowing one is *visible*. Visibility and being in force are independent properties. A boundary can be narrowed in plain sight and still have been in force across the whole window, and it can have been left silently unamended while the window ran past its validity — the second case is precisely what A-02 denies, and TM-S-002 does not exercise it. Citing TM-002 would have turned the traceability gate green against a scenario that demonstrates a different claim.

**AR-028** — A-09 MUST NOT be asserted unless the authoritative source is named in the attestation and every action counted in R has a conformant `OutcomeRecord` whose `action_id` identifies that action and whose `authoritative_source` exactly matches the named source. A generic `ExternalConfirmation` does not satisfy this rule: it can prove that a destination record exists without proving the action's outcome. Actions with no matching `OutcomeRecord` are excluded from R rather than assumed confirmed; where excluding them is not possible, A-09 is withheld entirely. An absent or unnamed source withholds A-09 outright, because "confirmed" with no stated confirming party is not a factual assertion about evidence within the meaning of AR-002.

> **Why this is not CM-010.** CM-010 separates enumeration from confirmation as connector capabilities, and CM-S-005 demonstrates one direction of it: a connector that can confirm but not enumerate supports no window-level coverage claim. A-09 fails in the other direction — actions counted as confirmed whose outcome was never checked against the named source at all. A connector fully capable of confirmation satisfies CM-010 while emitting A-09 over actions it never confirmed.

---

## 3. Standing exclusions

Present on every attestation, adjacent to the assertions, not in an appendix.

**AR-005** — The following are excluded without exception:

- Semantic correctness or appropriateness of any action
- Competence or quality of any human reviewer's judgement
- Any action, identity, system, or family outside the declared boundary
- Integrity of the destination system itself
- Any period outside the declared window
- Any prediction of future behaviour
- Compliance with any law, regulation, or standard

**AR-006** — Where the boundary excludes a family the customer operates, the attestation MUST state that other families exist and are out of scope. Silence about known-excluded scope is materially misleading (threat-model §4.2).

---

## 4. Permitted reliance

**AR-007** — Each attestation names its permitted relying parties: either specific named entities, or a defined class ("enterprise customers of the issuer's customer, for procurement evaluation"). Reliance by anyone outside is unauthorised and disclaimed.

**AR-008** — Purpose limitation is explicit: procurement evaluation, renewal review, invoice verification, audit support, incident investigation, or underwriting. An attestation issued for one purpose MUST NOT be represented as supporting another.

**AR-009** — Validity period is stated and enforced by the verifier. Expired attestations verify as expired, not as valid-with-a-warning.

---

## 5. Revocation and supersession

**AR-010** — Any attestation may be revoked by the issuer. Grounds: discovered defect in computation, evidence integrity failure discovered after issuance, qualification found invalid, or customer misrepresentation.

**AR-011** — Late-arriving evidence never amends an issued attestation. It produces a superseding attestation referencing the original (CM-020).

**AR-012** — Named relying parties MUST be notified of revocation or supersession within the period stated at issuance. Notification status is recorded in the `RevocationRecord`.

**AR-013** — The verifier MUST check revocation online where possible and MUST report `unchecked` rather than `valid` when offline (TM-014).

**AR-029 — The revocation endpoint protocol.** AR-013 and TM-014 oblige a verifier to check "the issuer endpoint" and said nothing about how, which left every independent implementer to invent a protocol and left "no revocation exists" indistinguishable from "I could not ask". The protocol is:

```
GET {endpoint}/revocations/{attestation record_id}
  404                    -> the issuer published nothing        -> checked
  200 + RevocationRecord -> authenticated, then classified      -> checked
  any other response     -> nothing was established             -> unchecked
```

The 200 body MUST be a complete `RevocationRecord` in canonical wire form, carrying the primary `issuer`-namespace signature ES-033 requires of that type, and its `attestation_ref` MUST name the attestation asked about. A response failing any of those establishes nothing and MUST be reported `unchecked` — not `revoked`, because an unauthenticated response would let anyone revoke, and not `valid`, because a suppressed one would let anyone un-revoke.

**The asymmetry is deliberate.** A verifier pointed at an endpoint that does not implement this protocol reports `unchecked`, which is wrong but safe. The opposite default — treating an unrecognised answer as "nothing published" — is wrong and fatal, because every outage, misconfiguration and captive portal would then read as a clean bill of health. Where a verifier cannot distinguish the two, it MUST choose `unchecked`.

**AR-030 — `superseding_ref` distinguishes supersession from revocation.** A `RevocationRecord` whose `superseding_ref` names another attestation reports `superseded`; one without reports `revoked`. §5.14 gave the record both a `reason` and a `superseding_ref` without saying which carries the distinction, and AR-010's grounds for revocation do not include supersession while AR-011 requires a superseding attestation to reference the original — so the two states were describable and not separable. They are separate answers to a relying party: a revoked attestation says the claim was wrong, a superseded one says a later claim replaces it.

**AR-031 — A revocation takes effect at `effective_at`, not at publication.** Where an authenticated `RevocationRecord` has an `effective_at` later than the verifier's evaluation instant, the attestation is not yet revoked and the status is `valid`. The verifier MUST surface the pending revocation and its `effective_at` alongside that status. Reporting `revoked` before the issuer said it takes effect would misstate the issuer's own act; reporting `valid` while silently discarding a published revocation would withhold the one fact a relying party deciding today most needs.

**A verification is an assertion about an instant.** Because AR-009's validity period and this rule both compare against a clock, a verifier MUST make the instant it evaluated at explicit in its output, and MUST accept that instant as an input so a relying party can reconstruct a past decision rather than only ask about today.

---

## 6. Liability

**Requires your input — see §10.**

**AR-014** — Liability attaches only to the factual assertions in §2, and only where the assertion was wrong at issuance due to our defect. It does not attach to: correct assertions relied upon for an unstated purpose, conclusions the relying party drew, destination-system failure, or customer misrepresentation not detectable under the methodology.

**AR-015** — A liability cap is stated on every attestation and referenced by `liability_ref`. Cap methodology to be settled (§10).

**AR-016** — Professional and technology E&O cover MUST be in force before the first attestation carrying a cap is issued. Phase 0 concierge artefacts operate under §9 instead.

**AR-017** — Where an assertion is later found wrong, the correction process (§7) runs regardless of whether liability is triggered. Correction is not an admission and MUST NOT be gated on a liability determination.

---

## 7. Dispute and correction

**AR-018** — Any relying party or customer may dispute an assertion. Disputes are logged with an identifier, and the response states whether the assertion stands, is corrected, or is revoked.

**AR-019** — Correction produces a superseding attestation and a public change entry (identifier and date; no customer content).

**AR-020** — A dispute that reveals a methodology defect rather than an implementation defect triggers a methodology version change under CM-024.

---

## 8. Independence

**AR-021** — We produce evidence and factual assertions. Where a partner issues an assurance conclusion, certification, or opinion, that partner remains solely responsible for it, and our commercial relationship with the customer MUST be disclosed to them.

**AR-022** — We MUST NOT offer remediation consultancy for the same scope we attest. Advising a customer on how to improve a coverage figure we then attest to is the Delve failure mode and is prohibited structurally, not by policy.

**AR-023** — Any future trust mark MUST be issued by a separately governed entity (PRD §7.2).

---

## 9. Phase 0 concierge variant

Needed now. Applies to manually assembled evidence packs before any automated attestation exists.

**AR-024** — Every phase 0 artefact MUST carry, on its first page:

- That it is a manually prepared evidence summary, not an attestation
- The scope: systems, families, identities, window
- The method: how the population was established and by whom
- That no coverage claim is made unless a denominator class is stated
- That it is prepared for a named recipient for a named purpose
- That no reliance beyond that recipient and purpose is authorised
- No liability cap, because no liability is accepted — this is explicitly a working document, not an assurance product

**AR-025** — Phase 0 artefacts MUST NOT use the words attestation, certification, assurance, verified, or audited.

**AR-026** — Every phase 0 artefact is retained. When automated attestation begins, the phase 0 set is reviewed for any claim that would not survive the full framework, and recipients of those are contacted.

---

## 10. Decisions required from you

These cannot be settled without you, and the first two block §6 entirely.

| Decision | Why it needs you | Options |
|---|---|---|
| **Issuing legal entity** | An attestation is issued by a legal person. There isn't one yet for this venture — and the DamDam structure (IoM holding, French tax residence) does not obviously transfer. Jurisdiction affects enforceability, E&O availability, and how EU relying parties treat the issuer. | Decide before first attestation; likely an EU or UK entity given the relying-party population |
| **Liability cap methodology** | Determines E&O sizing and appears on every artefact | (a) Fixed low cap per attestation; (b) multiple of fees paid in trailing 12 months; (c) tiered by assurance level. (b) is the professional-services norm and the easiest to insure |
| **Named vs class reliance default** | Named is safer and slower; class scales but widens exposure | Recommend named-only through V1, class from V2 |
| **Revocation notification window** | Stated on every attestation | Recommend 5 business days; shorter is a differentiator, harder to staff solo |
| **Whether §9 needs counsel now** | It is the only part with live exposure in month one | Recommend yes — a short review of the concierge disclaimer is cheap and the exposure is real |

---

## 11. Acceptance criteria

### AR-S-001 — No assertion outside the catalogue *(AR-003)*

```gherkin
Given an attestation generation request
When the assertion set is assembled
Then every assertion maps to a catalogue ID
And any unmapped assertion causes generation to fail
```

### AR-S-002 — No aggregate score *(AR-004)*

```gherkin
When an attestation is rendered
Then no single composite score, rating, or grade appears
And each assertion carries its own scope and counts
```

### AR-S-003 — Excluded scope disclosed *(AR-006)*

```gherkin
Given a customer operating action families [X, Y, Z]
And a boundary covering only [X]
When an attestation is issued
Then it states that other families exist and are out of scope
```

### AR-S-004 — Expired verifies as expired *(AR-009)*

```gherkin
Given an attestation whose validity_until has passed
When the verifier validates it
Then the result is "expired"
And the result is not "valid"
```

### AR-S-005 — Supersession preserves the original *(AR-011)*

```gherkin
Given attestation A and superseding attestation A'
When either is verified
Then A remains independently verifiable
And A' references A
And A is reported as superseded, not invalid
```

### AR-S-006 — Phase 0 artefact language check *(AR-025)*

```gherkin
Given a phase 0 evidence pack
When it is reviewed before release
Then it contains none of: attestation, certification, assurance, verified, audited
And it carries the full §9 header
```

### AR-S-007 — A-02 is withheld where the boundary did not span the window *(AR-027, QA-018)*

Exercises AR-027, and so **A-02**. Deliberately not TM-S-002: that
scenario demonstrates that narrowing a boundary is *visible*, while A-02 claims
the declared boundary was *in force for the whole window*. A boundary can be
narrowed visibly and still have been in force throughout, and it can have been
silently unamended while the window ran past its validity. Citing TM-002 as
A-02's basis would turn this gate green without demonstrating the claim, which
is why the scenario below is new rather than a re-pointing. Owned by EV-17,
which selects assertions from the catalogue; EV-25 wrote AR-027 and this
scenario but does not build the attestation service that discharges them.

```gherkin
Given the referenced assurance boundary version has effective interval B1 to B2 after applying its declared window, signed ingest time, and any next version
And an attestation window from W1 to W2 where W1 < B1 or W2 > B2
When the attestation is generated
Then A-02 is withheld
And the uncovered interval is reported with its bounds
And no narrower restatement of A-02 is emitted in its place
```

### AR-S-008 — A-09 is withheld where outcomes were not confirmed *(AR-028, QA-018)*

Exercises AR-028, and so **A-09**. CM-S-005 covers CM-010, confirmation
without enumeration; this covers the other direction — actions counted under
A-09 whose outcome was never checked against the named authoritative source at
all. Owned by EV-17 for the same reason as AR-S-007.

```gherkin
Given R actions claimed as confirmed against a named authoritative source
And S of them have no OutcomeRecord whose authoritative_source matches that source
When the attestation is generated
Then A-09 is withheld unless R is restated as R - S
And the named source is identified in the attestation
And an unnamed or absent source withholds A-09 outright
```

### AR-S-009 — An answer the verifier cannot authenticate establishes nothing *(AR-029)*

```gherkin
Given a revocation endpoint that does not answer with an authenticated RevocationRecord
When the verifier checks revocation for an attestation
Then revocation_status is reported as "unchecked"
And it is not reported as "valid"
And it is not reported as "revoked"
```

### AR-S-010 — Supersession is distinguished from revocation *(AR-030)*

```gherkin
Given an authenticated RevocationRecord naming a superseding attestation
When the verifier checks revocation
Then revocation_status is reported as "superseded"
And the superseding attestation is identified
And an otherwise identical record with no superseding_ref reports "revoked"
```

### AR-S-011 — A revocation before its effective date does not revoke *(AR-031)*

```gherkin
Given an authenticated RevocationRecord whose effective_at is later than the evaluation instant
When the verifier checks revocation
Then revocation_status is reported as "valid"
And the pending revocation and its effective_at are surfaced
And the evaluation instant appears in the output
```

## Verification classifications

> **Verification for AR-001 — scenario-bearing; deferred EV-35.** This is externally observable runtime behaviour; EV-35 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for AR-002 — non-testable (governance).** This defines the professional responsibility boundary and is governed through contracts and review, not product execution.

> **Verification for AR-005 — scenario-bearing; deferred EV-35.** This is externally observable runtime behaviour; EV-35 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for AR-007 — scenario-bearing; deferred EV-35.** This is externally observable runtime behaviour; EV-35 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for AR-008 — scenario-bearing; deferred EV-35.** This is externally observable runtime behaviour; EV-35 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for AR-010 — scenario-bearing; deferred EV-35.** This is externally observable runtime behaviour; EV-35 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for AR-012 — scenario-bearing; deferred EV-35.** This is externally observable runtime behaviour; EV-35 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for AR-013 — scenario-bearing; deferred EV-35.** This is externally observable runtime behaviour; EV-35 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for AR-014 — non-testable (governance).** This defines contractual liability scope rather than behaviour an executable product scenario can establish.

> **Verification for AR-015 — scenario-bearing; deferred EV-35.** This is externally observable runtime behaviour; EV-35 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for AR-016 — scenario-bearing; deferred EV-35.** This is externally observable runtime behaviour; EV-35 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for AR-017 — scenario-bearing; deferred EV-35.** This is externally observable runtime behaviour; EV-35 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for AR-018 — scenario-bearing; deferred EV-35.** This is externally observable runtime behaviour; EV-35 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for AR-019 — scenario-bearing; deferred EV-35.** This is externally observable runtime behaviour; EV-35 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for AR-020 — scenario-bearing; deferred EV-35.** This is externally observable runtime behaviour; EV-35 owns its missing Gherkin scenario and executable acceptance proof.

> **Verification for AR-021 — non-testable (governance).** Partner responsibility and commercial disclosure are contractual governance obligations, not runtime behaviour.

> **Verification for AR-022 — non-testable (governance).** The prohibition on remediation consultancy for an attested scope is an organisational conflict rule.

> **Verification for AR-023 — non-testable (governance).** A future trust mark's legal-entity separation is corporate governance rather than executable behaviour.

> **Verification for AR-024 — otherwise-verified; deferred EV-38.** `pytest:tests/traceability/test_artifact_controls.py::test_ar_024_phase_zero_template_has_all_first_page_disclosures` — This requirement is verified by a structural, database, CI, or artifact check rather than a Gherkin product scenario.

> **Verification for AR-026 — non-testable (process).** Phase-zero retention, retrospective review, and recipient contact are governed operating procedures.
