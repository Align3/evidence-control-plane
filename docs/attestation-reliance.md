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
| **A-02** | The declared assurance boundary was in force for the window | ES-009 |
| **A-03** | The denominator source was of class C, qualified on date D | CM-003/004 |
| **A-04** | Of the enumerated population of N actions, M were matched to evidence at level L | CM-008/011 |
| **A-05** | The following intervals are unknown, for the stated causes | CM-014/016 |
| **A-06** | Coverage level claimed is the minimum of evidence-supported and class-admissible | CM-008 |
| **A-07** | For P actions requiring human review, review records exist with the recorded properties | ES-013/014 |
| **A-08** | For Q of those, review occurred while the action was still reversible | ES-014 |
| **A-09** | Outcomes for R actions were confirmed against the named authoritative source | CM-007 |
| **A-10** | This computation is reproducible from the referenced bundle by the named verifier version | CM-013 |

**AR-004** — Each assertion carries its own scope and count. Aggregate scores, trust ratings, letter grades, and single-number summaries MUST NOT be issued. They invite reliance the evidence does not support.

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
