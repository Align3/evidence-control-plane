# Denominator Probe Protocol

**Repo location:** `docs/denominator-probe.md`
**Purpose:** determine empirically whether a defensible coverage denominator exists for any real action family against a real system of record.
**Depends on:** `coverage-methodology.md` §3, §4, §7
**Gates:** EV-13, EV-14, and the commercial thesis

---

## 0. What this is testing

The riskiest assumption in the venture, stated plainly:

> For some real action family in some real enterprise system, we can establish the authoritative population of agent actions **independently of the vendor**, and separate agent-originated actions from human-originated ones.

If that is false everywhere we look, the product caps at `observed` coverage permanently, which is a logging tool with extra steps. Everything else — the architecture, the attestation format, the pitch — assumes this is achievable at class C1 or C2 for at least some meaningful set of families.

It costs a few days and no money. Sandbox tiers are free on every candidate below.

---

## 1. The two-phase split, and why collapsing it fails

**Phase A — desk.** Read API documentation. Produce a *hypothesis* about the denominator class.

**Phase B — hands.** Create a sandbox account, perform real actions under two distinct credentials, run the actual enumeration query. Produce a *finding*.

**DP-001 — A go/no-go decision may only be made on a Phase B finding.** Phase A output is never sufficient.

The reason is a specific and predictable false positive. Documentation will tell you a system supports scoped API credentials, service accounts, or restricted keys. An analyst — human or agent — reads that and concludes identity isolation works. But the question is not *can you create a distinct credential*. The question is:

> **Does the created record retain which credential created it, and is that attribute retrievable through the enumeration API?**

Those are different properties and most documentation does not distinguish them. A system can have excellent credential management and still return records with no durable actor attribution. You cannot find that out by reading; you find it out by creating a record and looking at what comes back.

This is the trap that would let you conclude the thesis works when it does not.

---

## 2. Phase A — desk protocol

Per candidate system, per action family, answer from documentation. Every answer carries a source URL. "I believe so" is not an answer.

| # | Question | What specifically to find |
|---|---|---|
| A1 | Is there a list/search endpoint scoped by a time window? | Endpoint, the time parameter, whether it filters on creation or modification |
| A2 | Is ordering guaranteed and stable across pages? | Documented ordering guarantee; cursor vs offset pagination |
| A3 | Is there a result cap? | Maximum page size, maximum total results, whether truncation is signalled |
| A4 | Can results be filtered or grouped by the acting principal? | The parameter name, or explicitly none |
| A5 | Does a returned record carry an actor attribute? | The field name, or explicitly none |
| A6 | Can that attribute be set arbitrarily per request by the caller? | If yes, it is not a trustworthy isolator |
| A7 | Is there a separate audit-log API with actor attribution? | Endpoint, retention period, whether it requires elevated plan tier |
| A8 | Is there an authoritative server-side timestamp? | Field name, whether client-supplied values are accepted |
| A9 | What is the documented retention period? | For records and for audit entries separately |
| A10 | Can records be deleted or backdated, and does it leave a trace? | Delete semantics: hard, soft, or none |

**Output:** a hypothesis of C1, C2, C3, or C5 per family, with the reasoning and the specific uncertainty that Phase B must settle.

---

## 3. Phase B — hands protocol

The experiment. Roughly two to three hours per system once the account exists.

### Setup

1. Create a free sandbox or developer account.
2. Create **two** distinct credentials: one standing in for the agent, one for a human operator. Where the system distinguishes API keys from user accounts, use one of each — that is the realistic enterprise shape.

### Run

3. Note the start time. Perform **10 actions under the agent credential and 10 under the human credential, interleaved**, over roughly 30 minutes. Record the exact identifier and timestamp of each.
4. Wait 30 minutes.

### Measure

5. **Enumeration.** Query the list endpoint for the window. Does it return exactly 20? Does pagination complete? Is truncation signalled or silent?
6. **Isolation — the decisive test.** Can you retrieve exactly the 10 agent actions, and only those, from the API? Not from the dashboard — from the API, with a field on the record or a filter parameter.
7. **Settlement lag.** From the timestamps: how long between an action being performed and appearing in enumeration? Take the maximum observed.
8. **Confirmation.** Retrieve one action individually. Is that a different endpoint or permission from enumeration?
9. **Mutability.** Delete or amend one action. Does the enumeration still show it? Is there a trace?
10. **Retention.** Confirm the documented retention against what the API actually exposes.

### Record

11. Fill a `QualificationRecord` per `evidence-spec.md` §5.2 and Appendix A of `coverage-methodology.md`.

**DP-002 — Paste the raw API responses.** Not a summary of them. This is the same discipline as AG-009: a self-report is not evidence, and that applies to your own research as much as to an agent's PR.

---

## 4. Candidate systems

**These are hypotheses ranked by plausibility, not findings.** API capabilities change and none of this is confirmed — confirming it is the point of the exercise. Verify each against current documentation before investing time.

| Candidate | Action family | Why plausible | The specific doubt |
|---|---|---|---|
| **CRM with per-record creator attribution** (e.g. Salesforce) | Record create/update | Object-level created-by fields and a query language that filters on them would give strong isolation directly on the record | Whether integration users are distinguishable from human users in practice, and whether the field survives bulk operations |
| **Ticketing / support** (e.g. Zendesk, Intercom) | Ticket resolution, reply | Audit and event trails with channel and actor are common; the largest agent-vendor population sits here | Whether the audit trail is retained long enough and is available below enterprise plan tiers |
| **Payments** (e.g. Stripe) | Refund, disbursement | Strongest audit culture, clean list endpoints, highest buyer anxiety so the evidence is worth most | Whether the created object durably records *which API key* created it, retrievable via API rather than only in dashboard request logs. This is the doubt worth resolving first |
| **Accounting** (e.g. Xero, QuickBooks) | Invoice, payment, journal | Regulated bookkeeping implies immutability and strong audit trails | API surface for enumeration by actor is often thinner than the audit UI suggests |
| **Calendar / scheduling** | Booking, cancellation | Creator and organiser fields are standard | Agents frequently act *as* the user via delegation, which collapses isolation |

Probe **three**, not one. A single negative result tells you little; three tells you whether this is a property of the category or of one vendor.

---

## 5. Go / no-go

**DP-003 — The gate for proceeding to EV-13:**

> For at least one action family in at least one system, Phase B demonstrated that the authoritative population can be enumerated for a bounded window, that agent-originated actions can be isolated from human-originated ones through the API, and that the settlement lag is bounded and measured.

**Green** — one or more candidates reach C1 or C2 on a Phase B finding. Proceed; that family becomes the MVP target and shapes design-partner selection.

**Amber** — candidates reach C3 only (enforcement-authoritative, no destination enumeration). The product still works but coverage caps at `enforced`, never `reconciled`. This materially weakens the pitch and should change how you talk about it. Probe two more before accepting it.

**Red** — nothing above C4 anywhere. Stop and reconsider before writing another line of the coverage engine. The honest options are to reframe around reliability and security evidence rather than coverage, or to reconsider the venture. Better to find this now than after four stories of cryptographic primitives.

---

## 6. Downstream use

The probe is not only a technical gate.

**It sharpens the ICP.** "Sells into enterprise procurement" becomes "operates agents in systems where a class C1 or C2 denominator is available." That is a filter you can apply to a target list.

**It is the outreach question.** Fifteen minutes into a first call, with a hard answer:

> *In your destination system, can you list everything your agent did last week, separately from what your human staff did?*

**It sizes the market bottoms-up.** Vendors whose agents act in the systems that passed, times a defensible ACV band — which is the slide-5 number still sitting as a placeholder in the deck.

---

## 7. Time and cost

| Phase | Effort | Delegable? |
|---|---|---|
| A — desk, 3 systems | 1 day | Yes, heavily |
| B — hands, per system | 2–3 hours + account setup | Partly; the isolation test needs your judgement |
| Writing up 3 QualificationRecords | half a day | Yes, from your raw output |

Roughly a week elapsed, running alongside the build. No cost — every candidate has a free sandbox tier.

## Verification classifications

> **Verification for DP-001 — otherwise-verified; deferred EV-38.** `pytest:tests/traceability/test_research_controls.py::test_dp_001_decision_record_is_based_on_a_phase_b_finding` — This requirement is verified by a structural, database, CI, or artifact check rather than a Gherkin product scenario.

> **Verification for DP-002 — otherwise-verified; deferred EV-38.** `pytest:tests/traceability/test_research_controls.py::test_dp_002_phase_b_evidence_contains_raw_api_responses` — This requirement is verified by a structural, database, CI, or artifact check rather than a Gherkin product scenario.

> **Verification for DP-003 — otherwise-verified; deferred EV-38.** `pytest:tests/traceability/test_research_controls.py::test_dp_003_ev_13_gate_has_all_three_phase_b_proofs` — This requirement is verified by a structural, database, CI, or artifact check rather than a Gherkin product scenario.
