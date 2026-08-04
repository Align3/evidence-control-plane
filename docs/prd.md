# Product Requirements — Build Specification

**Version:** 0.2 (supersedes the PDF PRD of July 2026)
**Repo location:** `docs/prd.md`
**Purpose:** the spec coding agents build from. Every story here is sized to be picked up independently.

---

## 0. How to use this document

This is the entry point for Codex and Claude Code. The working pattern:

1. An agent picks a story by ID (`EV-nn`).
2. It reads the **Satisfies** requirements in the referenced documents.
3. It writes the **Acceptance** scenarios as failing tests first.
4. It implements until they pass.
5. Independent review before merge — no self-report accepted.

**Concurrency rule.** Every story declares **Touches**: the files and tables it will modify. Two stories may run concurrently only if their Touches sets are disjoint. This is the rule that prevents the collision class DamDam hit when work was split by story number instead of by file overlap.

**Requirement IDs referenced here live in:**

| Prefix | Document |
|---|---|
| `CM-` | `coverage-methodology.md` |
| `ES-` | `evidence-spec.md` |
| `TM-` | `threat-model.md` |
| `AR-` | `attestation-reliance.md` |
| `AC-` | `architecture.md` |
| `SE-` | `security.md` |
| `IN-` | `infrastructure.md` |
| `QA-` | `testing-qa.md` |

---

## 1. Reconciliation with the PDF PRD

Four material changes. Where this document and the PDF disagree, **this document wins**.

| Change | Was | Now | Why |
|---|---|---|---|
| `PopulationRecord` | Did not exist | First-class signed record type (ES-011/012) | CM-002 forbids conflating population with denominator; enforcement requires the enumeration snapshot be signed evidence, not a computed number |
| "Independently verified" | Listed as top coverage level | Orthogonal attribute (`verification_status`) | A single ladder implies verified-observed beats self-computed-reconciled, which is false (CM-007) |
| Human oversight record | P1 | **P0** | It is the differentiator; the MVP without it is the commodity part of the product |
| Collection modes | Both P0 | **Mode 2 only at MVP** | Which mode is needed depends on the first design partner; mode 2 removes the entire critical-path class (AC-007, IN-002) |

Also changed: shareable verification link demoted to P1, and denominator qualification promoted to a gating procedure rather than an implicit assumption.

---

## 2. MVP definition

One action family, one destination system, end to end, in a live enterprise sales context.

**Done means:** production collection via mode 2; a signed evidence chain; an independently established denominator at class C1 or C2; reconciliation against the destination; a coverage report distinguishing known from unknown; an attestation an external verifier reproduces.

**Explicitly not in MVP:** reference checkpoint (mode 1), outcome proof, Article 72/73 modules, buyer portfolio, auditor workspace, registry, trust mark, multi-region.

---

## 3. Stories

Sizing target: one to five days for a competent agent with review. Anything larger is decomposed.

---

### Foundation

#### EV-01 — Repository scaffold and CI
Monorepo: `services/`, `sdk_python/`, `sdk-typescript/`, `verifier-go/`, `docs/`, `tests/`. Dev environment with ephemeral Postgres. CI running lint, typecheck, and empty test suites on every PR. `develop → staging → main` branch convention with the promotion gate stub.
**Touches:** repo root, `.github/`, `docker-compose.yml`
**Depends on:** —
**Satisfies:** IN-021
**Acceptance:** CI green on an empty PR; `docker compose up` yields a working dev environment.

#### EV-02 — Evidence schema types and canonicalisation (Python)
Typed record models for every type in `evidence-spec.md` §5. RFC 8785 JCS canonicalisation. Digest computation. Envelope validation including unknown-field rules. Typed `clocks` member carrying the ES-019 fields.
**Touches:** `sdk_python/evidence/schema.py`, `canonical.py`
**Depends on:** EV-01
**Satisfies:** ES-001…005, ES-002a, ES-002b, ES-019 (customer-observed record-shape portion — see note)
**Acceptance:** ES-S-008

**Note on ES-002a / ES-002b.** Both were added to `evidence-spec.md` §2 during review of EV-02, which found that the rule they state existed only in the Python implementation. ES-002a requires a conformant canonicalizer to reject rather than serialize non-integer numbers, out-of-range integers, and `NaN`/`Infinity`; ES-002b requires optional members to be encoded by absence rather than explicit `null`. Both bind EV-05 as much as EV-02 — the Go verifier must reach the same conclusions independently, and until it does, ES-S-007 cannot detect a disagreement. **Neither has an acceptance scenario in `evidence-spec.md` §12.** One is not invented here; writing it is a documentation change and belongs to whoever next amends that document.

**Note on ES-019.** The requirement splits across three stories. EV-02 types the customer-observed fields: required `source_time` and optional `authoritative_time`. EV-27 types and authenticates the hosted observation (`ingest_time`, measured `clock_skew_ms`) in a separate issuer-signed receipt. EV-07 creates that receipt at runtime. The previous model placed hosted observations in the customer-signed record, falsely attributing them to the collector and allowing the collector to suppress TM-006 by reporting zero skew; EV-27 corrects that shape before normative vectors freeze it.

#### EV-03 — Signing and chain primitives (Python)
Ed25519 sign/verify. Envelope signature construction. Chain linking via `prev_digest`. Sequence validation. Fork detection. Key continuity assertions.
**Touches:** `sdk_python/evidence/signing.py`, `chain.py`
**Depends on:** EV-02
**Satisfies:** ES-006…008, ES-006a, ES-021…024, ES-021a, ES-024a, SE-008
**Acceptance:** ES-S-001, ES-S-005, ES-S-010…012

#### EV-04 — Conformance vectors
Language-neutral JSON fixtures covering canonicalisation edge cases, digests, signatures, valid and invalid chains, key rotation with and without continuity. Published as normative (ES-029).
**Touches:** `tests/vectors/`
**Depends on:** EV-03, EV-27
**Satisfies:** ES-029, QA-001 (L1)
**Acceptance:** Python implementation passes all vectors.

#### EV-05 — Go verifier: primitives
Independent JCS canonicalisation, digest, signature verification, chain validation. **No shared code with Python** (AC-011). Single static binary.
**Touches:** `verifier-go/`
**Depends on:** EV-04
**Satisfies:** AC-011, QA-004
**Acceptance:** ES-S-007 — both implementations byte-identical on all vectors.

---

### Ledger and ingestion

#### EV-06 — Ledger schema and role permissions
Append-only evidence table per `data-model.md`. Per-tenant partitioning. Application role granted `INSERT`/`SELECT` only. Canonical bytes stored authoritative; parsed projection as rebuildable cache.
**Touches:** `services/ledger/`, `migrations/`, `data-model.md`
**Depends on:** EV-01
**Satisfies:** AC-012…015, SE-011, SE-012
**Acceptance:** AC-S-004, AC-S-006

#### EV-27 — Issuer-signed ingestion receipts
Remove hosted clock observations from the customer-signed record. Define and implement an issuer-signed receipt over the unchanged record digest, hosted `ingest_time`, and measured `clock_skew_ms`; store its authoritative canonical bytes and proof atomically beside the record. Refuse migration of a non-empty unreceipted ledger rather than fabricate historical observations.
**Touches:** `docs/evidence-spec.md`, `docs/data-model.md`, `docs/prd.md`, `sdk_python/evidence/schema.py`, `services/ledger/`, `services/ingestion/receipts.py`, `migrations/`, receipt and schema tests
**Depends on:** EV-03, EV-06
**Satisfies:** ES-019 (hosted receipt shape), ES-030, DM-005, DM-024, TM-006 (tamper resistance)
**Acceptance:** ES-S-013

**AG-011 debt.** EV-05 does not yet exist, so the repository's Go verifier cannot independently reproduce this schema/signature change today. EV-04 MUST publish normative receipt vectors and EV-05 MUST reproduce them independently. This known sequencing gap is recorded rather than represented by a vacuous Go build.

#### EV-07 — Ingestion service
FastAPI. Validate schema, verify signature, check collector registration, check sequence, durable append, acknowledge. **No queue anywhere in this path** (AC-001). Out-of-order arrival reconciled by sequence.
**Touches:** `services/ingestion/`
**Depends on:** EV-03, EV-06, EV-27
**Satisfies:** AC-001, AC-010, IN-003, IN-012, SE-018, ES-019 (runtime portion — see note), ES-020
**Acceptance:** AC-S-001, IN-S-001, IN-S-003, SE-S-006

**Note on ES-019 / ES-020.** EV-27 defines the separate hosted receipt because a collector cannot honestly sign our receipt time or a skew derived from it. EV-07 stamps `ingest_time`, computes `clock_skew_ms = ingest_time - source_time`, signs the receipt without changing the customer bytes, and appends both atomically. `authoritative_time` remains a customer-signed relayed claim and governs reconciliation ordering where present. Where it is absent, EV-16 applies the signed measured skew to numerator eligibility under ES-S-014. A customer record that supplies `ingest_time` or `clock_skew_ms` is rejected by schema validation rather than trusted.

---

### Collection

#### EV-08 — Python SDK: emission and buffering
Public API for emitting each record type. Local signing with client-held keys. Bounded local buffer when ingestion is unreachable. Configurable per-family fail behaviour.
**Touches:** `sdk_python/client/`
**Depends on:** EV-03, EV-07
**Satisfies:** IN-009, IN-010, SE-005, SE-006
**Acceptance:** IN-S-002 (buffer portion)

#### EV-09 — Offline gap markers
Locally signed `CoverageGap` emission requiring no hosted connectivity. Buffer-exhaustion and silence-threshold triggers. Accepted on reconnection with original signature.
**Touches:** `sdk_python/client/gaps.py`, `services/ingestion/`
**Depends on:** EV-08
**Satisfies:** ES-016, IN-011, TM-007
**Acceptance:** ES-S-004, IN-S-002

#### EV-10 — TypeScript SDK
Server-side emission parity with Python. Review-surface instrumentation capturing what was **rendered client-side**, not server-reconstructed.
**Touches:** `sdk-typescript/`
**Depends on:** EV-04
**Satisfies:** ES-013
**Acceptance:** Conformance vectors pass; rendered-evidence digest differs from server reconstruction in the fixture case.

#### EV-11 — Human oversight record *(P0 — the differentiator)*
Full `HumanReview` capture: reviewer identity and authority, evidence shown, options offered, timing, and **`action_state_at_review`**. Effectiveness evaluation that refuses to count review occurring after commitment.
**Touches:** `sdk-typescript/review/`, `sdk_python/evidence/`, `services/computation/oversight.py`
**Depends on:** EV-10
**Satisfies:** ES-013, ES-014
**Acceptance:** ES-S-003

---

### Denominator and reconciliation

#### EV-12 — Boundary and qualification management
CRUD for `AssuranceBoundary` (versioned, immutable, signed) and `QualificationRecord`. Enforce that every declared family carries a qualification ref, and that class cannot be upgraded retroactively.
**Touches:** `services/admin/boundary.py`, `qualification.py`, migrations
**Depends on:** EV-06
**Satisfies:** ES-009, ES-010, CM-003, CM-004, TM-002
**Acceptance:** TM-S-005, CM-S-009

#### EV-13 — Connector interface and first connector
The two-capability interface (`enumerate`, `confirm`, `capabilities`). First concrete connector against the chosen destination system. Must report `pagination_complete` and `result_cap_hit` honestly.
**Touches:** `services/connectors/`
**Depends on:** EV-12
**Satisfies:** AC-008, CM-010, ES-011, ES-012
**Acceptance:** AC-S-003
**Blocked on:** destination system decision.

#### EV-14 — Population service
Scheduled enumeration honouring settlement lag. Emits signed `PopulationRecord`. Refuses to emit a usable denominator on truncation.
**Touches:** `services/computation/population.py`, Celery tasks
**Depends on:** EV-13
**Satisfies:** CM-019, ES-011, ES-012, TM-012
**Acceptance:** ES-S-002

#### EV-15 — Reconciliation engine
Pure function matching evidence to population and confirmations. Closed classification enumeration, no residual bucket. Duplicate and ambiguous handling.
**Touches:** `services/computation/reconciliation.py`
**Depends on:** EV-14
**Satisfies:** AC-002, CM-012, ES-015, TM-010
**Acceptance:** AC-S-002, TM-S-006

#### EV-16 — Coverage engine and admissibility lattice
Applies the lattice: claimed level = min(evidence-supported, class-admissible). Ratio emitted only at C1/C2/C3. Gap conservation. No imputation.
**Touches:** `services/computation/coverage.py`
**Depends on:** EV-15
**Satisfies:** CM-008, CM-009, CM-011, CM-014, AC-005, ES-020, TM-006
**Acceptance:** CM-S-001, CM-S-003, CM-S-004, CM-S-010, QA-S-002, ES-S-014

---

### Attestation

#### EV-17 — Attestation service
Window assembly, assertion selection from the closed catalogue, exclusions, issuer counter-signature, validity. Refuses assertions outside the catalogue and refuses composite scores.
**Touches:** `services/attestation/`
**Depends on:** EV-16
**Satisfies:** AR-003…006, AR-027, AR-028, ES-017, ES-018, SE-002, SE-003
**Acceptance:** AR-S-001, AR-S-002, AR-S-003, AR-S-007, AR-S-008, ES-S-006, SE-S-001

**Note on AR-027 / AR-028 and their scenarios.** Both requirements, and the scenarios AR-S-007 and AR-S-008 that exercise them, were written by EV-25 when it found A-02 and A-09 resting on citations that did not state their claims. They are claimed here rather than there because both are conditions on **assertion selection** — each scenario's `When` is "the attestation is generated", which is this service and nothing earlier. EV-12 supplies the referenced boundary record, but it cannot emit an attestation. Production of outcome proof is explicitly outside the MVP; until matching `OutcomeRecord` evidence exists, EV-17 satisfies AR-028 by withholding A-09 rather than assuming confirmation. A future outcome-evidence producer still will not own the issuance condition. Until EV-17 lands, both scenarios are correctly reported as untested scenarios owned by an unlanded story.

#### EV-18 — Revocation and supersession
Revoke, supersede, expire. Relying-party notification status tracking. Late evidence produces supersession, never amendment. Evidence deletion blocked while a covering attestation is valid.
**Touches:** `services/attestation/lifecycle.py`
**Depends on:** EV-17
**Satisfies:** AR-010…013, CM-020, SE-017
**Acceptance:** AR-S-004, AR-S-005, SE-S-004, CM-S-006

#### EV-19 — Go verifier: full validation
Attestation bundle validation, coverage recomputation, lattice re-checking, qualification-date enforcement, revocation check with honest `unchecked` when offline.
**Touches:** `verifier-go/`
**Depends on:** EV-05, EV-17
**Satisfies:** TM-013, TM-014, AR-009, QA-003
**Acceptance:** TM-S-004, TM-S-005, AR-S-004

---

### Surfaces

#### EV-20 — Admin console
Boundary and qualification management, coverage status, gaps, unmatched records, attestation issuance and lifecycle. Role separation so issuance is not available to engineering roles.
**Touches:** `services/admin/`, `web/admin/`
**Depends on:** EV-18
**Satisfies:** SE-019, SE-020
**Acceptance:** Issuance blocked for a role without the issuance permission.

#### EV-21 — Buyer verification surface *(P1)*
Scoped, time-bound attestation view. Numerator and denominator sources shown, not just a headline. Gaps adjacent to claims. Verifier download.
**Touches:** `web/verify/`
**Depends on:** EV-19
**Satisfies:** SE-021, AR-006

---

### Test infrastructure

#### EV-22 — Traceability matrix generator
Parses requirement IDs, scenario IDs, test IDs, and assertion IDs; generates the four-link matrix; fails CI on orphans at the severity QA-011 currently enforces, and reports every orphan at every stage regardless.
**Touches:** `tests/traceability/`, CI config
**Depends on:** EV-01
**Satisfies:** QA-010…012
**Acceptance:** QA-S-001, QA-S-006, QA-S-007, QA-S-008

#### EV-23 — Adversarial suite
Executable test per attack in `threat-model.md` §4. Readable by someone who does not know the codebase.
**Touches:** `tests/adversarial/`
**Depends on:** EV-16
**Satisfies:** QA-006, QA-007
**Acceptance:** All rows in `testing-qa.md` §5 pass.

#### EV-24 — Golden attestations
Fixed fixtures producing byte-identical bundles. Covers each denominator class, each coverage level, gaps, chain break, superseded, revoked.
**Touches:** `tests/golden/`
**Depends on:** EV-17
**Satisfies:** QA-008, QA-009, AC-009
**Acceptance:** QA-S-003

#### EV-25 — Assertion catalogue basis repair
Two catalogued assertions cited a basis that does not state what they assert. **A-09** ("outcomes confirmed against the named authoritative source") cited CM-007, which is about coverage level and verification status being orthogonal — a different claim. **A-02** ("the declared assurance boundary was in force for the window") cited ES-009, which requires a `qualification_ref` and says nothing about being in force. Repair both citations and document a withholding scenario for each claim; the product demonstrations remain EV-17's work.

**Neither correct basis requirement existed.** The repair was expected to be a re-pointing; it is not one. Every numbered requirement in the corpus was checked, and nothing states that a boundary must span the window it is attested under, nor what entitles an action to be counted as outcome-confirmed. `AssuranceBoundary` carries `window_start`/`window_end` and `OutcomeRecord` carries `authoritative_source`, but a schema field is not a requirement. The nearest statement of A-02's rule was the unnumbered definition of *assurance boundary* in `coverage-methodology.md` §2 — "Claims are valid only inside it" — invisible to the matrix for exactly the reason QA-018 was invisible to it. So this story writes the two rules, AR-027 and AR-028, in `attestation-reliance.md` §2.1, stated as conditions on issuance because that is what they are, and because `evidence-spec.md` and `coverage-methodology.md` are outside this story's Touches and on EV-12's and EV-16's critical path.

**Do not shortcut this.** Re-pointing A-02 at TM-002 clears the traceability gate immediately, because TM-002 already has a scenario. It is substantively wrong: TM-S-002 demonstrates that narrowing a boundary is *visible*, while A-02 claims the boundary was *in force for the whole window*. A boundary can be narrowed visibly and still have been in force throughout, and it can have been silently unamended while the window ran past its validity — so the gate would go green while the assertion still rested on something that does not state the claim. That is AG-002's failure mode — weakening to make it pass — relocated from a scenario to a citation, where no rule forbade it. The same trap exists one row down: CM-010 has CM-S-005, and pointing A-09 there would go green while demonstrating the opposite direction of the claim. This is why the documentation defines two **new** scenarios, AR-S-007 and AR-S-008, one per assertion — each fails if its assertion is emitted without the condition it names. No existing scenario satisfies either, and the boundary-narrowing scenario in `threat-model.md` §11 specifically does not.

**This story writes those scenarios; EV-17 owns them.** Both are attestation-generation scenarios — `When the attestation is generated` — and only EV-17 selects assertions from the catalogue. They are therefore listed under EV-17's `Acceptance:` field, and they will sit as untested scenarios owned by an unlanded story until it merges, which is the classification that exists for this case. They are deliberately **not** listed in the `Acceptance:` field below: that field is parsed for scenario IDs, and a story that names a scenario it cannot discharge acquires ownership of it by accident. Because this story does land, naming them here would convert two honest pieces of roadmap debt into two high-severity defects against a story that never claimed to build an attestation service.

QA-018 is the rule this story exists to satisfy, and it was unnumbered prose in `testing-qa.md` §0 until EV-22's follow-up numbered it. That is the same defect one level up: the tool built to enforce "no assertion without a scenario" could not read the sentence that says it. CM-007 and ES-009 are **not** claimed here — they are the requirements A-02 and A-09 mis-cited, and dropping a wrong citation does not make this story their owner. AR-027 and AR-028 are likewise not claimed here: this story authored them, EV-17 discharges them.
**Touches:** `docs/prd.md`, `docs/attestation-reliance.md`, `docs/testing-qa.md`, `tests/features/`, `tests/steps/`
**Depends on:** EV-22
**Satisfies:** QA-018
**Acceptance:** independent review confirms that both repaired catalogue rows cite requirements stating the same claim, and the generated matrix emits no `ASSERTION_NO_SCENARIO` finding for A-02 or A-09. Product demonstrations remain owned by EV-17. Stated as prose because the two scenarios written here belong to that story.

#### EV-26 — Orphan triage and scenario ownership
Classify every requirement that has no scenario: write one, mark it non-testable with a stated reason, or defer it to a story `prd.md` defines. Assign every scenario to a story through that story's `Acceptance:` field. The marking syntax, the ownership parsing, and the enforcement all already exist (EV-22); this is the judgement work they were built for. At the first generated matrix that was 163 requirements — 82 specification, 52 claimed by a story, 29 process. Three document-level defaults in `agent-working-agreement.md`, `agent-prompts.md` and `dev-environment.md` clear 29 of them.

**Two findings from EV-22 that this story must resolve rather than paper over.** First, `data-model.md` has 14 requirements owned by **no** story and traced by nothing — the whole document is unclaimed, including the DM-001 migration-numbering rule that AG-004 depends on. Markings do not create owners. Second, a large share of the high findings were untested scenarios belonging to stories nobody has built; no amount of triage clears those, only shipping does. That share is no longer pooled with the rest: `SCENARIO_NO_TEST_UNBUILT` is medium roadmap debt against an unlanded owner, `SCENARIO_NO_TEST_LANDED` is a high-severity defect in something already shipped, and `SCENARIO_NO_TEST_UNOWNED` is high because nobody has said which of the two it is. EV-26 clears the third class outright and the first by ownership; only the second is a defect. This is what makes the 1 September high stage enforce completed triage rather than requiring EV-05 through EV-21 to have landed first.

This story does not implement the product scenarios owned by EV-05 through EV-21; those stay visible as unbuilt-story debt until their owners land.
**Touches:** all of `docs/` — including `docs/prd.md`, where the `Acceptance:` fields that record scenario ownership live — plus `tests/features/` and `tests/steps/`
**Depends on:** EV-22, EV-25
**Satisfies:** QA-011
**Acceptance:** QA-S-010

---

## 4. Build order

Critical path: **EV-01 → 02 → 03 → 06 → 27 → 07 → 12 → 13 → 14 → 15 → 16 → 17 → 19**. EV-04 also depends on EV-27 before publishing normative vectors; EV-05 follows EV-04.

Parallelisable once EV-07 lands (disjoint Touches):

| Track | Stories |
|---|---|
| A — collection | EV-08, EV-09 |
| B — review surface | EV-10, EV-11 |
| C — test infra | EV-22 → EV-25 → EV-26; EV-23, EV-24 after their product dependencies |
| D — denominator | EV-12 → EV-16 |

EV-13 is the only story blocked on an external decision. Everything before it can proceed now.

---

## 5. Definition of done

A story is done when: acceptance scenarios pass; the traceability matrix has no orphans at the severity QA-011 currently enforces; the adversarial suite still passes; for anything touching schema, signing, canonicalisation, or coverage, the Go verifier independently reproduces Python output; and an independent review session has reproduced the claims with real commands rather than accepting a self-report.

---

## 6. Open decisions blocking specific stories

| Decision | Blocks | Default if unresolved |
|---|---|---|
| Destination system | EV-13, EV-14 | Build the interface against a mock; defer the concrete connector |
| Deployment profile | EV-06 partitioning, EV-07 topology | P1 hosted, single EU region |
| Key custody default | EV-08 | Client-held |
| Issuing legal entity | EV-17 issuer identity | Blocks first external issuance, not the build |
| Liability cap | EV-17 `liability_ref` | Placeholder; must resolve before external issuance |
