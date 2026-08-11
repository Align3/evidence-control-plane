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
Remove hosted clock observations from the customer-signed record. Define and implement an issuer-signed receipt over the complete received wire record, including its customer signature, plus hosted `ingest_time` and measured `clock_skew_ms`; store its authoritative canonical bytes and proof atomically beside the record. Refuse migration of a non-empty unreceipted ledger rather than fabricate historical observations.
**Touches:** `docs/evidence-spec.md`, `docs/data-model.md`, `docs/prd.md`, `sdk_python/evidence/schema.py`, `services/ledger/`, `services/ingestion/receipts.py`, `migrations/`, `tests/vectors/`, receipt and schema tests

**Scope change — `tests/vectors/` added after EV-04 merged.** EV-04 published 41 vectors carrying `ingest_time` and `clock_skew_ms` inside the customer-signed record. ES-029 makes those vectors normative and authoritative over prose, so the amended ES-019 here contradicts a published artefact until they are regenerated. The story that changes the shape owns everything the shape governs: regenerating inside EV-27 means `develop` is never in a state where the specification and its normative vectors disagree, which splitting into a follow-up would guarantee for the interval between two merges.

**Scoped review exception — `services/ledger/schema.py`.** The SE-003 repair changes migration 0010's customer-key and receipt-key foreign keys to include fixed `evidence` and `issuer` namespace discriminators. The runtime table declaration and its previously false namespace comment must change with the migration so application inserts and schema-drift checks describe the enforced database shape. This exception is limited to those discriminator columns and comment.
**Depends on:** EV-03, EV-06
**Satisfies:** ES-019 (hosted receipt shape), ES-030, DM-005, DM-024, TM-006 (tamper resistance)
**Acceptance:** ES-S-013

**AG-011 debt.** EV-05 does not yet exist, so the repository's Go verifier cannot independently reproduce this schema/signature change today. EV-04 MUST publish normative receipt vectors and EV-05 MUST reproduce them independently. This known sequencing gap is recorded rather than represented by a vacuous Go build.

#### EV-07 — Ingestion service
FastAPI. Validate schema, verify signature, check collector registration, check sequence, durable append, acknowledge. **No queue anywhere in this path** (AC-001). Out-of-order arrival reconciled by sequence.
**Touches:** `services/ingestion/`, `services/ledger/schema.py`, `services/ledger/tenancy.py`, `sdk_python/evidence/signing.py`, `migrations/`, `docs/evidence-spec.md`, `docs/data-model.md`, `tests/vectors/`, ingestion and ledger tests
**Depends on:** EV-03, EV-06, EV-27
**Satisfies:** AC-001, AC-010, IN-003, IN-012, SE-018, ES-001, ES-006, ES-019 (runtime portion — see note), ES-020
**Acceptance:** AC-S-001, IN-S-001, IN-S-003, SE-S-006

**Note on ES-019 / ES-020.** EV-27 defines the separate hosted receipt because a collector cannot honestly sign our receipt time or a skew derived from it. EV-07 stamps `ingest_time`, computes `clock_skew_ms = ingest_time - source_time`, signs the receipt without changing the customer bytes, and appends both atomically. `authoritative_time` remains a customer-signed relayed claim and governs reconciliation ordering where present. Where it is absent, EV-16 applies the signed measured skew to numerator eligibility under ES-S-014. A customer record that supplies `ingest_time` or `clock_skew_ms` is rejected by schema validation rather than trusted.

**Review scope additions.** F3 required EV-07 to consume EV-27's namespaced verification API rather than duplicate its SQL policy, so the shared signing entry point and ledger runtime schema are explicit Touches exceptions. F4 makes non-canonical received wire a distinct refusal and adds the normative ES-029 vector. F5 persists rejected forks and content substitutions in a tenant-visible append-only operational table, with distinct response codes for fork, replay, and substitution. No evidence record type is added; whether the operational event should later become signed evidence remains a separate specification question.

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
**Satisfies:** ES-009, ES-010, CM-003, CM-004
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

#### EV-28 — Report every determinable failure at a chain break
Where several integrity failures are independently determinable at one stream position, report all of them in chain-traversal order rather than letting the first suppress the rest. A re-signed predecessor both breaks the link (ES-006a) and presents an unauthenticated key change (ES-024); reporting one makes the answer depend on a verifier's internal check order rather than on the evidence, so two conformant verifiers describe one attack differently.

**This is a behavioural change and everything moves together or not at all.** EV-05 drafted the Go half, wrote it into the specification, and withdrew all of it: the specification said one thing, the corpus recorded a single code per refusal, Python reported one, and Go reported two. The only way to keep the Go behaviour was to loosen the conformance harness to compare just the primary code — a verifier tolerating divergence from a normative result, which is the failure the corpus exists to prevent. Land the requirement, both implementations, the corpus expectation and the scenario in one change, or leave the rule unstated.

`reject-validly-resigned-predecessor` already exercises the case; what is missing is that its `expected` records only `chain.prev_digest_mismatch`. The primary code does not move, so no existing expectation is invalidated — but changing a stored vector is a normative corpus change reviewed by its byte diff (`tests/vectors/README.md`).
**Touches:** `docs/evidence-spec.md`, `sdk_python/evidence/chain.py`, `verifier-go/`, `tests/vectors/`, `tests/steps/`
**Depends on:** EV-05
**Satisfies:** — (introduces the requirement it implements)
**Acceptance:** a scenario demonstrating that both failures are reported, passing on both implementations, with the corpus recording the full result.

#### EV-29 — Scenario linkage for tests that are not pytest nodes
The traceability matrix links scenarios to tests only through pytest node ids collected under `testpaths = ["tests"]`. No Go test can discharge a scenario however completely it demonstrates one, so a Go-side demonstration is invisible to the four-link chain QA-010 publishes.

At EV-05 this cost one shim: a pytest step that shells out to the compiled binary so ES-S-007 could be seen. **At EV-19 it is structural.** Attestation bundle validation, coverage recomputation, lattice re-checking and revocation-status reporting are all Go-side, and every scenario demonstrating them faces the same choice — be reported as untested against a landed story, or acquire a Python shim written for no reason except to make the matrix see it. Shims that exist to satisfy a measuring tool are how a traceability matrix stops describing the system and starts describing itself.

Extend the collector to attribute scenario tags from non-pytest suites, or define a machine-readable result format that any suite emits and the matrix consumes. Either way the linkage must be earned by a test that actually ran; a declaration file asserting coverage without executing anything would be worse than the current gap, because it would look complete.
**Touches:** `tests/traceability/`, CI config
**Depends on:** EV-22, EV-05
**Satisfies:** QA-010
**Acceptance:** a Go test demonstrating a scenario links to it in the generated matrix, and a scenario whose Go test fails is not reported as demonstrated.

#### EV-30 — Close Python composition-path false acceptances and publish adversarial vectors
EV-05's review identified two invalid subjects that the shipping Python entry
points accepted at branch base `9e5904b`. Go already refused both when given a
truthful registered keyring:

* `verify_canonical_evidence_record` accepted an `AttestationWindow` whose
  issuer counter-signature had been deleted. The Python record entry point did
  not dispatch on `record_type`, so ES-023's second signature was checked only
  by callers that separately invoked the stricter primitive.
* Python's `verify_stream` and `verify_streams` took bare public keys with no
  namespace, so an issuer key could authenticate a customer evidence stream.
  Go's `VerifyEvidenceStream` already required registered namespaces.

The earlier cross-implementation harness did not expose the divergence because
it synthesized the evidence namespace for every namespace-free stream key. Add
a namespace-aware Python stream entry point, make record verification dispatch
on `record_type`, and publish the two refusal vectors with every trust input and
the measured per-implementation pre-fix result stated in the corpus.

This is the shipping evidence path, so it is a story rather than a patch tacked onto a verifier PR.

**Two decisions EV-05 made that Python must match, or the vectors cannot be written.** First, the Go stream entry point refuses a rotation onto a key the keyring does not list, even though the ES-024a continuity assertion authenticates it: the assertion establishes *which* key succeeds the old one, and cannot establish the successor's namespace, which is a custody fact only the keyring states. Second, Go's record path now refuses a `record_type` outside §5 and a body missing the members §5 defines for its type, which is what stops an `AttestationWindow` body from being presented as some other type with the ES-023 counter-signature dropped. Python already enforces the type dispatch through its typed models; it does not yet enforce the rotation rule. Go checks only that the mandatory body members are present — member *values* remain validated by Python's models alone, so a record Python's writer would refuse can still pass the Go verifier, and neither implementation should be described as validating §5 bodies without that qualification.
**Touches:** `sdk_python/evidence/chain.py`, `services/ingestion/receipts.py`, `tests/vectors/`
**Depends on:** EV-05
**Satisfies:** ES-023, SE-003
**Acceptance:** both vectors require refusal and pass on both implementations;
each records results measured against `9e5904b`, at least one shipping entry
point accepted the subject before the fix, and no harness supplies an unstated
namespace or other trust-decision input.

#### EV-31 — Receipts for constitutive records
Extend the ES-030 receipt mechanism to `AssuranceBoundary` and `QualificationRecord` (ES-032). Issuer-signed receipt, committed in the same transaction as the record, recorded time read from the receipt rather than from anything the signer supplied. Migration adds the receipt columns to `boundaries` and `qualification_records` on the shape migration 0010 established, and `services/admin/` writes both halves in one statement.

**Why this is not deferrable to EV-17.** EV-12 stores a boundary's recording time as a hosted observation with no issuer signature over it (DM-028). AR-027 floors a boundary version's effective interval at that value precisely so a boundary cannot be backdated into force — so an unsigned recording time means A-02 rests on trusting the issuer not to have moved it, which is the one thing an attestation cannot ask a relying party to take on trust. EV-17 consumes AR-027's arithmetic; if this has not landed by then, EV-17 inherits the weakness silently and nothing in the attestation says so.

Small: the mechanism, the payload shape, and the key namespacing all exist. What is new is two more call sites and a migration.
**Touches:** `services/admin/`, `services/ingestion/receipts.py`, migrations, `docs/data-model.md`
**Depends on:** EV-12, EV-27
**Satisfies:** ES-032
**Acceptance:** ES-S-017
**Sequenced before:** EV-17.

#### EV-32 — Constitutive-record envelope rule
Implement ES-031 as the `2.0.0` envelope: `boundary_ref` is present on an `AssuranceBoundary`, where it is self-referential and cross-checked against the signed body, and absent from a `QualificationRecord`. Absent, not null. Every other record type in §5 continues to require it.

The rule is written; what is unbuilt is the version-dispatching validator. `RecordEnvelope.boundary_ref` in `sdk_python/evidence/schema.py` is unconditionally required today, so a conformant schema-2 `QualificationRecord` under ES-031 is currently rejected by our own schema — EV-12 works around this by supplying a plausible value that nothing resolves, which is exactly the state a closed enumeration exists to end. Both Python and Go must retain the schema-1 rule and validate historical `1.0.0` records without rewriting them; this is a major-version change under ES-028, not a reinterpretation of the existing wire version.

Touches the envelope, so per §7 of the working agreement this is an architectural decision and not an implementation detail. ES-005 continues to reject any member not in the version-and-type-specific envelope. The negative vector set covers every governed §5 type rather than one representative, because a dispatcher that special-cases that representative would otherwise pass while leaving the closed enumeration open.
**Touches:** `sdk_python/evidence/schema.py`, `services/admin/`, `verifier-go/`, `tests/vectors/`
**Depends on:** EV-02, EV-05, EV-12
**Satisfies:** ES-031
**Acceptance:** ES-S-015, ES-S-016, ES-S-018

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
