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
Typed record models for every type in `evidence-spec.md` §5. RFC 8785 JCS canonicalisation. Digest computation. Envelope validation including unknown-field rules.
**Touches:** `sdk_python/evidence/schema.py`, `canonical.py`
**Depends on:** EV-01
**Satisfies:** ES-001…005
**Acceptance:** ES-S-008

#### EV-03 — Signing and chain primitives (Python)
Ed25519 sign/verify. Envelope signature construction. Chain linking via `prev_digest`. Sequence validation. Fork detection. Key continuity assertions.
**Touches:** `sdk_python/evidence/signing.py`, `chain.py`
**Depends on:** EV-02
**Satisfies:** ES-006…008, ES-021…024, SE-008
**Acceptance:** ES-S-001, ES-S-005

#### EV-04 — Conformance vectors
Language-neutral JSON fixtures covering canonicalisation edge cases, digests, signatures, valid and invalid chains, key rotation with and without continuity. Published as normative (ES-029).
**Touches:** `tests/vectors/`
**Depends on:** EV-03
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

#### EV-07 — Ingestion service
FastAPI. Validate schema, verify signature, check collector registration, check sequence, durable append, acknowledge. **No queue anywhere in this path** (AC-001). Out-of-order arrival reconciled by sequence.
**Touches:** `services/ingestion/`
**Depends on:** EV-03, EV-06
**Satisfies:** AC-001, AC-010, IN-003, IN-012, SE-018
**Acceptance:** AC-S-001, IN-S-001, IN-S-003, SE-S-006

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
**Satisfies:** CM-008, CM-009, CM-011, CM-014, AC-005
**Acceptance:** CM-S-001, CM-S-003, CM-S-004, CM-S-010, QA-S-002

---

### Attestation

#### EV-17 — Attestation service
Window assembly, assertion selection from the closed catalogue, exclusions, issuer counter-signature, validity. Refuses assertions outside the catalogue and refuses composite scores.
**Touches:** `services/attestation/`
**Depends on:** EV-16
**Satisfies:** AR-003…006, ES-017, ES-018, SE-002, SE-003
**Acceptance:** AR-S-001, AR-S-002, AR-S-003, ES-S-006, SE-S-001

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
Parses requirement IDs, scenario IDs, test IDs, and assertion IDs; generates the four-link matrix; fails CI on any orphan.
**Touches:** `tests/traceability/`, CI config
**Depends on:** EV-01
**Satisfies:** QA-010…012
**Acceptance:** QA-S-001

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

---

## 4. Build order

Critical path: **EV-01 → 02 → 03 → 04 → 05 → 06 → 07 → 12 → 13 → 14 → 15 → 16 → 17 → 19**.

Parallelisable once EV-07 lands (disjoint Touches):

| Track | Stories |
|---|---|
| A — collection | EV-08, EV-09 |
| B — review surface | EV-10, EV-11 |
| C — test infra | EV-22, EV-23, EV-24 |
| D — denominator | EV-12 → EV-16 |

EV-13 is the only story blocked on an external decision. Everything before it can proceed now.

---

## 5. Definition of done

A story is done when: acceptance scenarios pass; the traceability matrix has no orphans; the adversarial suite still passes; for anything touching schema, signing, canonicalisation, or coverage, the Go verifier independently reproduces Python output; and an independent review session has reproduced the claims with real commands rather than accepting a self-report.

---

## 6. Open decisions blocking specific stories

| Decision | Blocks | Default if unresolved |
|---|---|---|
| Destination system | EV-13, EV-14 | Build the interface against a mock; defer the concrete connector |
| Deployment profile | EV-06 partitioning, EV-07 topology | P1 hosted, single EU region |
| Key custody default | EV-08 | Client-held |
| Issuing legal entity | EV-17 issuer identity | Blocks first external issuance, not the build |
| Liability cap | EV-17 `liability_ref` | Placeholder; must resolve before external issuance |
