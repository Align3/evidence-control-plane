# Architecture

**Version:** 0.1 draft
**Repo location:** `docs/architecture.md`
**Depends on:** `coverage-methodology.md`, `evidence-spec.md`, `threat-model.md`
**Drives:** `api.md`, `security.md`, `infrastructure.md`, `reconciliation.md`

---

## 0. Parameterisation

Written against the denominator taxonomy rather than a specific destination system. Action family and destination are parameters throughout; deployment model is a variable with three profiles (§8). One worked example — `refund.issue` against a payments system, class C1 — is threaded through for readability. It is illustrative, not a commitment.

Requirements carry IDs `AR` is taken; architecture uses `AC-nnn`.

---

## 1. Principles

**AC-001 — Evidence ingestion never passes through a queue.** If a record is acknowledged, it is already durably appended. Queue-then-write produces an acknowledgment not backed by durability, which is the silent-evidence-loss failure that retroactively invalidates attestations.

**AC-002 — Computation is pure.** Reconciliation, coverage, and attestation generation are pure functions of (ledger, qualification record, boundary). They never mutate the ledger. This makes them replayable, cacheable, and testable, and it is what CM-013 requires.

**AC-003 — The evidence specification is the only abstraction boundary that matters.** Collection modes are producers behind it; verification and attestation are consumers of it. Internal interfaces are free to change; the spec is not.

**AC-004 — The checkpoint and the ledger are separate services.** The checkpoint is in the critical path and must be small, fast, and boring. The ledger is not in the critical path and can be slower and more durable. Collapsing them is what makes the latency target painful.

**AC-005 — The denominator is not abstracted.** Per `coverage-methodology.md` §3, connectors carry the denominator *result* and its class; they never manufacture it generically.

---

## 2. Component model

| Component | Responsibility | Critical path? |
|---|---|---|
| **SDK** (Python, TypeScript) | Emit spec-conformant records; local signing; offline gap markers; buffering | Client-side |
| **Reference checkpoint** | Authorisation decision + evidence emission before action | **Yes** (mode 1 only) |
| **Collector gateway** | Authenticate and normalise third-party enforcement records | No |
| **Ingestion** | Validate, verify signatures, durable append, sequence check | Yes (write path) |
| **Evidence ledger** | Append-only signed record storage, per-tenant | No |
| **Population service** | Execute enumeration against destination; emit `PopulationRecord` | No |
| **Reconciliation engine** | Match evidence to population and confirmations; classify | No |
| **Coverage engine** | Apply admissibility lattice; compute levels and counts | No |
| **Attestation service** | Assemble, assert, counter-sign, expire, revoke, supersede | No |
| **Verifier** | Independent validation. **Separate binary, separate language** | No |
| **Admin API + console** | Boundary and qualification management, monitoring, issuance | No |
| **Buyer verification surface** | Scoped attestation viewing and verifier download | No |

---

## 3. Collection modes as producers

Both modes terminate in identical spec-conformant records. The ledger does not know or care which produced a record beyond the `source` field.

**Mode 2 — third-party enforcement reconciliation (MVP default).** An existing gateway or internal enforcement point emits authenticated logs; the collector gateway normalises them; the population service enumerates the destination independently. No critical path, no latency budget, no in-line availability exposure.

**Mode 1 — reference checkpoint.** The agent requests authorisation before acting; the checkpoint returns a signed decision. Higher assurance on routing, at the cost of being in the critical path.

**Mode 3 — observation-only.** Records emitted beside the execution path. Permitted for onboarding and non-consequential families; **AC-006** — MUST be labelled lower assurance and MUST NOT contribute to an enforced coverage claim.

**AC-007** — Adding mode 1 after mode 1 ships is an additional producer, not a rewrite. Any design that would require ledger or computation changes to accommodate a new mode is a violation of AC-003.

---

## 4. Connector interface — two capabilities

The correction that matters most from the methodology work. A connector has **two independent capabilities**, and possessing one does not imply the other.

```
interface DestinationConnector:

    # Capability 1 — ENUMERATION (produces the denominator)
    enumerate(scope, window) -> PopulationRecord
        MUST report pagination_complete and result_cap_hit
        MUST NOT silently truncate
        MAY be unavailable -> denominator class degrades

    # Capability 2 — CONFIRMATION (verifies one action)
    confirm(action_ref) -> ExternalConfirmation
        MUST return an authoritative timestamp where the system provides one
        MUST classify into the closed enumeration (ES-015)

    # Metadata
    capabilities() -> {enumeration: bool, confirmation: bool,
                       authoritative_time: bool, settlement_lag: duration}
```

**AC-008** — A connector implementing `confirm` without `enumerate` supports per-action reconciliation but MUST NOT support a window-level coverage claim (CM-010). The type system should make this hard to get wrong; the coverage engine MUST enforce it regardless.

---

## 5. Data flow

1. Agent or gateway produces `ActionProposal`, `AuthorityDecision`, `ExecutionReceipt` — signed client-side, appended synchronously.
2. `HumanReview` emitted from the review surface, capturing what was rendered and the action state at review.
3. Population service enumerates the destination for the window after the declared settlement lag; emits `PopulationRecord`.
4. Connector retrieves `ExternalConfirmation` per action.
5. Reconciliation engine matches and classifies. Pure function.
6. Coverage engine applies the lattice. Pure function.
7. Attestation service assembles, asserts from the catalogue, counter-signs.
8. Relying party verifies offline; checks revocation online.

**AC-009** — Steps 3–7 are idempotent and replayable. Re-running against an unchanged ledger produces byte-identical output (the golden-attestation property in `testing-qa.md`).

---

## 6. Stack

| Layer | Choice | Rationale |
|---|---|---|
| API / services | **FastAPI (Python 3.12+)** | Existing operational familiarity; async; the latency budget is dominated by durable append, not by the runtime |
| Datastore | **PostgreSQL**, self-hosted | Append-only evidence table; hash chain does the integrity work, not the storage engine |
| Background | **Celery + Redis** | Enumeration runs, reconciliation, coverage, attestation generation, alerting — all derived computation |
| Signing | **Ed25519** via `cryptography` | Fast, small signatures, no parameter choices to get wrong |
| Canonicalisation | **RFC 8785 JCS** | Language-neutral; the spec depends on it |
| **Verifier** | **Go, single static binary** | Auditors download and run it. Cross-language implementation also proves the spec is independently implementable rather than encoding Python's serialization quirks |

**AC-010** — Celery MUST NOT appear anywhere in the evidence write path (AC-001). It is for derived computation only.

**AC-011** — The verifier MUST NOT share code with the writer. Shared code would defeat the cross-implementation conformance property that makes ES-S-007 meaningful.

---

## 7. Ledger design

**AC-012** — Evidence table is append-only: no `UPDATE`, no `DELETE`. Enforced by database role permissions, not application convention.

**AC-013** — Chain integrity is verified at read time by the verifier, not trusted from write time. A ledger that only checks on write cannot detect post-hoc storage tampering.

**AC-014** — Per-tenant partitioning with a separate signing key namespace. Cross-tenant reads are structurally impossible at the query layer, not filtered at the application layer.

**AC-015** — Records are stored as canonical bytes plus a parsed projection for querying. The canonical bytes are authoritative; the projection is a cache and MUST be rebuildable from them.

---

## 8. Deployment profiles

The one place abstraction genuinely leaks — key custody and network topology differ materially, so these are three profiles sharing a core, not one system with a config flag.

| | **P1 — Hosted SaaS** | **P2 — Customer VPC** | **P3 — Sidecar / on-prem** |
|---|---|---|---|
| Ledger location | Ours | Customer's cloud | Customer's infra |
| Signing keys | Customer-held, hosted KMS option | Customer-held | Customer-held |
| Population queries | Our egress to destination | Customer egress | Customer egress |
| We can read evidence | Yes | No (attestation metadata only) | No |
| Verification | Same verifier, all profiles | | |
| EU residency | Region selection | Native | Native |
| MVP support | **Yes** | V1 | V2 |

**AC-016** — The attestation format is identical across profiles. A relying party MUST NOT need to know the deployment profile to verify — though the profile IS recorded, because it affects the withholding analysis in `threat-model.md` §4.12.

> **Input needed.** P1 is the MVP recommendation on build cost. But EU-market positioning and the sovereignty argument point at P2 earlier than V1, and P2 materially weakens the "we can withhold" residual risk — under P2 we structurally cannot. If the first design partner is European, promoting P2 may be worth the cost.

---

## 9. What is pluggable, what is not

**Pluggable behind stable interfaces:** collection mode, destination connector, action family definition, policy engine reference, storage backend, notification transport.

**Not pluggable, deliberately:**

- **The denominator** (AC-005). Derived and argued per family in the methodology.
- **Canonicalisation and signing.** An abstraction over serialization is how two implementations end up disagreeing by a byte.
- **The admissibility lattice.** Configuration here would let a customer configure themselves a stronger claim.
- **The assertion catalogue.** Closed set (AR-003).

---

## 10. Acceptance criteria

### AC-S-001 — No queue in the write path *(AC-001, AC-010)*

```gherkin
Given a record submitted to ingestion
When ingestion acknowledges it
Then the record is durably committed to the ledger
And no acknowledgment occurs before commit
```

### AC-S-002 — Computation purity *(AC-002)*

```gherkin
Given a ledger state L
When reconciliation and coverage run
Then the ledger state is unchanged
And a second run produces identical output
```

### AC-S-003 — Confirmation-only connector blocks coverage *(AC-008)*

```gherkin
Given a connector reporting capabilities {enumeration: false, confirmation: true}
When a window-level coverage claim is requested
Then the coverage engine refuses
And per-action reconciliation results remain available
```

### AC-S-004 — Ledger immutability enforced at the database *(AC-012)*

```gherkin
Given the application database role
When an UPDATE or DELETE is attempted on the evidence table
Then the database rejects it
And the rejection is not dependent on application-layer checks
```

### AC-S-005 — Mode addition requires no core change *(AC-007)*

```gherkin
Given a running system in mode 2
When a mode 1 checkpoint producer is added
Then no ledger schema change is required
And no coverage engine change is required
```

### AC-S-006 — Projection rebuildable from canonical bytes *(AC-015)*

```gherkin
Given a populated evidence ledger
When the parsed projection is dropped and rebuilt
Then every record reproduces identically
And all digests and signatures still verify
```
