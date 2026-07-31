# Infrastructure and Operations

**Version:** 0.1 draft
**Repo location:** `docs/infrastructure.md`
**Depends on:** `architecture.md`, `security.md`, `threat-model.md`

---

## 0. The one way this differs from a normal application

Evidence loss is **retroactively catastrophic**. Losing a week of application logs is an inconvenience. Losing a week of evidence invalidates every attestation covering that window, requires revocation notices to relying parties, and is the kind of incident that gets discussed by the auditors you were trying to recruit.

So the durability target is not derived from availability reasoning. It is derived from: *what is the maximum evidence loss that does not force a revocation?* The answer is zero, and everything below follows from it.

Requirements carry IDs `IN-nnn`.

---

## 1. SLOs, split by criticality

Collapsing these into one number is what makes the latency target look impossible.

| Service | Availability | Latency | Consequence of breach |
|---|---|---|---|
| **Reference checkpoint** (mode 1 only) | 99.9% MVP, 99.95% V1 | p95 < 100ms added, p99 < 250ms | Customer's agent blocked (fail-closed) or coverage gap (fail-open) |
| **Ingestion** (write path) | 99.9% | p95 < 200ms to durable ack | SDK buffers; gap only if buffer exhausts |
| **Ledger read** | 99.5% | p95 < 500ms | Attestation generation delayed |
| **Computation** (reconciliation, coverage) | Best effort | Batch, minutes | Attestation delayed, never wrong |
| **Attestation issuance** | 99.5% | seconds | Procurement delayed |
| **Verification / revocation endpoint** | **99.95%** | p95 < 300ms | **Relying party cannot verify — highest-visibility failure** |

**IN-001** — The revocation endpoint carries the highest availability target in the system. A relying party who cannot check revocation is told `unchecked`, not `valid` (TM-014), which correctly makes our outage their blocker. That asymmetry is intentional and must be engineered for.

**IN-002** — Mode 2 has no critical path. Shipping mode 2 first removes the entire checkpoint latency and availability class from the MVP, which is a substantial reason to prefer it.

---

## 2. Evidence durability

**IN-003** — Durable append before acknowledgment. No acknowledgment is returned until the record is committed and fsynced. Documented in the SDK contract so the customer knows exactly what "recorded" means.

**IN-004** — RPO for evidence: **zero**. Synchronous replication to a second node before ack, or WAL-based commit guarantees equivalent to it.

**IN-005** — RTO: 4 hours for ingestion (during which SDKs buffer), 1 hour for the verification endpoint.

**IN-006** — Continuous WAL archiving to object storage, following the DamDam WAL-G pattern. **IN-007** — A destructive point-in-time restore test MUST be executed and its output recorded before the first production deployment, and quarterly thereafter. A backup that has never been restored is not a backup.

**IN-008** — Chain integrity MUST be re-verified after any restore, using the independent verifier, before the system accepts new writes. A restore that silently truncates a chain is worse than an outage.

---

## 3. Fail-open runtime

The design principle is in `coverage-methodology.md` CM-015; this is what it demands of infrastructure.

**IN-009** — Fail behaviour is configured **per action family**, not globally, and cannot be changed retroactively without an audit record.

**IN-010** — The SDK MUST buffer locally when ingestion is unreachable, with a configured bound. Buffered records retain their original signatures and timestamps.

**IN-011** — When the buffer bound is reached, or when the SDK cannot reach ingestion for longer than a configured threshold, it MUST emit a **locally signed** `CoverageGap` record. This is the integrity mechanism, not a convenience: if gap emission depended on our availability, our outage would erase the evidence of our outage.

**IN-012** — On reconnection, buffered records and gap markers are submitted with original signatures intact. Ingestion MUST accept out-of-order arrival and reconcile by sequence, not by receipt order.

**IN-013** — Fail-closed is available per family for high-risk actions. The operational trade-off — our outage becomes the customer's outage — MUST be stated explicitly at configuration time, not buried in documentation.

---

## 4. Regions and residency

**IN-014** — EU region is the default deployment for the hosted profile, given the relying-party population and the market positioning. A US region follows when a customer requires it, not before.

**IN-015** — Evidence never leaves its configured region. Cross-region operations are limited to attestation metadata and revocation status.

**IN-016** — The destination connector's egress originates in the evidence region under P1, and in the customer's environment under P2/P3.

---

## 5. Monitoring

Instrument the things that would make an attestation wrong, not just the things that would page an engineer.

**IN-017** — Alert on: sequence gaps, signature verification failures, collector silence beyond expected cadence, enumeration truncation (`result_cap_hit`), settlement lag exceeding the declared value, clock skew beyond threshold, unmatched-record rate deviation, and buffer-bound approach on any SDK instance.

**IN-018** — Collector silence is a first-class alert. An agent that stops reporting looks identical to an agent that stopped acting, and the difference is the entire product. Expected cadence is declared per collector; silence past it opens a provisional gap.

**IN-019** — PostHog for product and error telemetry (consistent with DamDam); Uptime Kuma for external endpoint monitoring including the revocation endpoint from outside our own infrastructure.

**IN-020** — Our own operational telemetry MUST NOT enter the evidence ledger. Mixing operational logging with evidence is how the schema rots.

---

## 6. Environments

| Environment | Purpose | Evidence |
|---|---|---|
| `dev` | Local; test vectors and fixtures | Synthetic only |
| `staging` | Full pipeline; conformance suite; restore drills | Synthetic + partner sandbox |
| `production` | Live | Real |

**IN-021** — Following the DamDam convention: `develop → staging → main`, with promotion to `main` gated by a signoff artifact enforced in CI.

**IN-022** — The promotion gate for this product additionally requires: conformance vectors passing in both implementations, a successful chain-verification run over staging evidence, and — for any release touching the evidence schema, signing, or coverage computation — a recorded independent verifier reproduction.

---

## 7. Runbooks required before production

Named here so they are not discovered during an incident.

1. Suspected key compromise → revoke, notify, re-issue boundary
2. Chain break detected in production → contain, terminate window, notify affected relying parties
3. Enumeration truncation discovered after issuance → supersede
4. Destination connector credential expiry → gap handling and backfill
5. Restore from backup → chain re-verification before accepting writes
6. Attestation issued in error → revocation and relying-party notification
7. Collector silence → distinguish agent stopped from collector stopped
8. Settlement lag exceeded → window issuance hold

**IN-023** — Runbooks 1, 2, and 6 MUST exist before the first attestation is issued to an external relying party. The others before general availability.

---

## 8. Acceptance criteria

### IN-S-001 — No ack before durable commit *(IN-003)*

```gherkin
Given ingestion receives a valid record
When the process is killed immediately after acknowledgment
Then the record is present after restart
And the chain verifies without a gap at that position
```

### IN-S-002 — Offline gap emission on buffer exhaustion *(IN-011)*

```gherkin
Given ingestion is unreachable
And the SDK local buffer reaches its configured bound
When further actions occur
Then a locally signed CoverageGap is emitted
And it is accepted on reconnection with its original signature
```

### IN-S-003 — Out-of-order reconnection reconciles by sequence *(IN-012)*

```gherkin
Given buffered records for sequences 10 through 20
When they are submitted in arbitrary order after reconnection
Then the ledger reconstructs the chain by sequence
And no gap is reported
```

### IN-S-004 — Restore re-verifies before accepting writes *(IN-008)*

```gherkin
Given a point-in-time restore has completed
When the system starts
Then chain verification runs across restored evidence
And writes are refused until verification succeeds
```

### IN-S-005 — Collector silence opens a provisional gap *(IN-018)*

```gherkin
Given a collector with declared cadence of 60 seconds
When no record is received for 300 seconds
Then an alert fires
And a provisional CoverageGap is opened for the silent interval
And it is closed only by evidence or by an explanation record
```

### IN-S-006 — Revocation endpoint availability under partial outage *(IN-001)*

```gherkin
Given ingestion and computation are degraded
When a relying party queries revocation status
Then the endpoint responds within SLO
And the response is authoritative
```

---

## 9. Input needed

| Question | Recommendation |
|---|---|
| Cloud provider | OCI is familiar from DamDam and the free tier is generous; but EU-region availability and enterprise-buyer perception favour AWS or a European provider (Scaleway, OVH, Hetzner) for a product sold on sovereignty. **Worth a deliberate decision rather than defaulting** |
| Evidence retention floor | Recommend attestation validity + 12 months, configurable upward |
| SDK buffer bound default | Recommend 10,000 records or 1 hour, whichever first; needs a real workload to tune |
| Multi-region at MVP | No. Single EU region; revocation endpoint is the exception and should be geo-redundant from day one |
