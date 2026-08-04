# Data Model

**Version:** 0.1 draft
**Repo location:** `docs/data-model.md`
**Depends on:** `evidence-spec.md`, `architecture.md`, `security.md`

---

## 0. Purpose and amendment convention

This is the shared contract between concurrently working agents. On DamDam, a real numbering collision occurred when two agents amended this file simultaneously — so:

**DM-001** — Migration numbers are allocated by editing this file **first**, in a commit that touches nothing else. An agent that needs migration `0007` claims it here before writing it.

**DM-002** — Section amendments are numbered (`§4.1 amendment 1`) rather than rewritten in place, so concurrent edits conflict visibly instead of silently overwriting.

**DM-003** — Two stories may run concurrently only if their table sets are disjoint. The Touches field in `prd.md` is authoritative; this file is the reference for what each table means.

---

## 1. Design rules

**DM-004** — The `evidence_records` table is append-only. The application role holds `INSERT` and `SELECT` only; `UPDATE` and `DELETE` are granted to no application role (AC-012, SE-012).

**DM-005** — `canonical_bytes` is authoritative. Every parsed column is a projection and must be rebuildable from it (AC-015). A migration that changes a projection column does not touch `canonical_bytes`.

"Every parsed column" is the whole list, not the droppable subset. Columns split three ways: **droppable** ones are dropped and rebuilt outright; **repairable** ones are recomputed in place, because no identity or uniqueness guarantee hangs off them; and **verified-only** ones — the record identity, the partition key, and the fork-detection key `(stream_id, sequence)` — are checked but never rewritten, because rewriting them would relocate rows between partitions or silently resolve a fork that ES-006 says must be reported. Review found the earlier implementation verifying eight of sixteen derived columns, which let a `source_time` edited away from the bytes go undetected and survive a rebuild. `ingest_time` is deliberately not derived — it records our receipt, not anything the writer signed — as are `key_id` and `signature`, which live in the signature member `canonical_bytes` excludes (ES-021).

**DM-006** — Cross-tenant reads must be inexpressible at the query layer, not filtered in application code (SE-011). Two mechanisms, because two access patterns:

| Tables | Mechanism | Why |
|---|---|---|
| `evidence_records` | Per-tenant `LIST` partitioning; no role holds any privilege on the parent | Evidence is always read in a tenant's context, so partitioning costs the query nothing and buys the strongest statement available: the other tenant's rows sit in a relation the role cannot name |
| `tenants`, `collectors`, `keys` | Row-level security policy scoped to `current_user` | The registry is read **by id** — ingestion resolves a collector from the `collector_id` on an incoming record (SE-018). Partitioning would require knowing the tenant before it could name the relation that tells it the tenant |

Neither is a `WHERE` clause in application code, which is what SE-011 forbids. Application-layer filtering is defeated by any code path that forgets it, and there is always one.

#### §1 amendment 1 — registry isolation (EV-06)

**DM-022** — Row-level security on the registry tables was added after review of EV-06 found that a `SELECT` grant on `tenants` alone let any tenant role enumerate every customer, and `collectors` exposed other customers' deployment topology. `keys` holds public keys and so carries little confidentiality weight, but is covered for consistency: a registry table without a policy invites the question of which others lack one.

Policies are `ENABLE`, not `FORCE`, so the owner bypasses them. That is what keeps provisioning and cross-tenant administration possible through the separately-credentialed path (SE-012 §6); those operations are logged and surfaced to the affected tenant under SE-013.

The policy predicate names the role directly — `current_user = 'evidence_tenant_' || tenant_id` — rather than reading a session variable. A session variable is settable by the session, which would make the isolation advisory.

**DM-007** — No `ON DELETE CASCADE` anywhere touching evidence. Deletion of evidence is blocked while a covering attestation is valid (SE-017), and cascades make that invariant unenforceable.

---

## 2. Tables

### 2.1 `tenants`

| Column | Type | Notes |
|---|---|---|
| `tenant_id` | text PK | |
| `name` | text | |
| `deployment_profile` | enum | `p1_hosted` \| `p2_vpc` \| `p3_sidecar` (SE-025) |
| `key_custody` | enum | `client_held` \| `hosted_kms` (SE-006) |
| `evidence_region` | text | IN-015 |
| `created_at` | timestamptz | |

### 2.2 `collectors`

Registered collection sources. Records from unregistered collectors are rejected (SE-018).

| Column | Type | Notes |
|---|---|---|
| `collector_id` | text PK | |
| `tenant_id` | text FK | |
| `implementation` | text | e.g. `sdk-python`, `gateway-adapter` |
| `version` | text | |
| `mode` | enum | `checkpoint` \| `third_party` \| `observation_only` |
| `expected_cadence_s` | integer | Silence past this opens a provisional gap (IN-018) |
| `registered_at` | timestamptz | |
| `revoked_at` | timestamptz null | |

### 2.3 `keys`

| Column | Type | Notes |
|---|---|---|
| `key_id` | text PK | |
| `tenant_id` | text FK | |
| `namespace` | enum | `evidence` \| `issuer` — structurally distinct (SE-003) |
| `public_key` | bytea | |
| `custody` | enum | `client_held` \| `hosted_kms` |
| `valid_from` | timestamptz | |
| `valid_until` | timestamptz null | |
| `continuity_signature` | bytea null | New key signed by predecessor (SE-008) |
| `predecessor_key_id` | text null | |
| `compromised_from` | timestamptz null | SE-009 |

**DM-008** — A key in namespace `issuer` may never sign an evidence record; a key in namespace `evidence` may never counter-sign an attestation. Enforced by a check at ingestion and at issuance, tested by SE-S-001.

### 2.4 `boundaries`

Immutable and versioned. Changes create rows; they never update.

| Column | Type | Notes |
|---|---|---|
| `boundary_ref` | text PK | `{tenant}:{name}:{version}` |
| `tenant_id` | text FK | |
| `name` | text | |
| `version` | integer | |
| `body` | jsonb | Full signed boundary per ES §5.1 |
| `canonical_bytes` | bytea | |
| `signature` | bytea | |
| `created_at` | timestamptz | |
| `superseded_by` | text null | |

Unique on `(tenant_id, name, version)`.

### 2.5 `qualification_records`

| Column | Type | Notes |
|---|---|---|
| `qualification_ref` | text PK | |
| `tenant_id` | text FK | |
| `action_family` | text | |
| `destination_system` | text | |
| `assigned_class` | enum | `c1`…`c5` |
| `enumeration_capable` | boolean | |
| `confirmation_capable` | boolean | AC-008 — independent of the above |
| `identity_isolation_attribute` | text null | |
| `identity_vendor_settable` | boolean | |
| `authoritative_time_available` | boolean | |
| `settlement_lag_s` | integer | CM-019 |
| `source_retention_days` | integer | |
| `deletion_traceless_possible` | boolean | TM-005 |
| `body` | jsonb | Full record per ES §5.2 |
| `qualified_at` | timestamptz | |
| `revalidate_after` | timestamptz | |
| `signature` | bytea | |

**DM-009** — No `UPDATE` on `assigned_class`. A stronger class requires a new row with a later `qualified_at`, applying only to windows beginning after it (ES-010, CM-004).

### 2.6 `evidence_records` — the core table

Partitioned by `tenant_id`. Append-only.

| Column | Type | Notes |
|---|---|---|
| `record_id` | uuid PK | UUIDv7 |
| `tenant_id` | text | Partition key |
| `record_type` | text | ES §5 |
| `schema_version` | text | |
| `boundary_ref` | text FK | |
| `stream_id` | text | |
| `sequence` | bigint | Monotonic within stream |
| `prev_digest` | bytea null | |
| `record_digest` | bytea | |
| `collector_id` | text FK | |
| `key_id` | text FK | |
| `signature` | bytea | |
| `source_time` | timestamptz | |
| `ingest_time` | timestamptz | |
| `authoritative_time` | timestamptz null | Governs where present (ES-020) |
| `clock_skew_ms` | integer | |
| `canonical_bytes` | bytea | **Authoritative** |
| `body` | jsonb | Projection — rebuildable |
| `action_id` | uuid null | Projection for join performance |
| `action_family` | text null | Projection |

Unique on `(tenant_id, stream_id, sequence)` — this constraint is what makes fork detection (ES-006) a database guarantee rather than application logic.

Indexes: `(tenant_id, action_id)`, `(tenant_id, action_family, source_time)`, `(tenant_id, record_type, ingest_time)`.

#### §2.6 amendment 1 — as built by migration 0002 (EV-06)

**DM-015** — The primary key is `(tenant_id, record_id)`, not `record_id` alone. Postgres requires the partition key in every unique constraint on a partitioned table, and `evidence-spec.md` §3 specifies `record_id` as unique *within tenant* — so this is the correct key rather than a concession to the partitioning.

**DM-016** — `collector_id` and `key_id` are **composite** foreign keys on `(tenant_id, collector_id)` and `(tenant_id, key_id)`. A single-column reference would let a record attribute itself to another tenant's collector or key, which SE-011 forbids and which no application check would reliably catch.

**DM-017** — `boundary_ref` is created as a plain `NOT NULL` column by migration 0002. The foreign key to `boundaries` is deferred to migration 0003, because `boundaries` is created by EV-12 and building it early would cross that story's table set (DM-003). The reference becomes enforceable when 0003 lands; until then `boundary_ref` is unvalidated.

**DM-018** — Partitions are created by `provision_tenant`, one per tenant, and there is **no DEFAULT partition**. Evidence naming an unprovisioned tenant is rejected outright rather than pooled into a shared relation that no tenant role could safely be granted.

**DM-019** — Grants. No role holds any privilege on the parent `evidence_records`; naming it is how a cross-tenant read would be spelled, so it must fail before a predicate is evaluated (SE-011). Each tenant has a role `evidence_tenant_{tenant_id}` holding `INSERT` and `SELECT` on its own partition and nothing else.

Each tenant role is itself a **login** role with its own credential, and is granted to nobody. An application session authenticates *as* the tenant rather than authenticating as a shared login and then assuming the tenant with `SET ROLE`.

The distinction is not stylistic. Membership in a role cannot be scoped to a connection: a login that may assume two tenants may assume the second at any point in any statement that reaches the database on that connection — including a statement introduced by SQL injection, which is precisely the query-layer crossing SE-011 requires be impossible rather than merely unused. Review of the shared-login design demonstrated it: a single stacked driver call moved an Acme session to Globex and read its evidence. With no membership to exercise, the server refuses the switch instead of the application being trusted not to attempt it.

The trust boundary remains the application process, which holds the secret each tenant password is derived from and can therefore open a connection as any tenant. What it cannot do is cross tenants *on a connection it already holds*. `evidence_app` is retained as a login that is a member of nothing and holds nothing, so that "an authenticated session with no tenant credential reaches nothing" is a property the suite asserts rather than one that follows from an absent role.

**DM-020** — `tenant_id` is constrained by CHECK to `^[a-z0-9]([a-z0-9_]{0,44}[a-z0-9])?$`. The tenant id reaches SQL identifiers in `CREATE TABLE ... PARTITION OF` and `CREATE ROLE`, neither of which accepts a bind parameter; restricting it to characters that are already a legal identifier makes the tenant → partition-name mapping injective, so two tenants can never derive one partition.

The **length** bound carries as much of that guarantee as the alphabet does, and for a less obvious reason. Postgres truncates an identifier longer than `NAMEDATALEN - 1` (63 bytes) **silently** — no error, no warning. Injectivity therefore has to hold on the truncated name, not on the string the application computed. The longest prefix in use is `evidence_records_` at 17 bytes, so a tenant id may be at most 46. At the original bound of 48, `evidence_records_` + `tenant_id` was 65 bytes and `evidence_tenant_` + `tenant_id` was 64: two tenant ids agreeing on their first 47 characters truncated to **one partition and one role**, and either tenant's ordinary session could read the other's evidence. Any future prefix must be counted against the same 63-byte budget; `services/ledger/naming.py` derives the bound rather than restating it, and raises if a derived identifier would not fit.

**DM-023** — `canonical_bytes` holds the JCS-canonical record **excluding** the `signature` field: the exact bytes that were signed (ES-021). The signature itself is decomposed into the `signature` and `key_id` columns. Storing what was signed, verbatim, means verification never re-canonicalises — and re-canonicalisation is precisely where two independent implementations diverge, which is what makes `ES-S-007` achievable at EV-05.

The consequence is a reassembly step: an export bundle must carry the **full** record including `signature`, so EV-19 needs a defined, tested reconstruction from `canonical_bytes` + `signature` + `key_id` back to the wire form. Not built here; recorded so it is not discovered late.

**DM-021** — Writing the projection requires `UPDATE`, which SE-012 grants to no application role. Projection rebuild (`services/ledger/projection.py`) therefore runs under the migrator credential and is unreachable from any service handling traffic. This is the design and not a workaround: a rebuild path the ingestion role could execute would mean that role held `UPDATE`, and AC-012 would be false.

### 2.7 `population_records`

The denominator. Distinct table because CM-002 forbids conflating population with denominator.

| Column | Type | Notes |
|---|---|---|
| `population_ref` | text PK | |
| `tenant_id` | text FK | |
| `action_family` | text | |
| `destination_system` | text | |
| `window_start` | timestamptz | |
| `window_end` | timestamptz | |
| `enumeration_query` | jsonb | As executed |
| `identifier_digest` | bytea | Digest over the identifier set |
| `identifiers` | jsonb null | Inline for small populations |
| `count` | integer | |
| `pagination_complete` | boolean | |
| `result_cap_hit` | boolean | |
| `retrieved_at` | timestamptz | |
| `signature` | bytea | |

**DM-010** — `result_cap_hit` or `NOT pagination_complete` must force `coverage_ratio` to null downstream (ES-011/012). Enforced in the coverage engine and asserted by ES-S-002.

### 2.8 `reconciliation_results`

Derived and rebuildable. Not evidence.

| Column | Type | Notes |
|---|---|---|
| `id` | bigserial PK | |
| `tenant_id` | text | |
| `population_ref` | text FK | |
| `action_id` | uuid null | Null where a population record has no matching evidence |
| `destination_record_id` | text null | |
| `status` | enum | Closed set (ES-015) — no default, no residual |
| `computed_at` | timestamptz | |
| `computation_version` | text | |

**DM-011** — This table may be truncated and rebuilt from evidence at any time (AC-002). If a rebuild produces different results from identical inputs, that is a defect.

### 2.9 `coverage_gaps`

| Column | Type | Notes |
|---|---|---|
| `gap_id` | uuid PK | |
| `tenant_id` | text | |
| `evidence_record_id` | uuid null | Present when signed by an SDK (ES-016) |
| `gap_start` | timestamptz | |
| `gap_end` | timestamptz null | Null while provisional/open |
| `cause` | enum | ES §5.12 |
| `affected_scope` | jsonb | |
| `detection_source` | text | |
| `provisional` | boolean | Opened by silence detection (IN-018) |
| `actions_during_gap` | integer null | |

### 2.10 `attestations`

| Column | Type | Notes |
|---|---|---|
| `attestation_id` | uuid PK | |
| `tenant_id` | text FK | |
| `boundary_ref` | text FK | |
| `window_start` / `window_end` | timestamptz | |
| `methodology_version` | text | |
| `denominator_class` | enum | |
| `coverage_level` | enum | |
| `capped_by_class` | boolean | ES-018 |
| `verification_status` | enum | `self_computed` \| `independently_reproduced` (CM-007) |
| `coverage_ratio` | numeric null | **Explicit null at C4/C5** (ES-017) |
| `counts` | jsonb | |
| `assertions` | jsonb | Catalogue IDs only (AR-003) |
| `exclusions` | jsonb | |
| `relying_parties` | jsonb | |
| `purpose` | text | AR-008 |
| `validity_from` / `validity_until` | timestamptz | |
| `liability_ref` | text | |
| `issuer_key_id` | text FK | Namespace must be `issuer` |
| `signature` | bytea | |
| `bundle_digest` | bytea | Golden-attestation comparison (QA-008) |
| `issued_at` | timestamptz | |

### 2.11 `revocations`

| Column | Type | Notes |
|---|---|---|
| `revocation_id` | uuid PK | |
| `attestation_id` | uuid FK | |
| `reason` | text | |
| `effective_at` | timestamptz | |
| `superseding_attestation_id` | uuid null | |
| `notified_at` | timestamptz null | AR-012 |
| `notification_status` | enum | |

### 2.12 `admin_audit_log`

| Column | Type | Notes |
|---|---|---|
| `id` | bigserial PK | |
| `operator_identity` | text | |
| `operation` | text | |
| `tenant_id` | text null | |
| `justification` | text | |
| `surfaced_to_tenant_at` | timestamptz null | SE-013 |
| `occurred_at` | timestamptz | |

---

## 3. Migration register

Claim a number here before writing the migration (DM-001).

| # | Story | Description | Status |
|---|---|---|---|
| 0001 | EV-06 | Tenants, collectors, keys; registry row-level security (DM-022) | applied |
| 0002 | EV-06 | `evidence_records` + partitioning + role grants | applied |
| 0003 | EV-12 | Boundaries, qualification records | unclaimed |
| 0004 | EV-14 | Population records | unclaimed |
| 0005 | EV-15 | Reconciliation results | unclaimed |
| 0006 | EV-09 | Coverage gaps | unclaimed |
| 0007 | EV-17 | Attestations | unclaimed |
| 0008 | EV-18 | Revocations | unclaimed |
| 0009 | EV-20 | Admin audit log | unclaimed |
| 0010 | EV-27 | Signed ingestion receipts and receipt-derived clock metadata | claimed |

---

## 4. Retention and deletion

**DM-012** — Evidence within the window of a valid attestation cannot be deleted. Deletion requires prior revocation (SE-017), and the check runs in the deletion path, not as a scheduled sweep.

**DM-013** — Derived tables (`reconciliation_results`, projections) may be dropped and rebuilt freely. Evidence, population records, gaps, attestations, and revocations may not.

**DM-014** — Retention floor: attestation validity plus the dispute window, with 12 months recommended as the configurable default (IN-009 note).
