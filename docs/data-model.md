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

**DM-005** — `canonical_bytes` is authoritative for the customer-signed record, and `receipt_canonical_bytes` is authoritative for the issuer-signed hosted receipt. Every parsed column is a projection and must be rebuildable from the signed bytes of the attestor that observed it (AC-015). A migration that changes a projection column does not touch either authoritative byte string.

"Every parsed column" is the whole list, not the droppable subset. Columns split three ways: **droppable** ones are dropped and rebuilt outright; **repairable** ones are recomputed in place, because no identity or uniqueness guarantee hangs off them; and **verified-only** ones — the record identity, the partition key, and the fork-detection key `(stream_id, sequence)` — are checked but never rewritten, because rewriting them would relocate rows between partitions or silently resolve a fork that ES-006 says must be reported. Review found the earlier implementation verifying eight of sixteen derived columns, which let a `source_time` edited away from the bytes go undetected and survive a rebuild. `ingest_time` and `clock_skew_ms` are deliberately not derived from customer `canonical_bytes`: they reproduce from `receipt_canonical_bytes`, signed by the service that observed and computed them (ES-019, ES-030). `key_id` and `signature` live in the customer signature member that `canonical_bytes` excludes (ES-021); `receipt_key_id` and `receipt_signature` likewise authenticate but are not members of the receipt payload they sign.

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
| `collector_id` | text FK null | Required for `evidence`; forbidden for `issuer` |
| `namespace` | enum | `evidence` \| `issuer` — structurally distinct (SE-003) |
| `public_key` | bytea | |
| `custody` | enum | `client_held` \| `hosted_kms` |
| `valid_from` | timestamptz | |
| `valid_until` | timestamptz null | |
| `continuity_signature` | bytea null | New key signed by predecessor (SE-008) |
| `predecessor_key_id` | text null | |
| `compromised_from` | timestamptz null | SE-009 |

**DM-008** — A key in namespace `issuer` may never sign an evidence record; a key in namespace `evidence` may never counter-sign an attestation. Enforced by a check at ingestion and at issuance, tested by SE-S-001.

For SE-018, every `evidence` key is bound to exactly one registered collector by the composite foreign key `(tenant_id, collector_id)`; an `issuer` key is bound to none. Key rotation may create multiple evidence keys for one collector, but one evidence key cannot authenticate two collector identities. The database refuses both an unbound evidence key and an issuer key carrying a collector binding. Ingestion requires the record's declared `source.collector_id` to equal the signing key's binding.

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

#### §2.4 amendment 1 — as built by migration 0012 (EV-12)

**DM-026 — `superseded_by` is not built, because it cannot be.** Writing it means `UPDATE`ing the row being superseded, which is the single operation an immutable table exists to refuse (TM-002). A column that only ever holds `NULL` is worse than no column: it reads as a supported field and invites a later story to make it work.

Supersession is derived from the version ordering instead. Version *n* is superseded by *n+1* where one exists, and `boundary_versions` in `services/admin/boundary.py` returns the ordered history. This is strictly stronger than the pointer would have been — there is no state in which it is stale, and TM-002's requirement that the change history be *visible* is satisfied by a list of immutable rows rather than by a mutable field pointing between them.

**DM-027 — the signature is bound to a key.** Two columns are added, `key_id` and `key_namespace`, referencing `keys(tenant_id, key_id, namespace)` by the same composite form migration 0010 uses on `evidence_records`, with `key_namespace` CHECK-pinned to `evidence`. §2.4 as originally written carried a `signature` with nothing identifying what verifies it, which makes the signature decorative: a boundary is what every other record's scope claim rests on, and an unverifiable one is a scope declaration asserted by nobody in particular. The namespace pin is DM-008 — an issuer key may not sign customer evidence.

**DM-028 — `created_at` is replaced by `recorded_at`, and it is a hosted observation.** AR-027 floors a boundary version's effective interval at the later of its declared `window_start` and the time the hosted service observed it being recorded, so that a boundary written after the fact cannot be backdated into force. `created_at` with a `now()` default reads as a database convenience; `recorded_at` is a value the issuance rule depends on, is supplied by the service rather than by the signer, and is never read from the signed body — the same separation ES-019 makes between `source_time` and `ingest_time`, for the same reason.

> **Open, and not resolved here.** AR-027 names this value "its signed envelope `clocks.ingest_time`". ES-019 forbids `ingest_time` from appearing in a customer-signed record and puts it in the ES-030 issuer-signed receipt. `recorded_at` is therefore a hosted observation stored beside the boundary but *not* itself under an issuer signature, because ES-030 receipts are defined for `evidence_records` and extending them to `boundaries` is EV-27's machinery, not this story's. Until that is done, a party who does not trust the vendor cannot independently check `recorded_at`, which weakens AR-027 by exactly that much. Recorded so it is not discovered late.

**DM-029 — `boundary_ref`'s format is a CHECK, not a convention.** `boundary_ref = tenant_id || ':' || name || ':' || version::text`, with `name` restricted to an alphabet excluding `:`. A ref parsed anywhere in the system therefore decomposes to the row it names, and a row cannot claim a ref inside another tenant's namespace. `evidence_records` references `(tenant_id, boundary_ref)` compositely for DM-016's reason.

### 2.4.1 `boundary_action_families`

Added by migration 0012. One row per `action_families[]` entry of one boundary version — a projection of the signed body, rebuildable from it, and immutable on the same trigger as its parent.

| Column | Type | Notes |
|---|---|---|
| `tenant_id` | text | |
| `boundary_ref` | text | Composite FK to `boundaries(tenant_id, boundary_ref)` |
| `action_family` | text | |
| `qualification_ref` | text **not null** | ES-009 |
| `destination_system` | text | CM-003 — the declared denominator source |
| `fail_behaviour` | text | `fail_closed` \| `fail_open` |

Primary key `(tenant_id, boundary_ref, action_family)`.

**DM-030 — ES-009 is a `NOT NULL`, not a validation.** "A boundary declaring a family without qualification is invalid" is a statement about which rows may exist, so it is enforced as one. A family with no `qualification_ref` has no row it could occupy.

The foreign key to `qualification_records` is on **four** columns — `(tenant_id, qualification_ref, action_family, destination_system)` — rather than on the ref alone. A qualification record earns a class for one *(family, destination system)* pair; a single-column reference would let a boundary attach a record that qualified `ticket.resolve` as the qualification for `refund.issue`, producing a well-formed boundary declaring a class nothing ever assessed it at. That is the well-formed-but-false declaration ES-009 and CM-003 exist to prevent, and it is not something an application check would reliably catch.

A boundary with *no* family rows at all is refused by a deferred constraint trigger. The `NOT NULL` above does not reach that case, which is the same defect one step further along: a scope declaration under which every family is undeclared, and which evidence may nonetheless cite through `boundary_ref`.

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

#### §2.5 amendment 1 — as built by migration 0012 (EV-12)

**DM-031 — the whole row is immutable, not only `assigned_class`.** DM-009 names one column; the trigger refuses `UPDATE` and `DELETE` on all of them. Every column except `canonical_bytes` is a projection of the signed record, so an edit to any of them puts the row into a state the signature does not cover — and a trigger holding a case that permits `UPDATE` leaves `assigned_class` one predicate away from being editable. `canonical_bytes` and `key_id`/`key_namespace` are added on the same reasoning as DM-027.

**DM-032 — DM-009's second sentence is enforced at write time, by the database.** A `BEFORE INSERT` trigger refuses a record whose class is *stronger* than an existing record for the same `(tenant_id, action_family, destination_system)` triple and whose `qualified_at` is not strictly later than it. Without this, the ES-010 attack is not amending a record — it is inserting a new, perfectly valid one dated behind the weaker one, so that a resolver taking "the latest record before the window" finds the stronger class and believes it was in force throughout.

The guard is deliberately **directional**. A record assigning a *weaker* class may be dated at any point, because CM-004 permits a mid-window downgrade and a downgrade can only reduce what may be claimed. Attestations already issued over the affected windows are invalidated by it; handling that is supersession (AR-011, EV-18), not something a trigger can do.

`UNIQUE (tenant_id, action_family, destination_system, qualified_at)` accompanies it. Two records for one triple at one instant leave "the class in force at T" with no answer, and the tie would be broken by insertion order — which is to say, by whichever the vendor wrote second.

**DM-033 — the §4 and §6 qualifying constraints are CHECKs.** Each is a numbered requirement that caps a class, so each is a row the database will not hold:

| Constraint | Requirement |
|---|---|
| No `identity_isolation_attribute` ⇒ class is `c5` | CM-006 |
| `c1`/`c2` require an attribute the vendor cannot set per request | CM-005 |
| `c1`/`c2`/`c3` require `enumeration_capable` | CM-009 — a ratio-emitting class needs an enumerable population |

Nothing constrains `confirmation_capable` against `enumeration_capable`, and that is AC-008 rather than an omission: a record carrying confirmation without enumeration is valid, useful for per-action reconciliation, and capped below the ratio-emitting classes by the third row above. The window-level refusal is the coverage engine's (EV-16) and is not represented here.

**DM-034 — three guards, and the third is not in this repository's Python.** The rule DM-009 states is enforced at write time by DM-032's trigger, at read time by `class_in_force` in `services/admin/qualification.py`, and at verification time by the Go verifier (TM-013: "verifier enforces this independently"). The first two run on our infrastructure under our credentials, so a relying party has no reason to trust either; only the third is reproducible by someone who does not trust us. The verifier half is unbuilt — `verifier-go/` is EV-05's and EV-19's — and TM-S-005 is not closed until it lands.

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
| `record_key_namespace` | key_namespace | Fixed to `evidence`; part of the key FK |
| `signature` | bytea | |
| `source_time` | timestamptz | |
| `ingest_time` | timestamptz | |
| `authoritative_time` | timestamptz null | Governs where present (ES-020) |
| `clock_skew_ms` | integer | |
| `canonical_bytes` | bytea | **Authoritative** |
| `received_wire_bytes` | bytea | Exact accepted canonical wire record, including `signature`; receipt-bound |
| `receipt_key_id` | text FK | Issuer-namespace key used for ES-030 |
| `receipt_key_namespace` | key_namespace | Fixed to `issuer`; part of the receipt-key FK |
| `receipt_signature` | bytea | Raw Ed25519 signature over `receipt_canonical_bytes` |
| `receipt_canonical_bytes` | bytea | **Authoritative hosted receipt** |
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

**DM-023** — `canonical_bytes` holds the JCS-canonical record **excluding** the `signature` field: the exact bytes that were signed (ES-021). The signature itself is decomposed into the `signature` and `key_id` columns. Ingestion first proves that `received_wire_bytes` equals the canonical form of the complete parsed record; a difference is refused as `wire.non_canonical`. It then verifies against, and stores, the signature-excluded canonical bytes. It never accepts a non-canonical request by re-rendering it into a different authoritative artifact — precisely the divergence `ES-S-007` exists to catch.

The consequence is a reassembly step: an export bundle must carry the **full** record including `signature`, so EV-19 needs a defined, tested reconstruction from `canonical_bytes` + `signature` + `key_id` back to the wire form. Not built here; recorded so it is not discovered late.

**DM-024** — `receipt_canonical_bytes` holds the exact ES-030 payload bytes signed by the hosted issuer key. Its `record_digest` binds `received_wire_bytes`, the complete accepted wire record including its `signature` member; it is not the signature-excluded `record_digest` column governed by DM-023. `ingest_time` and `clock_skew_ms` are projections of the receipt bytes and MUST reproduce from them; they MUST NOT reproduce from, or be accepted from, customer `canonical_bytes`. The customer-key FK includes a discriminator fixed to namespace `evidence`, and the receipt-key FK includes one fixed to `issuer`; either cross-namespace use is rejected by the database. `receipt_signature` is the raw 64-byte Ed25519 proof. Record and receipt columns are inserted together, so append-only grants make an unreceipted accepted record and a receipt attached after acknowledgment equally inexpressible. Migration 0010 refuses to apply to a non-empty ledger rather than fabricate issuer observations for historical rows.

### 2.6.1 `ingestion_integrity_events`

Append-only and partitioned by `tenant_id`, with the same tenant role holding only `INSERT` and `SELECT` on its own partition. Replays are reported but not retained as integrity events; forks and content substitutions are retained after the rejected evidence transaction rolls back.

| Column | Type | Notes |
|---|---|---|
| `event_id` | uuid | Returned to the tenant with the refusal |
| `tenant_id` | text | Partition key |
| `event_type` | text | `stream_fork` or `content_substitution` |
| `record_id` | uuid | Submitted identity |
| `conflicting_record_id` | uuid null | Previously accepted identity |
| `stream_id` / `sequence` | text / bigint | Submitted stream position |
| `submitted_wire_bytes` | bytea | Exact rejected canonical artifact |
| `existing_wire_bytes` | bytea null | Exact accepted artifact |
| `occurred_at` | timestamptz | Detection time |
| `surfaced_to_tenant_at` | timestamptz | Same synchronous response boundary |

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
| 0003 | — | *void* — was EV-12's pre-allocation; see §3 amendment 1 | void, never written |
| 0004 | — | *void* — was EV-14's pre-allocation (population records) | void, never written |
| 0005 | — | *void* — was EV-15's pre-allocation (reconciliation results) | void, never written |
| 0006 | — | *void* — was EV-09's pre-allocation (coverage gaps) | void, never written |
| 0007 | — | *void* — was EV-17's pre-allocation (attestations) | void, never written |
| 0008 | — | *void* — was EV-18's pre-allocation (revocations) | void, never written |
| 0009 | — | *void* — was EV-20's pre-allocation (admin audit log) | void, never written |
| 0010 | EV-27 | Signed ingestion receipts and receipt-derived clock metadata | applied |
| 0011 | EV-07 | Collector-key binding, exact received wire retention, tenant-visible ingestion integrity events | applied |
| 0012 | EV-12 | Boundaries, qualification records, `evidence_records.boundary_ref` FK | claimed |

### §3 amendment 1 — register reconciliation (EV-12)

The register above had drifted from the database. Two corrections, and one new
rule so the drift does not recur.

**What was wrong.** 0010 and 0011 were recorded as `claimed` when both are
applied — `alembic upgrade head` on a base database runs 0001, 0002, 0010,
0011 and stops. And 0003 through 0009 were pre-allocated by story rather than
by order of arrival, so the register asserted a chain that Alembic could not
build: 0011 is the current head, and EV-12 writing "0003" would have to declare
`down_revision = "0011"`, leaving a revision whose number says it precedes 0010
and whose chain says it follows 0011. A migration number that disagrees with
the chain it sits in is worse than no number, because the register is the one
place a reviewer looks to reconstruct apply order without reading every file.

**DM-025** — Migration numbers are allocated **in order of claim, above the
current chain head**, not reserved per story in advance. A story claiming a
number takes the next integer after the highest number in this table, whatever
its own story ID, and its `down_revision` is the previous row. Pre-allocation
was the source of the collision above: a reserved number is claimed at planning
time and written at implementation time, and nothing keeps those two orders the
same. The unwritten reservations 0003–0009 are therefore voided rather than
renumbered; the stories that held them (EV-14, EV-15, EV-09, EV-17, EV-18,
EV-20) claim fresh numbers here when they are ready to write. Voided numbers
are never reused, so a database or a review comment naming "0003" is
unambiguous about referring to something that was never applied.

> **Non-testable — process.** DM-025 governs how an agent allocates a number
> before writing a migration, which happens in a commit rather than at
> runtime. The property a test could assert — that the applied chain is
> contiguous and ordered — is a consequence of the rule, not the rule, and
> Alembic already refuses a chain that is neither.

**Consequence for DM-017.** DM-017 states that the `evidence_records.boundary_ref`
foreign key is "deferred to migration 0003, because `boundaries` is created by
EV-12". The reasoning stands unchanged and the deferral is discharged as
described; only the number moves. Read DM-017 as naming **0012**.

---

## 4. Retention and deletion

**DM-012** — Evidence within the window of a valid attestation cannot be deleted. Deletion requires prior revocation (SE-017), and the check runs in the deletion path, not as a scheduled sweep.

**DM-013** — Derived tables (`reconciliation_results`, projections) may be dropped and rebuilt freely. Evidence, population records, gaps, attestations, and revocations may not.

**DM-014** — Retention floor: attestation validity plus the dispute window, with 12 months recommended as the configurable default (IN-009 note).
