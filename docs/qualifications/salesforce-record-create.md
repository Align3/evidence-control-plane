# Qualification Record — Salesforce `record.create`

**Repo location (suggested):** `docs/qualifications/salesforce-record-create.md`
**Status:** Draft, hand-authored from a real Phase B trial. Not yet a signed
`QualificationRecord` instance per `evidence-spec.md` §5.2 — this is the
source data the Salesforce connector story should emit as one, once real
API auth exists. Treat this file as the spec for that emission, not a
substitute for it.

---

## Scope

| Field | Value |
|---|---|
| `action_family` | `record.create` |
| `destination_system` | Salesforce (Developer Edition; production orgs may differ — see Open Items) |
| `deployment` | Standalone Case object, no managed package customisation |
| `qualified_at` | 2026-08-18 |
| `revalidation_cadence` | `PT1H`, plus an uncached preflight before every enumeration/attestation window |

---

## 1. Enumeration

| Field | Value |
|---|---|
| API | SOQL via standard REST query endpoint |
| Scoping parameters | `WHERE CreatedDate >= :start AND CreatedDate <= :end` |
| Ordering guarantee | None by default — must specify `ORDER BY` explicitly (Phase A finding, not re-tested in trial since the trial window was small enough not to need it) |
| Pagination | Query locator / `nextRecordsUrl`; batch size 200–2000, configurable via `Sforce-Query-Options` header |
| Result cap | 2000/batch documented; **not exercised** — trial window was 20 records, well under cap |
| Truncation signalling | `totalSize` / `done` fields present; trial returned exactly 20/20 with no truncation indicator firing |

**Trial evidence:** `SELECT Id, Subject, CreatedById, CreatedDate FROM Case WHERE CreatedDate = TODAY` returned exactly 20 rows against a known-created population of 20 (10 agent-authored, 10 human-authored), zero more, zero fewer.

---

## 2. Identity isolation (CM-005)

| Field | Value |
|---|---|
| Attribute | `CreatedById` |
| Vendor-settable | **Conditionally true** |
| Condition | Only when the acting user holds the `PermissionsCreateAuditFields` permission ("Set Audit Fields upon Record Creation") |

**Trial evidence — the decisive finding of this probe:**

- Isolation without the permission granted: exact. `WHERE CreatedById = :agent_id` returned exactly the 10 agent-authored records, zero bleed either direction.
- With the permission granted, a forged record (`CreatedById`, `LastModifiedById`, `OwnerId` all set to the agent's Id on insert) was **indistinguishable from a genuine agent record** on every field in `FIELDS(STANDARD)`. Setting `CreatedById` alone left `OwnerId`/`LastModifiedById` pointing at the actual inserting user — a real but fragile tell, defeated once all three fields are set deliberately.
- **The mitigating fact:** `PermissionsCreateAuditFields` is itself queryable with no elevated access —
  ```sql
  SELECT AssigneeId, Assignee.Name, PermissionSet.Name
  FROM PermissionSetAssignment
  WHERE PermissionSet.PermissionsCreateAuditFields = true
  ```
  confirmed working against the live trial org, correctly returning the one user holding the grant.

**Consequence for CM-005/CM-006:** the isolation attribute is forgeable, but the forgery *capability* is monitorable. This is not the unconditional pass Phase A hoped for, and it is not a fallback to C3 — it's C1 with a standing precondition: **the integration user must not hold `PermissionsCreateAuditFields`, checked at qualification and re-checked on a cadence.**

---

## 3. Confirmation

| Field | Value |
|---|---|
| API | SOQL retrieve by `Id` — same endpoint family as enumeration |
| Permission required | Standard object read access; nothing beyond enumeration |
| Independent of enumeration? | **No.** The connector reports confirmation as supported with `confirmation_access = shared_with_enumeration`; enumeration and confirmation share one API surface and credential and differ only in query shape. |

---

## 4. Temporal

| Field | Value |
|---|---|
| Authoritative timestamp | `CreatedDate`, server-set |
| Measured settlement lag | **~0s** — standard object, synchronously written, not eventually consistent. A single-record insert (`LAG-TEST`) was queryable immediately after insert with no observed delay. |
| Caveat | This was observed via query timing, not re-confirmed with an explicit logged row count on that specific run — treat as high-confidence, not independently re-verified twice |

---

## 5. Retention and mutability

| Field | Value |
|---|---|
| Record retention | No fixed documented expiry — governed by org data storage allocation |
| Deletion possible | **Yes** — confirmed |
| Trace available on deletion | **Yes** — confirmed. Deleted record invisible to a normal query (`0` rows), fully present and correctly flagged (`IsDeleted = true`) via `... ALL ROWS` |
| Backdating possible | **Untested.** The forge trial deliberately isolated `CreatedById` from `CreatedDate`; whether `CreatedDate` itself can be overridden under the same permission, and whether `SystemModstamp` is writable alongside it, was flagged by Phase A as undocumented and was not exercised in this trial. |

---

## 6. Assigned class

**C1, conditional on `PermissionsCreateAuditFields` not being granted to the integration user.**

Per §6's admissibility lattice: this class permits `reconciled` coverage and a coverage ratio, same as an unconditional C1. The condition does not weaken the *class*, it constrains the *population of valid deployments* — any deployment where the integration user holds the permission must downgrade immediately, not at the next scheduled check.

---

## 7. Trial summary

| Metric | Value |
|---|---|
| Trial window | Single day, 2026-08-18 |
| Population | 20 records (10 agent, 10 human), plus 3 forged/probe records excluded from the isolation count |
| Match rate | 100% — isolation query returned exactly the agent-created 10, zero false positives, zero false negatives |
| Unmatched explanations | N/A — controlled trial, not a production reconciliation run |

---

## Open items — the connector story should resolve these, not assume them

1. **`CreatedDate`/`SystemModstamp` override under the audit-fields permission** — untested. If either is forgeable alongside `CreatedById`, the temporal-authority claim in §4 needs the same conditional treatment as identity isolation.
2. **Production org differences** — this trial ran against a Developer Edition org. Governor limits, `SLA`/workflow trigger behaviour (visible in the trial's debug logs, e.g. `WF_RULE_EVAL_BEGIN`), and permission-set behaviour may differ in a real customer's production org. Do not treat this qualification as portable without re-verification against the first real design partner's org.

### Resolved by EV-42

- **Revalidation cadence:** `PT1H`, with an additional uncached permission preflight before every enumeration/attestation window. A grant or failed check at T2 after a clean check at T1 makes T1–T2 unknown and triggers review of overlapping issued attestations.
- **Permission outcome:** `confirmed-clean`, `confirmed-granted`, and `check-failed` remain three distinct values. Only the first is C1-eligible; the second caps at C5; the third is unqualified rather than being mislabeled as either definite state.
- **Confirmation independence:** confirmation remains a supported capability, but its access relationship is explicitly `shared_with_enumeration`.
