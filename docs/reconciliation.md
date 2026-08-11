# Reconciliation

**Version:** 0.1 draft
**Repo location:** `docs/reconciliation.md`
**Depends on:** `coverage-methodology.md`, `evidence-spec.md`, `architecture.md`
**Drives:** `coverage-methodology.md` implementation, coverage computation

This document closes the matching rules that were deliberately left pending
until EV-13 supplied a concrete destination interface. It is added by EV-15 as
a scoped exception to that story's original Touches set. The accompanying `RC`
prefix registration is part of the same exception.

---

## 1. Inputs and unit of classification

Reconciliation consumes a stored `PopulationRecord`, the immutable evidence
ledger records for the same boundary, and issuer-authenticated
`ExternalConfirmation` records. It produces one result for each distinct
identifier explicitly carried by the population record. The population is the
denominator evidence; reconciliation does not re-enumerate it, deduplicate it,
change its count, or infer identifiers that it does not carry.

**RC-001 — Exact identity only.** A match requires an exact, unique stable-identity
chain: the population's `destination_record_id`, an `ExecutionReceipt` whose
`destination_record_ref` is exactly that value, and an `ExternalConfirmation`
whose `destination_record_id` and `action_id` exactly equal the receipt's
values. The linked `ActionProposal.action_family` and confirmation
`destination_system` must exactly equal the population scope. Timestamp
proximity, amount proximity, ordering, string similarity, and confidence
scores have no standing. A missing proposal prevents a match because the
action family cannot be established; it does not license an inferred scope.

**RC-002 — Closed classification and precedence.** Every classifiable population
identifier resolves to exactly one of `matched`, `unmatched_with_evidence`,
`unmatched_without_evidence`, `duplicate`, `ambiguous`, or `out_of_scope`.
There is no default or residual status. The decision order is:

1. `out_of_scope` when linked evidence names another action family or a
   candidate confirmation names another destination system;
2. `ambiguous` when candidate identity is not unique, including multiple
   confirmations for one population identifier, multiple execution receipts
   for one identifier, multiple proposals for a candidate action, or one
   action linked to multiple population identifiers;
3. `duplicate` for each of two or more *distinct* destination identifiers whose
   unique confirmations carry identical `destination_record_digest` content;
4. `matched` for the single exact identity chain defined by RC-001;
5. `unmatched_with_evidence` when at least one execution receipt names the
   destination identifier but no exact unique chain reaches `matched`;
6. `unmatched_without_evidence` when no execution receipt names the destination
   identifier at all.

Ambiguity therefore takes precedence over `unmatched_with_evidence`: uniqueness
is part of matching, not an optional tie-break. Duplicate detection never picks
a preferred record and never removes one of the destination identifiers.

**RC-003 — Destination duplicates remain visible.** When two or more distinct
population identifiers have unique confirmations with identical exact content
digests, every involved identifier is classified `duplicate`. Every result is
retained, so downstream counts reflect the destination-side duplication.

**RC-004 — Unclassifiable populations are refused.** A population with a repeated
inline identifier is a population-integrity violation, not a destination
duplicate. A population that supplies only `identifier_digest` cannot support
per-record classification. Reconciliation refuses either population with a
named error for that `population_ref`; it does not silently deduplicate,
manufacture identifiers, or emit partial results.

**RC-005 — Replay is deterministic and non-mutating.** Reconciliation is a pure
function of the supplied population, evidence records, and confirmations. It
does not mutate those inputs or any ledger relation. Identical inputs produce
value-identical, identically ordered results, allowing a derived results store
to be truncated and rebuilt without drift.

**RC-006 — Denominator cardinality is conserved.** For every accepted inline
population, the result count equals the signed `PopulationRecord.count`, and
the result order follows `record_identifiers`. Reconciliation does not repair
or reinterpret the denominator. A count/identifier mismatch is refused as a
population-integrity violation.

---

## 2. Classification matrix

| Condition for a population identifier | Classification | Downstream meaning |
|---|---|---|
| Linked evidence is provably outside the declared family or destination | `out_of_scope` | Excluded from the declared scope, explicitly rather than discarded |
| More than one candidate can occupy either side of the identity relation | `ambiguous` | No candidate is selected; ambiguity is surfaced |
| Distinct destination identifiers carry identical confirmed content | `duplicate` | Each destination-side event remains in the denominator and counts |
| Exactly one complete, in-scope stable-identity chain exists | `matched` | Exact reconciliation, with no confidence score |
| Execution evidence names the identifier but the exact chain is incomplete | `unmatched_with_evidence` | Captured execution that a later pass may resolve |
| No execution evidence names the identifier | `unmatched_without_evidence` | Selective-instrumentation signature described by TM-001 |

`unmatched_without_evidence` is the more severe unmatched class: the
destination says an action occurred and the execution evidence path says
nothing about that identity. `unmatched_with_evidence` proves collection
occurred but confirmation did not tie cleanly, and may be resolved by a later
reconciliation pass. EV-16 must preserve this distinction rather than treating
the two unmatched statuses as interchangeable.

---

## 3. Open items inherited by EV-16

A digest-only `PopulationRecord` cannot support EV-15's per-record labels. EV-16
must decide whether choosing digest-only mode caps coverage below `reconciled`,
or whether an aggregate ratio can be supported through per-action
`confirm()` calls validated against the digest-implied total. EV-15 makes
neither claim and exposes no aggregate fallback.

---

## 4. Acceptance criteria

### RC-S-001 — Approximate evidence is never matched *(RC-001, RC-002)*

```gherkin
Given a population record and evidence whose amounts and timestamps are close but whose stable identities differ
When reconciliation runs against the population
Then the population entry is classified "unmatched_without_evidence"
And no confidence score or approximate match is emitted
```

### RC-S-002 — Ambiguity wins over unmatched evidence *(RC-002)*

```gherkin
Given one population entry with one execution receipt and two candidate confirmations
When reconciliation runs against the population
Then the population entry is classified "ambiguous"
And no candidate confirmation is selected
```

### RC-S-003 — Distinct duplicate destination records remain visible *(RC-003)*

```gherkin
Given two distinct population identifiers with identical confirmed content
When reconciliation runs against the population
Then both population entries are classified "duplicate"
And two reconciliation results are retained
```

### RC-S-004 — Unclassifiable population representations are refused *(RC-004)*

```gherkin
Given one population with a repeated identifier and one digest-only population
When per-record reconciliation is requested for each population
Then both populations are refused with named integrity errors
And no partial reconciliation results are emitted
```

### RC-S-005 — Reconciliation conserves immutable inputs and output cardinality *(RC-005, RC-006)*

```gherkin
Given a valid inline population and immutable reconciliation inputs
When reconciliation is replayed twice
Then both runs produce identical ordered results
And the inputs are unchanged
And the result count equals the population count
```
