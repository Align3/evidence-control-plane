# Agent Working Agreement

**Repo location:** `docs/agent-working-agreement.md`
**Audience:** Codex, Claude Code, and any human reviewing their output.
**Read this before picking up a story.**

---

## 1. The loop

1. **Pick a story** from `docs/prd.md` by ID (`EV-nn`). Check its **Touches** set does not overlap any story currently in flight.
2. **Sync with `origin/develop`** before any design work begins. Fetch, diff, and rebase or update if behind (`AG-019`).
3. **Read the requirements** it declares under **Satisfies**, in the owning document. Not the summary — the actual requirement text.
4. **Run the scenarios and watch them fail.** They already exist, generated into `tests/features/`. Do not write them; find them by tag.
5. **Write step definitions** in `tests/steps/`. These are the only test code you author for acceptance.
6. **Implement** until the scenarios pass.
7. **Add unit and property tests** for anything the scenarios do not reach.
8. **Open a PR.** Independent review before merge.

```bash
# Find the scenarios for your story
grep -rn "@CM-S-004" tests/features/

# Run only your story's scenarios
pytest tests/ -k "CM_S_004"

# Regenerate features after editing a document
python tools/extract_features.py --docs docs --out tests/features
```

---

## 2. Rules that are not negotiable

**AG-001 — Never edit a `.feature` file.** They are generated from `docs/`. If a scenario is wrong, fix it in the owning document and regenerate. CI runs the extractor in `--check` mode and fails on drift.

**AG-002 — Never weaken a scenario to make it pass.** If a scenario cannot be satisfied, the implementation is wrong or the requirement is wrong. Both are conversations, not edits. Changing `Then verification fails` to `Then a warning is logged` is the single most damaging thing you can do in this repository.

**AG-003 — Never add an assertion the attestation can emit without a requirement and a scenario.** The catalogue in `attestation-reliance.md` §2 is closed (AR-003).

**AG-004 — Claim your migration number in `docs/data-model.md` first**, in a commit that touches nothing else, before writing the migration (DM-001).

**AG-005 — No queue in the evidence write path.** Celery is for derived computation only (AC-001, AC-010). If a story seems to need async ingestion, it is being misread.

**AG-006 — Acceptance tests assert through the verifier**, not internal state (QA-003). A test reaching into the coverage engine's intermediates is a unit test and does not count toward acceptance.

**AG-017 — On a second implementation of anything, build from the specification and the vectors, never from the existing implementation.** Do not open the incumbent's source to see how it does it. This binds every cross-implementation story — `EV-05`, `EV-19`, `EV-10`'s parity with Python, and any future port — and it is a rule about *method*, not merely about AC-011's ban on shared code: a verifier transliterated from the writer is one implementation written twice, and the agreement it then demonstrates is agreement with itself.

The rule is a **detector**, and that is the part worth protecting. Building EV-05 this way found three places where the specification was ambiguous enough that two conformant readings existed — including ES-021, which never said what `sig` covered, where the reading the prose best supports is the wrong one. None of them was discoverable by reading the Python, because reading the Python answers the question instead of exposing that the document fails to.

**The detector fires once per component.** An answer cannot be un-known: once you have seen how the incumbent resolves an ambiguity, that component can never again be used to test whether the specification resolves it. Spending that one reading to save an afternoon is a bad trade, because the specification is the artifact we publish and third parties implement against, and an ambiguity that survives to publication becomes a breaking change rather than a clarification.

If the specification turns out to be insufficient, that is the finding — record it, and amend the document from the **vectors** (ES-029 makes them authoritative), not from what the other implementation happens to do. Where the two disagree, the specification and the vectors decide; the incumbent is not evidence of anything except itself.

**AG-018 — When a builder must originate spec, not just implementation.**
If no requirement covers a structural decision needed to proceed, and no prior implementation exists to consult, the builder may write the missing requirement — but must: (1) mark it explicitly as a new decision, not a clarification of existing text; (2) record any rejected alternative and why, so the choice reads as a choice rather than an inevitability; (3) never manufacture a vector to validate its own decision (QA-019); and (4) the requirement remains **UNCONFIRMED** until a second, independent implementation is built cold against it, with no access to the originating code. Until that confirmation lands, treat the requirement as provisional in any review or reliance decision, regardless of how many tests currently pass against it.

This is not AG-017 restated. AG-017 governs *not reading an incumbent* to resolve an ambiguity someone else already resolved; AG-018 governs the case where there is no incumbent and no answer, so someone has to decide in order to keep building. The two are different situations and only the second permits writing the requirement.

The risk AG-018 addresses is nevertheless the same one. A specification section is supposed to be derivable from the requirements, not from whatever the first implementation happened to find convenient. Where a container shape or a protocol exists because it made one codebase cleaner rather than because it is the necessary shape, a reader cannot tell the difference, and a specification whose structure silently encodes one implementation's incidental choices is weaker than one that does not — even when those choices are good ones. The four obligations above do not remove that risk; they make it visible and bound its duration. The second implementation is what discharges it: if it builds cold against the text without needing to guess or diverge, the requirement stood on its own regardless of how it originated, and if it struggles, AG-017's detector has fired one implementation late rather than never.

Rationale for requirements originated under this rule — the rejected alternatives obligation (2) requires — is recorded in `docs/decision-log.md`, together with the running list of what has been originated and its confirmation status; every cold-build prompt MUST exclude that file. Obligation (2) and obligation (4) otherwise defeat each other: a rationale explaining why the rejected shape was wrong hands the next implementer the answer, the mechanism and the fix, and whatever they build then avoids the defect because the text told them to rather than because they derived it. Keeping the rationale out of the normative documents lets both obligations hold at once.

**AG-018a — The exclusion binds the brief, not only the file.** A cold-build prompt MUST NOT reference the excluded rationale file and MUST NOT restate, paraphrase, or summarise anything recorded in it. That includes naming the rejected alternative, describing how it failed, stating the conclusion it led to, or directing the builder toward the chosen shape. A brief phrased as *"build it this way, not that way"*, or *"watch out for this specific failure mode"*, has already delivered the entire contents of the decision-log entry, and the exclusion of the file has achieved nothing.

**No example of a leak appears in this rule, deliberately.** This document is on every cold-build reading list. An illustration naming a real rejected alternative would put the leak into the one file the builder is always told to read — which is the third way this has now been got wrong, caught in drafting rather than in the field. Concrete examples of leaked and unleaked briefs live in the excluded rationale file, where the builder never sees them.

The test to apply before issuing a brief: **would a reader who has never seen the decision log learn from this brief what the rejected alternative was, or why it was rejected?** If yes, the brief is contaminated and the build it commissions cannot confirm anything under obligation (4).

What a brief MAY contain: the requirement IDs to implement, the documents to read, the tests required, the reporting obligations, and the instruction to report friction. What it MUST NOT contain is the answer. In particular, the instinct to warn a builder what to watch out for is exactly the instinct to resist — the evidence obligation (4) seeks is whether an independent implementer arrives somewhere unsafe *unprompted*, and "notice if you nonetheless arrive somewhere unsafe" cannot be obeyed by someone who has just been told where unsafe is.

Where a defect must be guarded against regardless, the place for it is the **required tests**, phrased as an obligation over the requirement's own normative text rather than as a warning about a known failure. "Construct an adversarial input that attempts to violate this requirement, and show it is refused" commissions the same test without naming the shape that failed.

**This has now happened twice, and neither occurrence was foreseen.** The first cold build reported that its assigned reading had defeated the experiment before it wrote a line of code, which is why the rationale moved to a separate file. The second reported that the brief had reproduced the file's contents in prose, and recorded the consequence in its own words: *it could not have arrived at the rejected design after reading the brief, so its not arriving at one is worth nothing as evidence.* Both times the leak was introduced by someone trying to be helpful. Assume the next one will be too, and apply the test above rather than relying on intent.

**AG-019 — Sync with `origin/develop` before the first design decision, not before the PR.** Before beginning **any** design or implementation work on a story, fetch and diff against `origin/develop`. If the branch is behind, rebase or update **first** — before a single design decision is made, not once the work is finished and the PR is being opened.

Checking staleness at PR time catches the git conflict. That is the cheap failure, and it is not the one this rule exists for. What it does not catch is having independently reinvented something that already exists on `develop` — a helper, an abstraction, a requirement re-derived from scratch. That cost is incurred at design time, in the shape chosen and built against, and by the time a merge conflict surfaces it has already been paid in full: conflicts are resolved in minutes, whereas a duplicated abstraction is either found in review and rewritten, or not found and merged twice. Staleness is therefore a design-time input, not a merge-time chore.

---

## 3. Negative-first

The dangerous defect here is not a crash. It is a **false claim**. A system returning 500 is embarrassing; a system quietly reporting full enforced coverage across an interval where the collector was down is fatal to the company.

**AG-007** — For any capability you implement, write the withholding case before the happy path. Ask: *under what conditions must this refuse to claim?* Then make that fail first.

Left to natural inclination an agent writes `test_coverage_computed_correctly`. What is needed is `test_coverage_refuses_when_denominator_truncated`. If your test names are mostly affirmative, you have built the wrong suite.

---

## 4. Known traps

Specific places where the obvious implementation is wrong. Each has burned someone already or is predicted to.

### EV-11 — the oversight record is not logging

The pattern-match is "record that a human approved something." That implementation is worthless. What matters is `action_state_at_review`: a review recorded against an action that had already committed **must not count as effective oversight**, no matter what decision it carries. Scenario `ES-S-003` enforces this. If your implementation counts it, you have built the commodity version of the differentiating feature.

Likewise `evidence_shown` must be a digest of what was **rendered client-side**. A server-side reconstruction of what should have been shown is a different claim and must be labelled as such (ES-013).

### EV-16 — the coverage engine must refuse, not estimate

Every instinct says fill the gap: interpolate, extrapolate, report a best estimate. All of it is prohibited (CM-011). An unmatched record is counted and classified. An unknown interval is reported as a time range, not folded into a percentage. At denominator class C4 or C5, `coverage_ratio` is **explicitly null** — not zero, not omitted (ES-017). The null is a claim about the world.

Watch gap conservation specifically (`QA-S-002`): covered intervals and gap intervals must partition the window exactly. An interval that is neither is the silent-overclaim bug this product exists to prevent.

### EV-13 — two capabilities, not one

`enumerate` and `confirm` are independent. A connector with `confirm` but not `enumerate` supports per-action reconciliation and **must not** support a window-level coverage claim (AC-008). The type signature should make this hard to get wrong; the coverage engine must enforce it regardless, because a future connector will get it wrong.

### EV-05 / EV-19 — the Go verifier shares no code with Python

Sharing a canonicalisation library between writer and verifier defeats the entire point (AC-011). The cross-implementation agreement in `ES-S-007` is only meaningful if the implementations are genuinely independent. If you find yourself extracting a shared module, stop.

### EV-06 — immutability lives in the database

`UPDATE` and `DELETE` are refused by role grant, not by an application check (AC-012). An ORM configuration that merely avoids issuing them does not satisfy `AC-S-004`.

---

## 5. Review protocol

Following the DamDam convention, and for the same reason: a self-report is not evidence.

**AG-008 — The reviewer MUST be a different model from the builder.** Not merely a different session — a different model. Whatever failure mode led one model to write something wrong is reasonably likely to lead the same model to read it as right; same-model review shares blind spots and produces false confidence. Roles are not fixed: either agent builds, the other reviews, alternating by track.

**AG-009 — Review is a fresh session in the main clone** that **reproduces the claims with real commands**. Not reading the diff and agreeing. Run the tests, inspect the database, verify the chain, confirm the migration applied. The reviewer must not inherit the builder's session context or reasoning — doing so discards the independence the cross-model rule buys.

**AG-010 — Read the requirement before the diff.** Form an expectation of what a correct implementation looks like from the requirement text alone, then compare against what was built. Reading the diff first anchors you to the author's framing, which is exactly what the review exists to escape.

**AG-011** — For anything touching the evidence schema, signing, canonicalisation, or coverage computation, the review must include the Go verifier independently reproducing Python output. This is the check that catches the class of bug nothing else will.

**AG-012 — Adversarial review on high-risk stories.** For `EV-11`, `EV-16`, `EV-05`, and `EV-19`, confirming that tests pass is not sufficient. The reviewer must actively attempt to construct an input that makes the implementation emit a **false claim** — a coverage figure it should have withheld, an oversight record it should have disqualified, a verification that should have failed. For a product whose failure mode is overclaiming, an hour spent trying to break it is worth more than a careful diff read.

**AG-013 — Dual review on those same four stories.** Both models review independently, without seeing each other's findings, and both recommendations are recorded. Expensive, and correct: a false negative on `EV-11` or `EV-16` survives to production and quietly converts the product into a logging tool.

**AG-014** — An automated review-bot pass is not a merge signal on its own for anything in the evidence, signing, coverage, or attestation path.

**AG-015** — Deliberately unbuilt items are disclosed explicitly in the PR, never dropped silently. "Spec listed X; not built because Y" is acceptable. Silence is not.

**AG-016 — Reviewers report; builders fix.** A reviewer MUST NOT author the patch for a finding they raised. This is broader than "do not approve your own work": reporting a defect and correcting it are different roles, and the moment a reviewer writes code in a PR the independent read that AG-008 buys is spent. No model can review a diff it wrote — not in that session, and not in a later one, because the blind spot that produced the code is the same blind spot that reads it as correct. A correct patch from the wrong author still consumes the only independent look that PR will get.

The sequence is: the reviewer files findings; the builder takes ownership and fixes them; the reviewer re-checks the fix. This holds even when the fix is small, obvious, or already written in the reviewer's head — *especially* then, because that is when authoring it feels harmless.

If a reviewer has already committed to the branch, the patch is handed back to the builder with a note stating what was changed, why, and what needs independent eyes. The builder takes ownership of that code as if they had written it. The reviewer does not verify their own patch further, and green CI does not change this — CI is not the independent check the review was for (AG-014).

---

## 6. Done

A story is done when all of the following hold:

- Its acceptance scenarios pass, asserted through the verifier
- The traceability matrix has no orphans (`EV-22`)
- The adversarial suite still passes (`EV-23`)
- Golden attestations are unchanged, or changed with a stated reviewed cause (`EV-24`)
- `extract_features.py --check` passes
- For schema, signing, canonicalisation, or coverage changes: cross-implementation reproduction recorded
- An independent review session has reproduced the claims with real commands

---

## 7. When to stop and ask

Stop rather than guess if:

- A scenario appears unsatisfiable as written
- A requirement in one document contradicts another
- Implementing a story cleanly would require changing the evidence schema
- A story's Touches set turns out to be wrong once you are inside it
- You are about to make the coverage engine estimate anything
- You are about to add a field to the envelope

The last two are architectural decisions wearing the costume of implementation details.

## Verification classifications

> **Verification (document default) — non-testable (process).** These requirements govern agent authoring and independent review procedure; they do not describe product runtime behaviour.
