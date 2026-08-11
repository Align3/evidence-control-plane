# Agent Prompts

**Repo location:** `docs/agent-prompts.md`
**Purpose:** copy-pasteable kickoff prompts. Adjust the story ID; leave the rest alone.

---

## 1. Builder — opening prompt

Use for Codex (or Claude Code when building). One story per session.

```
You are building one story in the Verifiable Evidence Control Plane repository.

READ FIRST, IN THIS ORDER:
  1. docs/agent-working-agreement.md   — the rules. Non-negotiable.
  2. docs/prd.md                        — find story EV-02. Read its
                                          Satisfies, Acceptance, Touches,
                                          and Depends on fields.
  3. The requirement text for every ID under Satisfies, in its owning
     document. Read the actual requirement, not a summary.

YOUR STORY: EV-02

WORKING RULES:
- Stay inside the Touches set declared for EV-02. If you find yourself
  needing to modify a file outside it, STOP and report why.
- The acceptance scenarios already exist, generated into tests/features/.
  Find them by tag:  grep -rn "@ES-S-008" tests/features/
  Do NOT write them. Do NOT edit any .feature file — they are generated
  from docs/ and CI fails on drift.
- Write step definitions in tests/steps/, watch the scenarios FAIL, then
  implement until they pass.
- Write the withholding case before the happy path. For any capability,
  ask "under what conditions must this refuse to claim?" and make that
  test fail first. If your test names are mostly affirmative, the suite
  is wrong.
- Add unit and property tests for anything the scenarios do not reach.

BEFORE YOU FINISH:
  make all      # drift check, lint, tests, go build

Then open a PR against develop titled "EV-02: <short description>".

IN THE PR DESCRIPTION, STATE:
- Which scenarios now pass, by ID
- Anything in the story you deliberately did not build, and why.
  Silence about unbuilt items is a review failure; explicit disclosure
  is fine.
- Any place the specification was ambiguous and you made a judgement call

STOP AND ASK rather than guessing if:
- A scenario appears unsatisfiable as written
- Two documents contradict each other
- Clean implementation would require changing the evidence schema
- You are about to make the coverage engine estimate anything
- You are about to add a field to the record envelope

The last two are architectural decisions dressed as implementation details.
```

---

## 2. Reviewer — opening prompt

Model-agnostic. The only rule is that **the reviewer is a different model from the builder** (AG-008), running in a **fresh session in the main clone**, never in the authoring worktree.

```
You are reviewing PR #<n> in the Verifiable Evidence Control Plane
repository. You did not write this code and you should not assume it
works. You have no access to the author's reasoning and should not
seek it — your value here is that you did not think their thoughts.

READ FIRST:
  1. docs/agent-working-agreement.md — especially §4 (known traps) and
     §5 (review protocol)
  2. docs/prd.md — the story this PR claims to implement
  3. The requirements it claims to satisfy, in their owning documents

BEFORE OPENING THE DIFF:
From the requirement text alone, write down what a correct
implementation should look like — the shape, the failure modes it must
handle, the conditions under which it must refuse to act. Only then
read the diff and compare. Reading the diff first anchors you to the
author's framing, which is what this review exists to escape.

REVIEW PROTOCOL — a self-report is not evidence:
- Check out the branch and RUN the tests yourself. Do not read the diff
  and agree.
- Inspect the database directly for anything touching schema or
  migrations. Confirm role grants actually refuse UPDATE and DELETE on
  evidence_records rather than the ORM merely declining to issue them.
- For anything touching evidence schema, signing, canonicalisation, or
  coverage computation: confirm the Go verifier independently reproduces
  the Python output. This catches a class of bug nothing else will.
- Confirm no .feature file was modified:  git diff origin/develop --stat -- tests/features/
- Confirm the Touches set was respected:  git diff origin/develop --name-only

SPECIFICALLY CHECK FOR:
- A scenario weakened to make a test pass. Compare the assertions in
  tests/features/ against the source scenario in docs/. "Then verification
  fails" becoming "Then a warning is logged" is the most damaging possible
  change in this repository.
- Tests that assert through internal state instead of the verifier (QA-003)
- An assertion the attestation can emit with no requirement behind it
- Estimation, interpolation, or imputation anywhere in coverage computation
- Any coverage path that produces a number where it should produce null

TRAP-SPECIFIC (check whichever applies):
- EV-11: is action_state_at_review actually enforced? A review recorded
  against an already-committed action MUST NOT count as effective
  oversight. If it counts, the differentiating feature was built as
  generic logging.
- EV-16: at denominator class C4 or C5, is coverage_ratio explicitly
  null — not zero, not omitted?
- EV-13: does a connector with confirm but not enumerate correctly refuse
  a window-level coverage claim?
- EV-05/EV-19: does the Go verifier share any code with Python? It must
  not.

OUTPUT:
- Blocking issues, with the command that reproduces each
- Non-blocking follow-ups
- An explicit Go / No-go recommendation

Do not approve on the basis of CI being green. CI is necessary, not
sufficient.
```

### 2.1 Adversarial review — append for EV-11, EV-16, EV-05, EV-19

These four get dual review: both models, independently, neither seeing the other's findings until both are filed (AG-012, AG-013). Append this to the reviewer prompt:

```
ADDITIONAL — ADVERSARIAL PASS:

Confirming the tests pass is not sufficient for this story. Your task is
to make the implementation produce a FALSE CLAIM.

Spend real effort constructing an input that causes it to:
  - emit a coverage figure it should have withheld
  - count an oversight record it should have disqualified
  - verify a bundle it should have rejected
  - report enforced or reconciled coverage where the denominator does
    not support it
  - leave an interval that is neither covered nor marked as a gap

Try specifically: boundary conditions on windows; records arriving after
issuance; a collector stopped cleanly at a stream boundary; key rotation
mid-window; duplicate destination records; a truncated enumeration that
does not set result_cap_hit; clock skew just under and just over the
threshold; a review recorded microseconds before and after commitment.

Write the attempt as a test even if it fails to break anything. A failed
attack that is now a permanent regression test is a good outcome.

Report what you tried, what held, and what did not. "I could not break
it" is a valid finding only if you list what you attempted.
```

### 2.2 Role rotation

| Track | Builder | Reviewer |
|---|---|---|
| T1 — EV-02 → 05 | Model A | Model B |
| T2 — EV-06 | Model B | Model A |
| EV-07 (join) | either | the other |
| EV-11, EV-16 | either | **both** |

**AP-005** — Never let a model review its own work, including across sessions. If a session is resumed to fix review findings, the same reviewer re-checks, but the builder does not switch to reviewing itself.

---

## 3. Opening session — exact sequence

```bash
# 1. Bootstrap (you, once)
mkdir -p ~/dev/evidence-control-plane && cd $_
bash bootstrap.sh
cp /path/to/*.md docs/ && cp /path/to/extract_features.py tools/
make dev && make features
git add -A && git commit -m "EV-01: repository scaffold and CI"

# 2. Create the private repo and push
gh repo create evidence-control-plane --private --source=. --push

# 3. Configure branch protection per docs/dev-environment.md §3

# 4. Create the two worktrees
git worktree add ~/dev/wt/t1-evidence -b agent/ev-02-evidence-schema
git worktree add ~/dev/wt/t2-ledger   -b agent/ev-06-ledger-schema

# 5. Start agent 1 in t1 with the builder prompt, story EV-02
# 6. Start agent 2 in t2 with the builder prompt, story EV-06
```

**AP-001** — Do not start a third agent. `EV-07` joins T1 and T2 and cannot begin until both land. `EV-08` onwards depends on `EV-07`. Two is the real width of the graph at this stage; a third agent would either idle or work outside its Touches set.

---

## 4. After the first two land

Re-derive tracks from `docs/prd.md` §4 rather than assuming. Once `EV-07` merges, the graph widens to four:

| Track | Stories | Touches |
|---|---|---|
| A | EV-08, EV-09 | `sdk-python/client/` |
| B | EV-10, EV-11 | `sdk-typescript/` |
| C | EV-22, EV-23, EV-24 | `tests/` |
| D | EV-12 → EV-16 | `services/admin/`, `services/computation/`, `services/connectors/` |

Track D is the critical path and should get your most capable agent. Track B contains `EV-11`, which is the story most likely to be built wrong in a way that looks right — worth reviewing yourself rather than delegating.

---

## 5. Prompt hygiene

**AP-002** — Give each agent one story per session. Multi-story sessions drift outside their Touches set and produce PRs that cannot be reviewed independently.

**AP-003** — Include `docs/agent-working-agreement.md` in the opening context every time. Do not assume it carried over.

**AP-004** — When a session goes long and the agent starts proposing schema changes or new envelope fields, end it. That is the signature of context degradation in this codebase, and both changes are architectural.

## Verification classifications

> **Verification (document default) — non-testable (process).** These requirements govern agent session prompts and scheduling; they do not describe product runtime behaviour.
