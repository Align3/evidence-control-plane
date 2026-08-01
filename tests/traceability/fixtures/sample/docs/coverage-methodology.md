# Fixture: coverage methodology

Synthetic requirements in the 900 block. Not the live corpus.

---

## 1. Requirements

**CM-901** — A fully traced requirement: it has a scenario, the scenario has a
test, and an assertion cites it as basis.

**CM-902** — A requirement that cannot carry a scenario and says so.

> **Non-testable — process.** This is a statement about how the change-log
> review is conducted by humans; there is no executable behaviour to assert.

**CM-903** — A requirement with no scenario and no exemption, claimed by a
story. The sharpest class of orphan.

**CM-904** — A requirement whose scenario is owed by a later story.

> **Non-testable (deferred) — EV-90.** The scenario belongs with the
> cross-implementation work and is not invented here. EV-90 exists and lists
> this requirement under Satisfies, so the deferral is fully accounted for.

**CM-905** — A requirement carrying an exemption whose category is not in the
closed enum. It must fail closed.

> **Non-testable — convenient.** The category token is not one of the four
> permitted values, so this marker must not exempt anything.

**CM-906** — A requirement with a scenario that no test implements.

**CM-907** — A requirement whose exemption reason is too short to argue with.

> **Non-testable — process.** Too short.

**CM-908** — A requirement deferred without an owning story.

> **Non-testable (deferred) — unassigned.** Nobody has taken this one yet, and
> that fact is the whole point of recording it here rather than in a side file.

**CM-910** — A requirement deferred to a story that prd.md does not define. The
deferral must be revoked, not honoured.

> **Non-testable (deferred) — EV-97.** Typing a story number that does not exist
> must not retire the debt; the requirement has to fall back to being an orphan.

**CM-911** — A requirement deferred to a real story that does not claim it under
Satisfies. The deferral stands, but nobody has committed to it.

> **Non-testable (deferred) — EV-91.** EV-91 exists but does not list this
> requirement under Satisfies, so the commitment is not recorded anywhere.

**CM-909** — A requirement referenced by a scenario whose reference list also
carries prose, so that the malformed reference does not disturb another chain.

---

## 2. Scenarios

### CM-S-901 — Coverage ratio withheld *(CM-901)*

```gherkin
Given a denominator of class C5
When coverage is computed
Then no ratio is emitted
```

### CM-S-902 — Second scenario *(CM-906)*

```gherkin
Given a scenario nobody has implemented
When the matrix is generated
Then the scenario is reported as untested
```

### CM-S-903 — Reference list carrying prose *(CM-909 property 6)*

```gherkin
Given a reference list with prose in it
When the feature file is generated
Then the tag contains whitespace and Gherkin refuses the file
```

### CM-S-904 — Future story acceptance remains visible *(CM-906)*

```gherkin
Given a scenario owned by a story that has not landed
When the traceability matrix is generated
Then the missing test is reported as expected roadmap debt
```

### CM-S-905 — Scenario ownership is mandatory *(CM-906)*

```gherkin
Given a scenario no story lists under Acceptance
When the traceability matrix is generated
Then missing ownership is reported as a defect
```
