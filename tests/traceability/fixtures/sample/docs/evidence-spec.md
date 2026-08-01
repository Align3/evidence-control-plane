# Fixture: evidence specification

---

## 1. Requirements

**ES-901** — A traced requirement in a second document, to prove that binding
is per-file and that a marker in one document cannot reach into another.

**ES-902** — Two requirements sharing one physical line, as `security.md` does. **ES-903** — The second one must not be swallowed by the first; a requirement the parser cannot see is a requirement nothing enforces.

---

## 2. Scenarios

### ES-S-901 — Record is canonical *(ES-901)*

```gherkin
Given a record
When it is canonicalised
Then the bytes are stable
```
