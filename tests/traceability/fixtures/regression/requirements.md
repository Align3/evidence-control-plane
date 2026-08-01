# Fixture: requirements for the QA-S-001 regression gate

One traced requirement and one untraced one, so an assertion can be pointed at
either. Kept on disk rather than inline in the test module: the matrix reads
requirement IDs written in test files as citations, and inlining these would
make the suite report its own fixture data as retired references.

**CM-401** — Traced. A scenario below references it.

**CM-402** — Not traced. Nothing demonstrates it.

### CM-S-401 — A scenario for the traced requirement *(CM-401)*

```gherkin
Given a thing
When it happens
Then it holds
```
