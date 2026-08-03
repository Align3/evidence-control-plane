# Fixture: the reference that resolves to nothing

**CM-401** — A requirement, so the corpus is not empty.

Enforcement begins on EV-97 merge, and triage completes under EV-98. Neither
story is defined anywhere, so both references are dangling. The story defined in
prd.md without a Satisfies field must not be reported.

#### EV-99 — A story heading in the wrong document

A `#### EV-nn` heading outside `prd.md` must not define a story. If it did,
every dangling reference could be silenced by writing its heading beside the
reference, which is the dangling reference re-spelt rather than resolved. The
heading above is the only mention of that story in this fixture, deliberately:
if the reference scan skipped heading-shaped lines, a second mention in prose
would keep the test passing while the hole was open.
