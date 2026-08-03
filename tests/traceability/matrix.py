#!/usr/bin/env python3
"""Generate the four-link traceability matrix (EV-22; QA-010, QA-011, QA-012).

    requirement ID -> scenario ID -> test ID -> attestation assertion ID

Everything is parsed out of the repository. There is no checked-in matrix and
no side file of exceptions: QA-012 says generated, never hand-maintained, and a
hand-maintained traceability matrix is wrong within a month while still
inviting confidence.

Sources
-------
requirements  bold `**XX-nnn**` definitions in `docs/*.md`
scenarios     `### XX-S-nnn — title *(refs)*` headings, cross-checked against
              the `@tags` in the generated `tests/features/*.feature`
tests         pytest node ids from `--collect-only`, linked to scenarios by
              pytest-bdd decorator and by function name
assertions    the `A-nn` catalogue table in `attestation-reliance.md` §2
ownership     the `**Satisfies:**` fields in `docs/prd.md`
acceptance    the `**Acceptance:**` fields in `docs/prd.md`
story status  reachable commit subjects following the `EV-nn: ...` convention

Exemptions
----------
Most requirements are not scenario-bearing -- "this methodology is versioned
independently", "runbooks 1, 2 and 6 must exist" -- so QA-011 applied literally
fails permanently, and a gate that always fails gets switched off. A
requirement may therefore be marked non-testable, but the marking is explicit,
lives in the source document beside the requirement, and is *reported* rather
than netted off:

    **CM-022** — This methodology is versioned independently of the schema.

    > **Non-testable — process.** Enforced by the §14 change-log review and the
    > independent technical committee; no executable behaviour to assert.

Grammar, in full:

    > **Non-testable[ (MODIFIER)] — TOKEN.** REASON

    MODIFIER absent            TOKEN is a category; exempts this requirement
    MODIFIER "document default" TOKEN is a category; exempts every requirement
                                in the file that has no marker of its own
    MODIFIER "deferred"        TOKEN is `EV-nn` or `unassigned`; records debt,
                                reported separately and never as an exemption

    category  process | documentation | meta | external
    REASON    at least 40 characters, after joining continuation lines

A marker binds to the nearest requirement defined above it in the same file.
Anything that does not parse -- unknown category, missing story, reason too
short, no requirement above it, a second marker on one requirement -- is
reported as MALFORMED_EXEMPTION and exempts nothing. Exemptions fail closed: a
typo leaves a requirement orphaned rather than quietly excusing it.

Usage
-----
    python -m tests.traceability.matrix                       # report only
    python -m tests.traceability.matrix --out-md M.md --out-json M.json
    python -m tests.traceability.matrix --mode enforce --fail-on critical

`--mode` and `--fail-on` may only *strengthen* the QA-011 staged-enforcement
schedule, never weaken it. `--mode report` exits 0 only while the schedule
mandates nothing; once a stage is live it is overridden and the build fails at
the mandated severity. See ENFORCEMENT_SCHEDULE.

That is one instance of the general rule, which is stated in full on `main()`
and asserted as a property over the argument space in
`tests/traceability/test_argument_space.py`:

    No input the caller controls may produce a more permissive verdict than the
    default invocation.

Where an input redirects what is read rather than setting a value -- a different
docs directory, a supplied pytest collection, a repository root somewhere else
-- the run cannot be compared with the default and does not pretend otherwise:
it reports that it cannot establish anything and fails. An empty corpus produces
no findings, and no findings is not the same answer as no problems. CM-001 and
CM-009 say exactly this about a denominator the coverage engine cannot
establish; this generator is held to its own methodology.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------------
# Vocabulary
# --------------------------------------------------------------------------

# Every requirement prefix that appears in docs/. `AP` is agent-prompts.md;
# there is no `DP`. Adding a prefix here is how a new document joins the
# matrix -- a document whose prefix is absent is silently untracked, which is
# why the generator reports unknown-prefix definitions it finds.
PREFIXES = ("AC", "AG", "AP", "AR", "CM", "DE", "DM", "ES", "IN", "QA", "SE", "TM")

# Prefixes whose requirements describe the product. An orphan here is a gap in
# the specification of the thing we sell. The rest (AG, AP, DE) describe how we
# work, and an orphan there is worth knowing about but ranks below.
SPEC_PREFIXES = frozenset({"AC", "AR", "CM", "DM", "ES", "IN", "QA", "SE", "TM"})

CATEGORIES = ("documentation", "external", "meta", "process")
MIN_REASON = 40

# `test_matrix.py` names fictional 900-block requirements as fixture data, and
# `test_argument_space.py` names 800-block ones. Both are collected as tests
# like any other, but their IDs are not read as citations -- otherwise every
# fixture ID would be reported as a retired reference, which is what happened
# the first time the argument-space suite was added: five criticals appeared in
# the live matrix, all of them test data. The exclusion is deliberately a list
# of named files rather than the directory, so that EV-22's own acceptance
# tests still link to QA-S-001 and QA-S-006..008 through the normal path, and it
# is printed with every run so the hole stays arguable.
DEFAULT_EXCLUDED_CITATION_PATHS = (
    "tests/traceability/test_matrix.py",
    "tests/traceability/test_argument_space.py",
)

# QA-011 stages the *existing* backlog. It does not stage regressions.
#
# QA-S-001 is about a **new** assertion added to the catalogue -- a claim this
# pull request makes emittable without anything demonstrating it. That is not
# backlog to be worked off on a schedule, it is the backlog growing, and a
# ratchet that lets the thing it is ratcheting get worse is decorative. These
# finding kinds therefore fail the build immediately, at every stage, whatever
# `--mode` and `--fail-on` say.
ALWAYS_BLOCKING = frozenset(
    {
        "NEW_ASSERTION_NO_SCENARIO",
        "BASELINE_UNAVAILABLE",
        "STORY_HISTORY_UNAVAILABLE",
        # A run that cannot see a corpus cannot certify one. CM-001 and CM-009
        # say an insufficient denominator withholds the claim rather than
        # reporting zero; the generator obeys its own methodology.
        "CORPUS_UNAVAILABLE",
        "UNVERIFIED_INPUTS",
        "UNVERIFIED_COLLECTION",
    }
)

DEFAULT_BASELINE_REF = "origin/develop"

_P = "|".join(PREFIXES)

# A definition is a bold run that *starts* with the id and then either closes
# immediately (`**CM-001** — text`) or carries a title (`**CM-011 — No
# imputation.** text`). Prose that merely opens a bold run with an id --
# `**ES-019 has no acceptance scenario in ...**` in prd.md -- is not a
# definition and must not be counted as one.
REQ_DEF = re.compile(rf"\*\*(?P<rid>(?:{_P})-\d{{3}}[a-z]?)(?:\*\*|\s+[—-]\s)")
REQ_TOKEN = re.compile(rf"\b(?:{_P})-\d{{3}}[a-z]?\b")
ANY_REQ_TOKEN = re.compile(r"\b[A-Z]{2}-\d{3}[a-z]?\b")

SCENARIO_HEADING = re.compile(
    r"^###\s+(?P<sid>[A-Z]{2}-S-\d{3})\s+[—-]\s+(?P<title>.+?)"
    r"(?:\s*\*\((?P<refs>[^)]*)\)\*)?\s*$"
)
SID_TOKEN = re.compile(r"\b[A-Z]{2}-S-\d{3}\b")
# `test_qa_s_001_assertion_without_scenario_fails_ci` -> QA-S-001. The leading
# boundary must be `^` or `_`, not `\b`: an underscore is a word character, so
# `\b` never matches between `test_` and `qa` and this fallback silently linked
# nothing at all. Every apparent name-link was really coming from a pytest-bdd
# decorator elsewhere in the function body.
SID_IN_NAME = re.compile(r"(?:^|_)(?P<prefix>[a-z]{2})_s_(?P<num>\d{3})(?:_|$)")

STORY_HEADING = re.compile(r"^####\s+(?P<story>EV-\d{2})\b")
STORY_TOKEN = re.compile(r"\bEV-\d{2}\b")
SATISFIES = re.compile(r"^\*\*Satisfies:\*\*\s*(?P<body>.+?)\s*$")
ACCEPTANCE = re.compile(r"^\*\*Acceptance:\*\*\s*(?P<body>.+?)\s*$")
RANGE = re.compile(rf"(?P<prefix>{_P})-(?P<lo>\d{{3}})[a-z]?\s*(?:…|\.\.\.)\s*(?P<hi>\d{{3}})")
LANDED_STORY_SUBJECT = re.compile(r"^(?P<story>EV-\d{2}):(?:\s|$)")

ASSERTION_ROW = re.compile(
    r"^\|\s*\*\*(?P<aid>A-\d{2})\*\*\s*\|(?P<text>[^|]*)\|(?P<basis>[^|]*)\|"
)
BASIS_PART = re.compile(r"(?:(?P<prefix>[A-Z]{2})-)?(?P<num>\d{3}[a-z]?)")

EXEMPTION_OPEN = re.compile(
    r"^>\s*\*\*Non-testable(?:\s*\((?P<modifier>[^)]*)\))?\s*[—-]\s*"
    r"(?P<label>[^*.]+?)\.?\*\*\s*(?P<reason>.*)$"
)
QUOTE_LINE = re.compile(r"^>\s?(?P<text>.*)$")

FEATURE_TAGS = re.compile(r"^\s*@\S")


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}

# QA-011 staged enforcement. `--fail-on X` fails on every finding at or above X,
# so a *higher* rank is a stricter gate: `low` fails on everything, `critical`
# only on criticals.
#
# These dates are hard expiries, not targets. On each one CI begins failing at
# that severity whether or not the backfill is done and whether or not the
# owning story has merged -- slipping EV-25 does not slip the gate. The schedule
# lives here rather than in the CI invocation precisely so that deferring a date
# is a code change that shows up in review; a ratchet that any argument can
# loosen is not a ratchet. `medium` and `low` share 1 October, and enforcing at
# `low` subsumes `medium`.
ENFORCEMENT_SCHEDULE: tuple[tuple[date, Severity], ...] = (
    (date(2026, 8, 8), Severity.CRITICAL),   # EV-25 merge
    (date(2026, 9, 1), Severity.HIGH),       # EV-26 triage completion
    (date(2026, 10, 1), Severity.LOW),       # medium and low together
)


def utc_today() -> date:
    """The calendar the ratchet runs on, pinned to UTC.

    `date.today()` reads the process timezone, which made the hard expiry
    locale-dependent: a runner at UTC-11 stayed on 7 August for eleven hours
    after the critical stage went live in UTC, and `TZ=Etc/GMT+12` was an off
    switch spelled as a locale rather than as a flag. Every other seam in this
    file was closed on the argument that a knob nobody can see is worse than one
    they can; an implicit dependency on `$TZ` is that knob. UTC is the one clock
    every runner, reviewer and auditor already agrees on, and the dates in
    ENFORCEMENT_SCHEDULE are published as calendar dates without a zone.
    """
    return datetime.now(UTC).date()


def mandated_threshold(today: date) -> Severity | None:
    """The strictest `--fail-on` level QA-011 requires on this date, if any."""
    mandated: Severity | None = None
    for effective_from, severity in ENFORCEMENT_SCHEDULE:
        if today >= effective_from and (
            mandated is None or SEVERITY_RANK[severity] > SEVERITY_RANK[mandated]
        ):
            mandated = severity
    return mandated


def strictness(threshold: Severity | None) -> int:
    """Order thresholds by how much they block. `None` blocks nothing.

    `None` MUST rank strictly below every severity. An earlier version folded it
    onto `Severity.CRITICAL` with `mandated or Severity.CRITICAL`, which gave
    "no mandate" and "fail on critical" the same rank of 0 and let
    `--today 2026-08-07` disable the live critical stage for the whole of
    August: `0 > 0` is false, so the real-calendar floor never applied. The
    sentinel is gone rather than repaired -- a comparison that has to remember
    a special case is one someone reintroduces.
    """
    return -1 if threshold is None else SEVERITY_RANK[threshold]


def strictest(*candidates: Severity | None) -> Severity | None:
    """The candidate that blocks the most. Ties keep the first."""
    return max(candidates, key=strictness)


def effective_threshold(
    requested: Severity | None,
    asof: date,
    real_today: date | None = None,
) -> tuple[Severity | None, str]:
    """Resolve the requested gate against the schedule. The strictest wins.

    The floor is whatever the *real* calendar mandates. `asof` may bring a
    future stage forward for rehearsal, so its mandate counts too, but it can
    never lower the floor: the mandate is the strictest of the two, and the
    result is the strictest of that and what was requested.

    Returns the threshold to enforce (None means report-only) and a sentence
    saying which input decided it, so the build log states why it is failing or
    not failing rather than leaving a reader to infer it.
    """
    real = real_today if real_today is not None else asof
    mandated = strictest(mandated_threshold(real), mandated_threshold(asof))
    effective = strictest(requested, mandated)

    if effective is None:
        first = ENFORCEMENT_SCHEDULE[0][0].isoformat()
        return None, f"report-only: QA-011 mandates no severity before {first}"
    if mandated is None:
        return effective, f"requested {effective.value}; QA-011 mandates nothing yet"
    since = _mandate_date(mandated).isoformat()
    if requested is None:
        return effective, (
            f"QA-011 mandates {mandated.value} from {since}; report-only was requested "
            f"and is overridden"
        )
    if strictness(requested) >= strictness(mandated):
        return effective, (
            f"requested {requested.value}, at or above the {mandated.value} mandated "
            f"from {since}"
        )
    return effective, (
        f"requested {requested.value} is weaker than the {mandated.value} QA-011 mandates "
        f"from {since}; the schedule wins (one-way ratchet)"
    )


def _mandate_date(severity: Severity) -> date:
    return min(d for d, s in ENFORCEMENT_SCHEDULE if SEVERITY_RANK[s] >= SEVERITY_RANK[severity])

# What each finding means, in words an auditor can read without the codebase.
FINDING_HELP = {
    "RETIRED_REQUIREMENT_REF": (
        "Something cites a requirement ID that no document defines. Either the "
        "requirement was retired and the citation was not updated, or the ID is a typo."
    ),
    "ASSERTION_NO_REQUIREMENT": (
        "An attestation assertion has no requirement as its basis. AG-003 and AR-003 "
        "close the catalogue: an assertion without a requirement must not be emitted."
    ),
    "ASSERTION_NO_SCENARIO": (
        "No requirement underpinning this assertion has an executable scenario, so "
        "nothing demonstrates the assertion is true (QA-002, QA-S-001)."
    ),
    "MALFORMED_EXEMPTION": (
        "A non-testable marker could not be parsed, so it exempted nothing. The "
        "requirement is still counted as an orphan below."
    ),
    "DUPLICATE_REQUIREMENT": (
        "One requirement ID is defined in more than one place. The first definition "
        "wins; the others are ignored."
    ),
    "DUPLICATE_SCENARIO": "One scenario ID is defined in more than one document.",
    "DUPLICATE_ASSERTION": (
        "One assertion ID appears twice in the catalogue. AR-003 closes the catalogue, so "
        "a duplicate row silently replacing a claim's text or basis would erase part of "
        "the published chain. The first row wins."
    ),
    "DUPLICATE_STORY": (
        "A story heading, Satisfies field, or Acceptance field is duplicated. The first "
        "wins, so content in later copies is not attributed to the story."
    ),
    "DEFERRED_UNKNOWN_STORY": (
        "A requirement is deferred to a story that does not exist. The deferral is revoked "
        "and the requirement is reported as an orphan: a typo in a story reference must "
        "not retire traceability debt."
    ),
    "DEFERRED_STORY_DOES_NOT_CLAIM": (
        "A requirement is deferred to a real story that does not list it under Satisfies. "
        "The deferral stands, but no story has committed to writing the scenario."
    ),
    "UNKNOWN_PREFIX": (
        "A requirement-shaped ID uses a prefix the matrix does not track, so it is "
        "invisible to this gate."
    ),
    "NEW_ASSERTION_NO_SCENARIO": (
        "This change adds an assertion, or re-points an existing one, so that a claim the "
        "attestation may emit has nothing demonstrating it. QA-S-001 fails the build for "
        "this now, at every stage: QA-011 stages the existing backlog, not new defects."
    ),
    "BASELINE_UNAVAILABLE": (
        "The previous assertion catalogue could not be read, so new unmapped assertions "
        "cannot be told apart from existing backlog. Reported and blocking rather than "
        "assumed clean."
    ),
    "FEATURE_TAG_MISSING": (
        "A scenario a document defines is not tagged in any generated feature file, so "
        "nothing in the suite can bind to it. Regenerate the features, or point the run "
        "at the directory that holds them."
    ),
    "UNVERIFIED_COLLECTION": (
        "The pytest collection was supplied by the caller rather than performed by this "
        "run. Those node ids are reported, but they do not clear a scenario's missing-test "
        "finding: the tool did not collect them and will not vouch for them."
    ),
    "MALFORMED_SCENARIO_REF": (
        "A scenario heading's requirement list contains something that is not a bare "
        "requirement ID. Each comma-separated part becomes a Gherkin tag, and a tag "
        "containing whitespace makes the generated .feature file unparseable."
    ),
    "SCENARIO_NO_TEST_LANDED": (
        "A scenario in the Acceptance field of a landed story has no test. The story "
        "shipped without demonstrating one of its declared acceptance conditions."
    ),
    "SCENARIO_NO_TEST_UNBUILT": (
        "A scenario is owned by the Acceptance field of a story that has not landed. "
        "This is expected roadmap debt: shipping the owning story is what clears it."
    ),
    "SCENARIO_NO_TEST_UNOWNED": (
        "A scenario has no test and no story lists it under Acceptance. Until ownership "
        "is recorded, the matrix cannot distinguish roadmap debt from a shipped defect."
    ),
    "SCENARIO_UNOWNED": (
        "A scenario has a test but no story lists it under Acceptance. The claim is "
        "demonstrated; what is missing is the record of which story owes it, without "
        "which a later regression has no owner."
    ),
    "DANGLING_STORY_REF": (
        "A document cites a story ID for which prd.md has no story heading. Ordinary "
        "prose is normative too; a missing story must not become a decorative trigger."
    ),
    "STORY_HISTORY_UNAVAILABLE": (
        "Reachable Git history could not be read, so the matrix cannot distinguish an "
        "unbuilt story from a landed story that omitted acceptance tests."
    ),
    "CORPUS_UNAVAILABLE": (
        "The corpus this run read is empty, or implausibly small beside the floor "
        "recorded from the last known good run. Zero requirements is an unknown, not a "
        "pass: the run cannot establish anything and says so instead of exiting 0."
    ),
    "UNVERIFIED_INPUTS": (
        "The caller redirected an input the tool would otherwise choose for itself, so "
        "this run's verdict cannot be compared with the default invocation's. The report "
        "is still generated; the verdict is withheld."
    ),
    "REQUIREMENT_NO_SCENARIO_CLAIMED": (
        "A story's Satisfies field claims this requirement, but nothing tests it and "
        "it carries no exemption. Someone committed to building it."
    ),
    "FEATURE_TAG_DRIFT": (
        "The generated .feature tags disagree with the scenario heading in the owning "
        "document. The document is authoritative; regenerate the feature files."
    ),
    "REQUIREMENT_NO_SCENARIO_SPEC": (
        "A product-specification requirement with no scenario and no exemption."
    ),
    "DEFERRED_UNASSIGNED": (
        "A requirement deferred without an owning story. Real debt with no owner."
    ),
    "REQUIREMENT_NO_SCENARIO_OTHER": (
        "A process or tooling requirement with no scenario and no exemption."
    ),
}


# --------------------------------------------------------------------------
# Model
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Exemption:
    category: str  # one of CATEGORIES, or "deferred"
    reason: str
    source: str  # "file.md:line" of the marker
    story: str | None = None  # deferred only; "unassigned" is recorded as None
    inherited_from: str | None = None  # document name, when a document default


@dataclass
class Requirement:
    rid: str
    doc: str
    line: int
    text: str
    exemption: Exemption | None = None
    claimed_by: tuple[str, ...] = ()
    scenarios: tuple[str, ...] = ()

    @property
    def prefix(self) -> str:
        return self.rid.split("-", 1)[0]


@dataclass
class Scenario:
    sid: str
    title: str
    refs: tuple[str, ...]
    doc: str
    line: int
    tests: tuple[str, ...] = ()
    accepted_by: tuple[str, ...] = ()
    # The comma-separated parts exactly as written in the heading. Kept so that
    # a part which is not a bare requirement ID can be reported: extract_features
    # turns each part into a Gherkin tag, and a tag containing whitespace makes
    # the whole generated .feature unparseable.
    raw_refs: tuple[str, ...] = ()


@dataclass
class Assertion:
    aid: str
    text: str
    basis: tuple[str, ...]
    doc: str
    line: int


@dataclass
class TestNode:
    nodeid: str
    file: str
    scenarios: tuple[str, ...] = ()
    citations: tuple[str, ...] = ()
    # (scenario id, how the link was established): "pytest-bdd" executes the
    # scenario's documented steps; "test name" and "cited in body" are the
    # author's assertion that the test covers it. Recorded so the strength of
    # each link in the published chain is visible rather than assumed.
    link_kind: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class Finding:
    kind: str
    severity: Severity
    subject: str
    location: str
    detail: str

    def sort_key(self) -> tuple[int, str, str]:
        return (SEVERITY_RANK[self.severity], self.kind, self.subject)


@dataclass
class Matrix:
    requirements: dict[str, Requirement] = field(default_factory=dict)
    scenarios: dict[str, Scenario] = field(default_factory=dict)
    tests: dict[str, TestNode] = field(default_factory=dict)
    assertions: dict[str, Assertion] = field(default_factory=dict)
    stories: dict[str, tuple[str, ...]] = field(default_factory=dict)
    story_acceptance: dict[str, tuple[str, ...]] = field(default_factory=dict)
    story_definitions: dict[str, str] = field(default_factory=dict)
    landed_stories: tuple[str, ...] = ()
    findings: list[Finding] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    excluded_citation_paths: tuple[str, ...] = ()
    collection_supplied: bool = False

    def worst(self) -> Severity | None:
        if not self.findings:
            return None
        return min((f.severity for f in self.findings), key=lambda s: SEVERITY_RANK[s])


# --------------------------------------------------------------------------
# Parsing: requirements and their exemption markers
# --------------------------------------------------------------------------


@dataclass
class _RawMarker:
    modifier: str | None
    label: str
    reason: str
    line: int
    bound_to: str | None  # requirement id, or None for a document default


def _clean(text: str) -> str:
    """Strip the markdown a table cell cannot carry."""
    text = re.sub(r"`([^`]*)`", r"\1", text)
    text = re.sub(r"\*\*([^*]*)\*\*", r"\1", text)
    text = re.sub(r"\*([^*]*)\*", r"\1", text)
    return " ".join(text.split())


def _parse_document(path: Path) -> tuple[list[Requirement], list[_RawMarker], list[Finding]]:
    requirements: list[Requirement] = []
    markers: list[_RawMarker] = []
    findings: list[Finding] = []
    lines = path.read_text(encoding="utf-8").splitlines()
    last_rid: str | None = None

    i = 0
    while i < len(lines):
        line = lines[i]

        match = EXEMPTION_OPEN.match(line)
        if match:
            reason_parts = [match.group("reason").strip()]
            j = i + 1
            while j < len(lines):
                cont = QUOTE_LINE.match(lines[j])
                if not cont:
                    break
                reason_parts.append(cont.group("text").strip())
                j += 1
            modifier = (match.group("modifier") or "").strip().lower() or None
            markers.append(
                _RawMarker(
                    modifier=modifier,
                    label=match.group("label").strip(),
                    reason=_clean(" ".join(p for p in reason_parts if p)),
                    line=i + 1,
                    bound_to=None if modifier == "document default" else last_rid,
                )
            )
            i = j
            continue

        # A markdown blockquote that is not a marker resets nothing; only a
        # requirement definition moves the binding point.
        #
        # More than one definition can share a line -- security.md:83 carries
        # SE-019 and SE-020 in one paragraph -- so take every match, and give
        # each requirement the text running up to the next definition.
        found = list(REQ_DEF.finditer(line))
        if found:
            for k, match in enumerate(found):
                stop = found[k + 1].start() if k + 1 < len(found) else len(line)
                text = _clean(line[match.end():stop].lstrip(" —-"))
                if not text:
                    # `**CM-011 — No imputation.**` style: the title is the text.
                    text = _clean(match.group(0))
                requirements.append(
                    Requirement(rid=match.group("rid"), doc=path.name, line=i + 1, text=text)
                )
            last_rid = found[-1].group("rid")
        elif ANY_REQ_TOKEN.search(line):
            for found_id in ANY_REQ_TOKEN.findall(line):
                prefix = found_id.split("-", 1)[0]
                defined = re.search(rf"\*\*{re.escape(found_id)}(\*\*|\s+—)", line)
                if prefix not in PREFIXES and defined:
                    findings.append(
                        Finding(
                            kind="UNKNOWN_PREFIX",
                            severity=Severity.MEDIUM,
                            subject=found_id,
                            location=f"{path.name}:{i + 1}",
                            detail=f"prefix {prefix!r} is not tracked by the matrix",
                        )
                    )
        i += 1

    return requirements, markers, findings


def _apply_markers(
    doc: str,
    requirements: dict[str, Requirement],
    markers: list[_RawMarker],
) -> list[Finding]:
    findings: list[Finding] = []
    doc_default: Exemption | None = None
    seen: set[str] = set()

    def malformed(subject: str, line: int, detail: str) -> None:
        findings.append(
            Finding(
                kind="MALFORMED_EXEMPTION",
                severity=Severity.CRITICAL,
                subject=subject,
                location=f"{doc}:{line}",
                detail=detail,
            )
        )

    for marker in markers:
        source = f"{doc}:{marker.line}"
        subject = marker.bound_to or doc

        if marker.modifier not in (None, "document default", "deferred"):
            malformed(subject, marker.line, f"unknown modifier {marker.modifier!r}")
            continue

        if marker.modifier == "deferred":
            if not re.fullmatch(r"EV-\d{2}|unassigned", marker.label):
                malformed(
                    subject, marker.line,
                    f"deferred requires a story reference or 'unassigned', got {marker.label!r}",
                )
                continue
            category, story = "deferred", (
                None if marker.label == "unassigned" else marker.label
            )
        else:
            if marker.label not in CATEGORIES:
                malformed(
                    subject, marker.line,
                    f"category {marker.label!r} is not one of {', '.join(CATEGORIES)}",
                )
                continue
            category, story = marker.label, None

        if len(marker.reason) < MIN_REASON:
            malformed(
                subject, marker.line,
                f"reason is {len(marker.reason)} characters; at least {MIN_REASON} required",
            )
            continue

        if marker.modifier == "document default":
            if category == "deferred":
                malformed(doc, marker.line, "a document default may not be a deferral")
                continue
            if doc_default is not None:
                malformed(doc, marker.line, "a second document default in one file")
                continue
            doc_default = Exemption(
                category=category, reason=marker.reason, source=source, inherited_from=doc
            )
            continue

        if marker.bound_to is None:
            malformed(doc, marker.line, "marker has no requirement defined above it")
            continue
        if marker.bound_to in seen:
            malformed(marker.bound_to, marker.line, "a second marker on one requirement")
            requirements[marker.bound_to].exemption = None
            continue

        seen.add(marker.bound_to)
        requirements[marker.bound_to].exemption = Exemption(
            category=category, reason=marker.reason, source=source, story=story
        )

    if doc_default is not None:
        for req in requirements.values():
            if req.doc == doc and req.exemption is None and req.rid not in seen:
                req.exemption = doc_default

    return findings


# --------------------------------------------------------------------------
# Parsing: scenarios, assertions, stories, tests
# --------------------------------------------------------------------------


def _parse_scenarios(path: Path) -> list[Scenario]:
    out: list[Scenario] = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = SCENARIO_HEADING.match(line)
        if not match:
            continue
        raw = match.group("refs") or ""
        refs = tuple(REQ_TOKEN.findall(raw))
        out.append(
            Scenario(
                sid=match.group("sid"),
                title=_clean(match.group("title")),
                refs=refs,
                doc=path.name,
                line=n,
                raw_refs=tuple(p.strip() for p in raw.split(",") if p.strip()),
            )
        )
    return out


def _parse_feature_tags(features_dir: Path) -> dict[str, tuple[str, ...]]:
    """Requirement tags carried by each generated scenario."""
    tags: dict[str, tuple[str, ...]] = {}
    if not features_dir.is_dir():
        return tags
    for feature in sorted(features_dir.glob("*.feature")):
        for line in feature.read_text(encoding="utf-8").splitlines():
            if not FEATURE_TAGS.match(line):
                continue
            tokens = [t.lstrip("@") for t in line.split()]
            sids = [t for t in tokens if SID_TOKEN.fullmatch(t)]
            refs = tuple(t for t in tokens if REQ_TOKEN.fullmatch(t))
            for sid in sids:
                tags[sid] = refs
    return tags


def expand_basis(raw: str) -> list[str]:
    """Expand the slash-compressed Basis column: `ES-006/021` -> both ids."""
    out: list[str] = []
    prefix: str | None = None
    for part in re.split(r"[,\s/]+", raw.strip()):
        if not part:
            continue
        match = BASIS_PART.fullmatch(part)
        if not match:
            continue
        if match.group("prefix"):
            prefix = match.group("prefix")
        if prefix is None:
            continue
        out.append(f"{prefix}-{match.group('num')}")
    return out


def _parse_assertions(path: Path) -> list[Assertion]:
    out: list[Assertion] = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = ASSERTION_ROW.match(line)
        if not match:
            continue
        out.append(
            Assertion(
                aid=match.group("aid"),
                text=_clean(match.group("text")),
                basis=tuple(expand_basis(match.group("basis"))),
                doc=path.name,
                line=n,
            )
        )
    return out


def expand_satisfies(raw: str) -> list[str]:
    """Expand a `**Satisfies:**` body: ranges, qualifiers, plain ids."""
    body = re.sub(r"\([^)]*\)", " ", raw)
    out: list[str] = []
    for chunk in body.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        span = RANGE.search(chunk)
        if span:
            prefix = span.group("prefix")
            lo, hi = int(span.group("lo")), int(span.group("hi"))
            if lo <= hi:
                out.extend(f"{prefix}-{n:03d}" for n in range(lo, hi + 1))
                continue
        out.extend(REQ_TOKEN.findall(chunk))
    return out


def _parse_stories(
    path: Path,
) -> tuple[
    dict[str, tuple[str, ...]],
    dict[str, tuple[str, ...]],
    dict[str, str],
    list[Finding],
]:
    """Ownership, acceptance and definedness, all read from `prd.md` alone.

    Definedness comes from the `#### EV-nn` heading, not from having a
    `Satisfies:` field: a story that declares none is unusual but it exists.
    The scan is restricted to this one file by construction. A `#### EV-nn`
    heading in any other document must not be able to define a story into
    existence -- otherwise a normative reference to a story nobody wrote can be
    silenced by writing the heading somewhere convenient, which is the dangling
    reference re-spelt.
    """
    stories: dict[str, tuple[str, ...]] = {}
    acceptance: dict[str, tuple[str, ...]] = {}
    definitions: dict[str, str] = {}
    findings: list[Finding] = []
    story: str | None = None
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        heading = STORY_HEADING.match(line)
        if heading:
            story = heading.group("story")
            if story in definitions:
                findings.append(
                    Finding(
                        kind="DUPLICATE_STORY",
                        severity=Severity.HIGH,
                        subject=story,
                        location=f"{path.name}:{n}",
                        detail=f"a second story heading; first defined at {definitions[story]}",
                    )
                )
            else:
                definitions[story] = f"{path.name}:{n}"
            continue
        satisfies = SATISFIES.match(line)
        if satisfies and story:
            if story in stories:
                findings.append(
                    Finding(
                        kind="DUPLICATE_STORY",
                        severity=Severity.HIGH,
                        subject=story,
                        location=f"{path.name}:{n}",
                        detail="a second Satisfies field for one story; the first wins, so the "
                               "requirements listed here are not attributed to any story",
                    )
                )
                continue
            stories[story] = tuple(expand_satisfies(satisfies.group("body")))
            continue
        accepted = ACCEPTANCE.match(line)
        if accepted and story:
            if story in acceptance:
                findings.append(
                    Finding(
                        kind="DUPLICATE_STORY",
                        severity=Severity.HIGH,
                        subject=story,
                        location=f"{path.name}:{n}",
                        detail="a second Acceptance field for one story; the first wins",
                    )
                )
                continue
            acceptance[story] = tuple(SID_TOKEN.findall(accepted.group("body")))
    return stories, acceptance, definitions, findings


BDD_SCENARIO_CALL = re.compile(
    r"@scenario\s*\(\s*[^)]*?[\"'](?P<sid>[A-Z]{2}-S-\d{3})\b", re.S
)


def _bdd_scenarios(body: str) -> list[str]:
    """Scenario ids bound through a pytest-bdd `@scenario(...)` decorator."""
    return [m.group("sid") for m in BDD_SCENARIO_CALL.finditer(body)]


def _function_spans(source: str) -> dict[str, tuple[int, int]]:
    """Map `name` / `Class::name` to the line span covering decorators + body."""
    spans: dict[str, tuple[int, int]] = {}

    def walk(node: ast.AST, prefix: str) -> None:
        for child in getattr(node, "body", []):
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef):
                start = min([child.lineno, *(d.lineno for d in child.decorator_list)])
                spans[f"{prefix}{child.name}"] = (start, child.end_lineno or child.lineno)
            elif isinstance(child, ast.ClassDef):
                walk(child, f"{prefix}{child.name}::")

    walk(ast.parse(source), "")
    return spans


def _link_tests(
    repo_root: Path, node_ids: list[str], exclude_citations: tuple[str, ...] = ()
) -> tuple[dict[str, TestNode], dict[str, tuple[str, ...]], list[Finding]]:
    """Attribute scenario links and requirement citations to each node id.

    A citation inside a test function belongs to that test. A citation outside
    every function -- a module docstring, a comment beside an import -- belongs
    to the file, and is kept only so that a retired ID cannot hide there.

    Files under `exclude_citations` are still collected as tests but their IDs
    are not read as citations. That is for this generator's own suite, whose
    fixture corpus names deliberately fictional requirements; reading them as
    claims about the product would fill the matrix with retired-ID findings
    that are really just test data. The excluded paths are reported in the
    output so the hole is visible rather than assumed.
    """
    tests: dict[str, TestNode] = {}
    module_citations: dict[str, tuple[str, ...]] = {}
    findings: list[Finding] = []
    by_file: dict[str, list[str]] = defaultdict(list)

    for nodeid in node_ids:
        if "::" not in nodeid:
            continue
        by_file[nodeid.split("::", 1)[0]].append(nodeid)

    for rel, ids in sorted(by_file.items()):
        path = repo_root / rel
        if not path.is_file():
            findings.append(
                Finding(
                    kind="MISSING_TEST_SOURCE",
                    severity=Severity.MEDIUM,
                    subject=rel,
                    location=rel,
                    detail="collected node id refers to a file that is not on disk",
                )
            )
            continue
        if any(rel.startswith(prefix) for prefix in exclude_citations):
            for nodeid in sorted(ids):
                tests[nodeid] = TestNode(nodeid=nodeid, file=rel)
            continue

        source = path.read_text(encoding="utf-8")
        lines = source.splitlines()
        try:
            spans = _function_spans(source)
        except SyntaxError:
            spans = {}

        covered: set[int] = set()
        for start, end in spans.values():
            covered.update(range(start, end + 1))
        outside = "\n".join(
            line for n, line in enumerate(lines, 1) if n not in covered
        )
        module_citations[rel] = tuple(sorted(set(REQ_TOKEN.findall(outside))))

        for nodeid in sorted(ids):
            name = nodeid.split("::", 1)[1]
            key = re.sub(r"\[.*\]$", "", name)
            span = spans.get(key)
            if span is None:
                tests[nodeid] = TestNode(nodeid=nodeid, file=rel)
                continue
            body = "\n".join(lines[span[0] - 1: span[1]])

            # How each scenario link was established is itself evidence: a
            # binding through pytest-bdd executes the documented Given/When/Then
            # steps, a link by function name or a mention in the body only
            # asserts that the author says the test covers the scenario. An
            # auditor reading the matrix should be able to tell the two apart
            # rather than take every link at equal weight.
            how: dict[str, str] = {}
            for decorator_sid in _bdd_scenarios(body):
                how[decorator_sid] = "pytest-bdd"
            for mentioned in SID_TOKEN.findall(body):
                how.setdefault(mentioned, "cited in body")
            in_name = SID_IN_NAME.search(key)
            if in_name:
                sid = f"{in_name.group('prefix').upper()}-S-{in_name.group('num')}"
                how.setdefault(sid, "test name")

            tests[nodeid] = TestNode(
                nodeid=nodeid,
                file=rel,
                scenarios=tuple(sorted(how)),
                citations=tuple(sorted(set(REQ_TOKEN.findall(body)))),
                link_kind=tuple(sorted(how.items())),
            )

    return tests, module_citations, findings


def _git(repo_root: Path, *args: str) -> str | None:
    """Run a read-only git command. None if git or the ref is unavailable."""
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell, no user input
            ["git", *args],  # noqa: S607 - git resolved from PATH by design
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    return proc.stdout if proc.returncode == 0 else None


def landed_story_ids(repo_root: Path) -> frozenset[str] | None:
    """Return story IDs whose implementation commits are reachable from HEAD.

    PR titles and story commits use the repository convention ``EV-nn: ...``.
    Looking only at reachable history means a story branch elsewhere in the
    repository does not count as landed in the build being checked, while the
    head commit of a candidate story PR does. Acceptance fields supply scenario
    ownership; history supplies whether that owner has landed.
    """

    subjects = _git(repo_root, "log", "--format=%s", "HEAD")
    if subjects is None:
        return None
    return frozenset(
        match.group("story")
        for subject in subjects.splitlines()
        if (match := LANDED_STORY_SUBJECT.match(subject)) is not None
    )


@dataclass(frozen=True)
class CatalogueEntry:
    """What an assertion said, as of some commit.

    The claim text is part of the identity, not decoration. Rewriting what an
    attestation asserts while keeping the same id and basis produces a
    different claim resting on the same evidence, which is exactly the case a
    closed catalogue (AR-003) exists to control. Comparing ids and bases alone
    would wave it through as old backlog.
    """

    text: str
    basis: tuple[str, ...]


def _parse_catalogue(blob: str) -> dict[str, CatalogueEntry]:
    out: dict[str, CatalogueEntry] = {}
    for line in blob.splitlines():
        m = ASSERTION_ROW.match(line)
        # First row wins, matching the live parse, so a duplicated id in the
        # baseline cannot change what "unchanged" means.
        if m and m.group("aid") not in out:
            out[m.group("aid")] = CatalogueEntry(
                text=_clean(m.group("text")), basis=tuple(expand_basis(m.group("basis")))
            )
    return out


def merge_base(repo_root: Path, ref: str) -> tuple[str | None, str]:
    """The commit the last known good state is read from, and why.

    None means it could not be established, which is reported and blocks. It is
    never silently treated as "nothing is new": a gate that cannot see the
    previous state cannot tell a regression from backlog, and guessing in the
    permissive direction is how this check would quietly stop working.

    There is deliberately no fall back to the tip of `ref` when `merge-base`
    fails. Unrelated histories and shallow clones both fail that way, and the
    tip is not the baseline in either case -- an earlier version substituted it
    and still called the result a merge base, which defeated the shallow-history
    safeguard `fetch-depth: 0` exists to satisfy.
    """
    if not (_git(repo_root, "rev-parse", "--verify", f"{ref}^{{commit}}") or "").strip():
        return None, f"{ref} could not be resolved"
    base = (_git(repo_root, "merge-base", "HEAD", ref) or "").strip()
    if not base:
        return None, (
            f"no merge base between HEAD and {ref} -- unrelated histories, or the common "
            f"ancestor was not fetched (actions/checkout needs fetch-depth: 0)"
        )
    # A merge base equal to HEAD means the state is being compared against
    # itself, so nothing can ever be new. That is the legitimate state on a push
    # build to the integration branch -- the PR was gated before it merged -- but
    # it is a vacuous check either way, and a vacuous check that reads as a clean
    # one is how every other seam in this gate went wrong. Say so plainly.
    head = (_git(repo_root, "rev-parse", "HEAD") or "").strip()
    vacuous = " -- this IS HEAD, so nothing can be new in this build" if base == head else ""
    return base, f"merge base {base[:12]} with {ref}{vacuous}"


def baseline_corpus(repo_root: Path, base: str, docs_reldir: str = "docs") -> dict[str, int]:
    """How big the corpus was at `base`: the floor this run must clear.

    CM-001 and CM-009 say that where the population cannot be independently
    established the methodology emits no ratio and says so, rather than
    reporting zero. The generator is held to its own rule. Reading no
    requirements is not a clean corpus, it is an unestablished one, and the
    only honest previous population available is the state the integration
    branch was last known good at.
    """
    listing = _git(repo_root, "ls-tree", "-r", "--name-only", base, "--", docs_reldir)
    counts = {"requirements": 0, "assertions": 0}
    for relpath in (listing or "").splitlines():
        if not relpath.endswith(".md"):
            continue
        blob = _git(repo_root, "show", f"{base}:{relpath}")
        if blob is None:
            continue
        counts["requirements"] += len({m.group("rid") for m in REQ_DEF.finditer(blob)})
        if relpath.endswith("attestation-reliance.md"):
            counts["assertions"] += len(_parse_catalogue(blob))
    return counts


def baseline_assertions(
    repo_root: Path, ref: str, ar_relpath: str = "docs/attestation-reliance.md"
) -> tuple[dict[str, CatalogueEntry] | None, str]:
    """The assertion catalogue as of the merge base with `ref`."""
    base, description = merge_base(repo_root, ref)
    if base is None:
        return None, description
    blob = _git(repo_root, "show", f"{base}:{ar_relpath}")
    if blob is None:
        # The file not existing at the baseline is a real answer, not a
        # failure: every assertion in it today is new.
        return {}, f"{ar_relpath} did not exist at {description}"
    return _parse_catalogue(blob), description


def collect_node_ids(repo_root: Path, target: str = "tests") -> list[str]:
    """Ask pytest what it would run. Sorted, so the matrix is deterministic."""
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell, no user input
        [
            sys.executable, "-m", "pytest", target,
            "--collect-only", "-q", "--no-header", "-p", "no:cacheprovider",
        ],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    ids = sorted({line.strip() for line in proc.stdout.splitlines() if "::" in line})
    if not ids:
        print(proc.stdout, file=sys.stderr)
        print(proc.stderr, file=sys.stderr)
        raise SystemExit("pytest collected no tests; the matrix would be meaningless")
    return ids


# --------------------------------------------------------------------------
# Build
# --------------------------------------------------------------------------


def build_matrix(
    *,
    repo_root: Path,
    docs_dir: Path,
    features_dir: Path | None,
    node_ids: list[str],
    exclude_citations: tuple[str, ...] = (),
    baseline: dict[str, CatalogueEntry] | None = None,
    baseline_description: str = "no baseline supplied",
    regression_gate: bool = False,
    landed_stories: frozenset[str] | None = None,
    extra_baselines: tuple[tuple[dict[str, CatalogueEntry] | None, str], ...] = (),
    collection_supplied: bool = False,
    corpus_floor: dict[str, int] | None = None,
) -> Matrix:
    matrix = Matrix()
    matrix.excluded_citation_paths = tuple(sorted(exclude_citations))
    matrix.collection_supplied = collection_supplied

    # -- requirements, then their markers, per document ---------------------
    for md in sorted(docs_dir.glob("*.md")):
        requirements, markers, findings = _parse_document(md)
        matrix.findings.extend(findings)
        for req in requirements:
            if req.rid in matrix.requirements:
                first = matrix.requirements[req.rid]
                matrix.findings.append(
                    Finding(
                        kind="DUPLICATE_REQUIREMENT",
                        severity=Severity.CRITICAL,
                        subject=req.rid,
                        location=f"{req.doc}:{req.line}",
                        detail=f"first defined at {first.doc}:{first.line}; that one wins",
                    )
                )
                continue
            matrix.requirements[req.rid] = req
        matrix.findings.extend(_apply_markers(md.name, matrix.requirements, markers))

    # -- scenarios ----------------------------------------------------------
    for md in sorted(docs_dir.glob("*.md")):
        for scenario in _parse_scenarios(md):
            if scenario.sid in matrix.scenarios:
                first = matrix.scenarios[scenario.sid]
                matrix.findings.append(
                    Finding(
                        kind="DUPLICATE_SCENARIO",
                        severity=Severity.CRITICAL,
                        subject=scenario.sid,
                        location=f"{scenario.doc}:{scenario.line}",
                        detail=f"also defined at {first.doc}:{first.line}",
                    )
                )
                continue
            matrix.scenarios[scenario.sid] = scenario

    # -- assertions and story ownership ------------------------------------
    # AR-003 closes the catalogue, so a duplicate row is worse here than
    # anywhere else: last-write-wins would silently replace a claim's text and
    # basis, erasing part of the published four-link chain while the matrix
    # still reported a complete one. First definition wins, and the collision
    # is reported.
    ar_doc = docs_dir / "attestation-reliance.md"
    if ar_doc.is_file():
        for assertion in _parse_assertions(ar_doc):
            if assertion.aid in matrix.assertions:
                first = matrix.assertions[assertion.aid]
                matrix.findings.append(
                    Finding(
                        kind="DUPLICATE_ASSERTION",
                        severity=Severity.CRITICAL,
                        subject=assertion.aid,
                        location=f"{assertion.doc}:{assertion.line}",
                        detail=f"already defined at {first.doc}:{first.line} with basis "
                               f"{', '.join(first.basis) or '(none)'}; the first row wins and "
                               f"this one is ignored",
                    )
                )
                continue
            matrix.assertions[assertion.aid] = assertion

    prd = docs_dir / "prd.md"
    if prd.is_file():
        stories, acceptance, definitions, story_findings = _parse_stories(prd)
        matrix.stories = stories
        matrix.story_acceptance = acceptance
        matrix.story_definitions = definitions
        matrix.findings.extend(story_findings)

    discovered_stories = landed_stories
    if discovered_stories is None:
        discovered_stories = landed_story_ids(repo_root)
        if discovered_stories is None:
            discovered_stories = frozenset()
            if matrix.story_acceptance:
                matrix.findings.append(
                    Finding(
                        kind="STORY_HISTORY_UNAVAILABLE",
                        severity=Severity.CRITICAL,
                        subject="story commit history",
                        location=str(repo_root),
                        detail="git log HEAD failed; scenario debt is not assumed unbuilt",
                    )
                )
    matrix.landed_stories = tuple(sorted(discovered_stories))

    # Every story-shaped reference in normative prose must resolve, not only
    # the references in specially parsed deferral markers. This catches dates,
    # gates and dependencies that name work nobody actually defined. Resolution
    # is against `story_definitions`, which `_parse_stories` reads from prd.md
    # and nowhere else: a `#### EV-nn` heading in another document is a citation
    # like any other, not a definition.
    # No special case for headings. A `#### EV-nn` line in prd.md defines the
    # story it names, so its own token resolves against `story_definitions` like
    # any other; a `#### EV-nn` line anywhere else is a citation, and skipping
    # heading-shaped lines here would have hidden exactly the citations this
    # check exists to catch.
    for md in sorted(docs_dir.glob("*.md")):
        for n, line in enumerate(md.read_text(encoding="utf-8").splitlines(), 1):
            for story_ref in STORY_TOKEN.findall(line):
                if story_ref not in matrix.story_definitions:
                    matrix.findings.append(
                        Finding(
                            kind="DANGLING_STORY_REF",
                            severity=Severity.CRITICAL,
                            subject=story_ref,
                            location=f"{md.name}:{n}",
                            detail=f"{story_ref} has no #### {story_ref} heading in prd.md",
                        )
                    )

    claims: dict[str, list[str]] = defaultdict(list)
    for story, rids in sorted(matrix.stories.items()):
        for rid in rids:
            claims[rid].append(story)
    for rid, owners in claims.items():
        if rid in matrix.requirements:
            matrix.requirements[rid].claimed_by = tuple(sorted(set(owners)))

    # A deferral names a story that owes the scenario. Validating only the
    # `EV-nn` shape let a deferral to a story that does not exist suppress an
    # orphan outright -- a typo in the reference silently retired the debt,
    # which is the exact failure the fail-closed rule exists to prevent. The
    # story list is only available here, after prd.md is parsed, so this runs
    # as a second pass and revokes the exemption it rejects.
    for rid, req in sorted(matrix.requirements.items()):
        exemption = req.exemption
        if exemption is None or exemption.category != "deferred" or exemption.story is None:
            continue
        if exemption.story not in matrix.story_definitions:
            req.exemption = None
            matrix.findings.append(
                Finding(
                    kind="DEFERRED_UNKNOWN_STORY",
                    severity=Severity.CRITICAL,
                    subject=rid,
                    location=exemption.source,
                    detail=f"deferred to {exemption.story}, which prd.md does not define; the "
                           f"deferral is revoked and the requirement is reported as an orphan",
                )
            )
        elif rid not in matrix.stories.get(exemption.story, ()):
            matrix.findings.append(
                Finding(
                    kind="DEFERRED_STORY_DOES_NOT_CLAIM",
                    severity=Severity.MEDIUM,
                    subject=rid,
                    location=exemption.source,
                    detail=f"deferred to {exemption.story}, which does not list it under "
                           f"Satisfies; the deferral stands, but nobody has committed to it",
                )
            )

    # -- tests --------------------------------------------------------------
    tests, module_citations, findings = _link_tests(
        repo_root, node_ids, matrix.excluded_citation_paths
    )
    matrix.tests = tests
    matrix.findings.extend(findings)

    # -- link requirement -> scenario --------------------------------------
    by_requirement: dict[str, list[str]] = defaultdict(list)
    for sid, scenario in sorted(matrix.scenarios.items()):
        for ref in scenario.refs:
            by_requirement[ref].append(sid)
    for rid, sids in by_requirement.items():
        if rid in matrix.requirements:
            matrix.requirements[rid].scenarios = tuple(sorted(set(sids)))

    # -- link scenario -> test ---------------------------------------------
    by_scenario: dict[str, list[str]] = defaultdict(list)
    for nodeid, test in sorted(matrix.tests.items()):
        for sid in test.scenarios:
            by_scenario[sid].append(nodeid)
    for sid, nodeids in by_scenario.items():
        if sid in matrix.scenarios:
            matrix.scenarios[sid].tests = tuple(sorted(set(nodeids)))

    accepted_by: dict[str, list[str]] = defaultdict(list)
    for story, accepted_sids in sorted(matrix.story_acceptance.items()):
        for sid in accepted_sids:
            accepted_by[sid].append(story)
    for sid, owners in accepted_by.items():
        if sid in matrix.scenarios:
            matrix.scenarios[sid].accepted_by = tuple(sorted(set(owners)))

    matrix.findings.extend(_check(matrix, features_dir, module_citations, by_scenario))

    if collection_supplied:
        matrix.findings.append(
            Finding(
                kind="UNVERIFIED_COLLECTION",
                severity=Severity.HIGH,
                subject="pytest collection",
                location=str(repo_root),
                detail=f"{len(node_ids)} node id(s) were supplied rather than collected by "
                       f"this run; they are linked and published but do not clear a "
                       f"scenario's missing-test finding",
            )
        )

    matrix.findings.extend(_check_corpus(matrix, corpus_floor))

    if regression_gate:
        seen: set[tuple[str, str]] = set()
        for base, description in ((baseline, baseline_description), *extra_baselines):
            for finding in _check_regressions(matrix, base, description):
                if (finding.kind, finding.subject) in seen:
                    continue
                seen.add((finding.kind, finding.subject))
                matrix.findings.append(finding)
    matrix.findings.sort(key=Finding.sort_key)
    matrix.summary = _summarise(matrix)
    return matrix


def _check(
    matrix: Matrix,
    features_dir: Path | None,
    module_citations: dict[str, tuple[str, ...]],
    by_scenario: dict[str, list[str]],
) -> list[Finding]:
    findings: list[Finding] = []
    known = set(matrix.requirements)

    def retired(subject: str, location: str, detail: str) -> None:
        findings.append(
            Finding(
                kind="RETIRED_REQUIREMENT_REF",
                severity=Severity.CRITICAL,
                subject=subject,
                location=location,
                detail=detail,
            )
        )

    # The reverse case, from every direction something can cite an ID.
    for sid, scenario in sorted(matrix.scenarios.items()):
        for ref in scenario.refs:
            if ref not in known:
                retired(ref, f"{scenario.doc}:{scenario.line}", f"cited by scenario {sid}")
    for nodeid, test in sorted(matrix.tests.items()):
        for ref in test.citations:
            if ref not in known:
                retired(ref, nodeid, "cited by a test")
    for rel, refs in sorted(module_citations.items()):
        for ref in refs:
            if ref not in known:
                retired(ref, rel, "cited at module level in a test file")
    for aid, assertion in sorted(matrix.assertions.items()):
        for ref in assertion.basis:
            if ref not in known:
                retired(ref, f"{assertion.doc}:{assertion.line}", f"basis of assertion {aid}")
    for story, rids in sorted(matrix.stories.items()):
        for rid in rids:
            if rid not in known:
                retired(rid, "prd.md", f"claimed by story {story} under Satisfies")

    # Assertions.
    for aid, assertion in sorted(matrix.assertions.items()):
        live = [r for r in assertion.basis if r in known]
        if not live:
            findings.append(
                Finding(
                    kind="ASSERTION_NO_REQUIREMENT",
                    severity=Severity.CRITICAL,
                    subject=aid,
                    location=f"{assertion.doc}:{assertion.line}",
                    detail="no requirement in the Basis column resolves; AR-003 closes the "
                           "catalogue, so this assertion must not be emitted",
                )
            )
            continue
        if not any(matrix.requirements[r].scenarios for r in live):
            findings.append(
                Finding(
                    kind="ASSERTION_NO_SCENARIO",
                    severity=Severity.CRITICAL,
                    subject=aid,
                    location=f"{assertion.doc}:{assertion.line}",
                    detail="no basis requirement has a scenario ("
                           + ", ".join(live)
                           + "); nothing demonstrates this claim, and an exempt "
                             "requirement cannot stand in for one",
                )
            )

    # Scenario reference lists. extract_features.py emits one Gherkin tag per
    # comma-separated part, so a part that is not a bare requirement ID becomes
    # a tag containing whitespace and Gherkin refuses the entire feature file.
    # Nothing catches that today: --check compares generated bytes against disk
    # and is happy, and no step definition binds to the broken feature, so it
    # stays green until someone tries to use it.
    for sid, scenario in sorted(matrix.scenarios.items()):
        for part in scenario.raw_refs:
            if not REQ_TOKEN.fullmatch(part):
                findings.append(
                    Finding(
                        kind="MALFORMED_SCENARIO_REF",
                        severity=Severity.HIGH,
                        subject=sid,
                        location=f"{scenario.doc}:{scenario.line}",
                        detail=f"reference {part!r} is not a bare requirement ID; it becomes "
                               f"the Gherkin tags {' '.join('@' + t for t in part.split())}, "
                               f"and a tag with whitespace makes the generated feature "
                               f"unparseable",
                    )
                )

    # Acceptance fields are the ownership map for scenarios. A misspelt or
    # retired scenario there is a broken story contract, not harmless prose.
    for story, sids in sorted(matrix.story_acceptance.items()):
        for sid in sids:
            if sid not in matrix.scenarios:
                findings.append(
                    Finding(
                        kind="RETIRED_SCENARIO_REF",
                        severity=Severity.CRITICAL,
                        subject=sid,
                        location=matrix.story_definitions.get(story, "prd.md"),
                        detail=f"story {story} lists a scenario no document defines",
                    )
                )

    # Scenarios. Missing tests are not one class of debt: a landed story that
    # omitted declared acceptance is a defect; an unlanded story is roadmap
    # debt; and no Acceptance owner at all is a triage failure.
    landed = set(matrix.landed_stories)
    for sid, scenario in sorted(matrix.scenarios.items()):
        if scenario.tests and not matrix.collection_supplied:
            # Demonstrated, so none of the missing-test classification below
            # applies -- but ownership is a separate record from demonstration,
            # and until this check existed a scenario with a test could sit in
            # no story's Acceptance field and produce no finding at all. That is
            # how EV-22's own Acceptance field came to omit QA-S-006, QA-S-007
            # and QA-S-008: the tool built to find unowned scenarios only looked
            # at the untested ones, so its own gap was in its blind spot.
            #
            # Medium, not high: the claim is demonstrated and only the ownership
            # record is missing, so this clears on 1 October with the rest of the
            # triage backlog rather than on EV-26's 1 September stage.
            if not scenario.accepted_by:
                findings.append(
                    Finding(
                        kind="SCENARIO_UNOWNED",
                        severity=Severity.MEDIUM,
                        subject=sid,
                        location=f"{scenario.doc}:{scenario.line}",
                        detail="a test implements this scenario but no story lists it under "
                               "Acceptance, so nothing records which story it belongs to",
                    )
                )
            continue
        # A collection this run did not perform cannot clear the finding. The
        # node ids are still linked and published, so the chain is visible, but
        # a file of node ids handed in on the command line is an assertion by
        # the caller, and accepting it here would let any scenario be marked
        # demonstrated by writing a line of text.
        why = (
            "the only implementing tests came from a caller-supplied collection this run "
            "did not perform"
            if scenario.tests
            else "no collected test implements this scenario"
        )
        landed_owners = tuple(owner for owner in scenario.accepted_by if owner in landed)
        if landed_owners:
            kind, severity = "SCENARIO_NO_TEST_LANDED", Severity.HIGH
            detail = f"{why}; accepted by landed story {', '.join(landed_owners)}"
        elif scenario.accepted_by:
            kind, severity = "SCENARIO_NO_TEST_UNBUILT", Severity.MEDIUM
            detail = f"{why}; owned by unlanded story {', '.join(scenario.accepted_by)}"
        else:
            kind, severity = "SCENARIO_NO_TEST_UNOWNED", Severity.HIGH
            detail = f"{why}, and no story lists this scenario under Acceptance"
        findings.append(
            Finding(
                kind=kind,
                severity=severity,
                subject=sid,
                location=f"{scenario.doc}:{scenario.line}",
                detail=detail,
            )
        )

    # Tests naming a scenario that does not exist.
    for sid, nodeids in sorted(by_scenario.items()):
        if sid not in matrix.scenarios:
            findings.append(
                Finding(
                    kind="RETIRED_SCENARIO_REF",
                    severity=Severity.CRITICAL,
                    subject=sid,
                    location=", ".join(sorted(nodeids)),
                    detail="a test names a scenario no document defines",
                )
            )

    # Feature tags versus the owning document.
    if features_dir is not None:
        feature_tags = _parse_feature_tags(features_dir)
        # The check used to run in one direction only: every tag had to resolve
        # to a document. Nothing asked whether every documented scenario reached
        # the generated suite, so pointing `--features` at a directory with no
        # feature files in it removed every finding on this axis and added none.
        # An input that can only subtract findings is a bypass whatever it is
        # called, so the reverse direction is a finding of its own -- a scenario
        # absent from the suite is one no test can bind to.
        for sid, scenario in sorted(matrix.scenarios.items()):
            if sid not in feature_tags:
                findings.append(
                    Finding(
                        kind="FEATURE_TAG_MISSING",
                        severity=Severity.HIGH,
                        subject=sid,
                        location=f"{scenario.doc}:{scenario.line}",
                        detail=f"no generated feature under {features_dir} tags this scenario, "
                               f"so no pytest-bdd test can bind to it",
                    )
                )
        for sid, refs in sorted(feature_tags.items()):
            scenario = matrix.scenarios.get(sid)
            if scenario is None:
                findings.append(
                    Finding(
                        kind="RETIRED_SCENARIO_REF",
                        severity=Severity.CRITICAL,
                        subject=sid,
                        location=str(features_dir),
                        detail="a generated feature tags a scenario no document defines",
                    )
                )
                continue
            if set(refs) != set(scenario.refs):
                findings.append(
                    Finding(
                        kind="FEATURE_TAG_DRIFT",
                        severity=Severity.HIGH,
                        subject=sid,
                        location=f"{scenario.doc}:{scenario.line}",
                        detail=f"document says {', '.join(scenario.refs) or '(none)'}; "
                               f"feature file says {', '.join(refs) or '(none)'}",
                    )
                )

    # Requirements.
    for rid, req in sorted(matrix.requirements.items()):
        if req.scenarios:
            continue
        exemption = req.exemption
        if exemption is not None and exemption.category != "deferred":
            continue
        if exemption is not None and exemption.category == "deferred":
            if exemption.story is None:
                findings.append(
                    Finding(
                        kind="DEFERRED_UNASSIGNED",
                        severity=Severity.MEDIUM,
                        subject=rid,
                        location=exemption.source,
                        detail="deferred with no owning story",
                    )
                )
            continue
        if req.claimed_by:
            kind, severity = "REQUIREMENT_NO_SCENARIO_CLAIMED", Severity.HIGH
            detail = f"claimed by {', '.join(req.claimed_by)} with no scenario and no exemption"
        elif req.prefix in SPEC_PREFIXES:
            kind, severity = "REQUIREMENT_NO_SCENARIO_SPEC", Severity.MEDIUM
            detail = "specification requirement with no scenario and no exemption"
        else:
            kind, severity = "REQUIREMENT_NO_SCENARIO_OTHER", Severity.LOW
            detail = "process requirement with no scenario and no exemption"
        findings.append(
            Finding(
                kind=kind,
                severity=severity,
                subject=rid,
                location=f"{req.doc}:{req.line}",
                detail=detail,
            )
        )

    return findings


# How much of the last known good corpus a run must still be able to read
# before its verdict means anything. Not 1.0: requirements are retired
# legitimately, and a floor that fires on every deletion is a floor someone
# raises rather than one that holds. Not much below it either -- a tenth of the
# corpus vanishing between the merge base and here is a redirected `--docs`, a
# half-copied checkout or a renamed directory far more often than it is a day's
# editing, and all three of those read as "clean" without this.
CORPUS_FLOOR_NUMERATOR = 9
CORPUS_FLOOR_DENOMINATOR = 10


def _check_corpus(matrix: Matrix, floor: dict[str, int] | None) -> list[Finding]:
    """CM-001 and CM-009, applied to the generator itself.

    An empty corpus is the shape every bypass in this file eventually takes:
    point the tool somewhere with nothing in it and every finding disappears at
    once, leaving an exit status of 0 that reads exactly like a clean run. Zero
    requirements is an unknown, not a pass. The coverage engine is not allowed
    to report 0% when it cannot enumerate the population, and neither is this.

    `floor` is the corpus size at the merge base -- the last state the
    integration branch was known good at. `None` means it could not be read,
    which is already reported and blocking as BASELINE_UNAVAILABLE; there is no
    second complaint about the same missing history.
    """
    findings: list[Finding] = []
    if not matrix.requirements:
        findings.append(
            Finding(
                kind="CORPUS_UNAVAILABLE",
                severity=Severity.CRITICAL,
                subject="requirements",
                location="the documents this run was pointed at",
                detail="no requirement definitions were read at all. Cannot establish: a "
                       "corpus with nothing in it produces no findings, and no findings is "
                       "not the same answer as no problems",
            )
        )
    if floor is None:
        return findings
    for dimension, current in (
        ("requirements", len(matrix.requirements)),
        ("assertions", len(matrix.assertions)),
    ):
        previous = floor.get(dimension, 0)
        # Compare the ratio exactly. Truncating `previous * 0.9` made a floor of
        # 11 accept 9 (81.8%), because int(9.9) became 9 before comparison.
        below_floor = (
            current * CORPUS_FLOOR_DENOMINATOR
            < previous * CORPUS_FLOOR_NUMERATOR
        )
        threshold = (
            previous * CORPUS_FLOOR_NUMERATOR + CORPUS_FLOOR_DENOMINATOR - 1
        ) // CORPUS_FLOOR_DENOMINATOR
        if previous and below_floor:
            findings.append(
                Finding(
                    kind="CORPUS_UNAVAILABLE",
                    severity=Severity.CRITICAL,
                    subject=dimension,
                    location="the documents this run was pointed at",
                    detail=f"read {current} {dimension} against {previous} at the baseline, "
                           f"below the floor of {threshold}. Cannot establish: this run is "
                           f"not looking at the corpus the last known good run looked at",
                )
            )
    return findings


def _check_regressions(
    matrix: Matrix,
    baseline: dict[str, CatalogueEntry] | None,
    description: str,
) -> list[Finding]:
    """QA-S-001: a newly unmapped assertion fails CI now, not on a schedule.

    "Newly unmapped" is either of:

      - an assertion id that did not exist at the baseline, or
      - an existing id whose Basis column changed.

    The second case matters as much as the first. Without it, re-pointing an
    assertion at a requirement with no scenario would slip through as backlog,
    and the gate would be one rename away from useless. Comparing the basis
    rather than the baseline's whole scenario graph keeps this cheap: an
    assertion whose id and basis are both unchanged and unmapped was already
    unmapped, and is exactly what QA-011 stages.
    """
    if baseline is None:
        return [
            Finding(
                kind="BASELINE_UNAVAILABLE",
                severity=Severity.CRITICAL,
                subject="assertion catalogue",
                location=description,
                detail="cannot tell a new unmapped assertion from existing backlog without "
                       "the previous catalogue. Fetch enough history for the baseline ref "
                       "(actions/checkout needs fetch-depth: 0). "
                       "Not assumed clean: that is how this gate would stop working quietly",
            )
        ]

    unmapped = {
        f.subject for f in matrix.findings
        if f.kind in ("ASSERTION_NO_SCENARIO", "ASSERTION_NO_REQUIREMENT")
    }
    findings: list[Finding] = []
    for aid in sorted(unmapped):
        assertion = matrix.assertions.get(aid)
        if assertion is None:
            continue
        was = baseline.get(aid)
        if was is None:
            why = "added to the catalogue"
        elif was.basis != assertion.basis:
            why = (
                f"basis changed from {', '.join(was.basis) or '(none)'} to "
                f"{', '.join(assertion.basis) or '(none)'}"
            )
        elif was.text != assertion.text:
            why = (
                f"claim text changed from {was.text!r} to {assertion.text!r}; the same "
                f"basis now carries a different claim"
            )
        else:
            continue  # unmapped before this change: QA-011 backlog, staged.
        findings.append(
            Finding(
                kind="NEW_ASSERTION_NO_SCENARIO",
                severity=Severity.CRITICAL,
                subject=aid,
                location=f"{assertion.doc}:{assertion.line}",
                detail=f"{why} and nothing demonstrates it (baseline: {description}). "
                       f"QA-S-001: this fails CI now. QA-011 stages the existing backlog, "
                       f"it does not stage making the backlog bigger",
            )
        )
    return findings


def _summarise(matrix: Matrix) -> dict[str, Any]:
    exempt_ids, deferred_ids = [], []
    by_category: dict[str, int] = defaultdict(int)
    by_story: dict[str, int] = defaultdict(int)
    for rid, req in sorted(matrix.requirements.items()):
        if req.exemption is None:
            continue
        if req.exemption.category == "deferred":
            deferred_ids.append(rid)
            by_story[req.exemption.story or "unassigned"] += 1
        else:
            exempt_ids.append(rid)
            by_category[req.exemption.category] += 1

    traced = [r for r in matrix.requirements.values() if r.scenarios]
    by_severity: dict[str, int] = defaultdict(int)
    by_kind: dict[str, int] = defaultdict(int)
    for finding in matrix.findings:
        by_severity[finding.severity.value] += 1
        by_kind[finding.kind] += 1

    return {
        "requirements": len(matrix.requirements),
        "requirements_with_scenario": len(traced),
        "scenarios": len(matrix.scenarios),
        "scenarios_with_test": sum(1 for s in matrix.scenarios.values() if s.tests),
        "tests": len(matrix.tests),
        "assertions": len(matrix.assertions),
        "stories": len(matrix.stories),
        "landed_stories": list(matrix.landed_stories),
        "excluded_citation_paths": list(matrix.excluded_citation_paths),
        "exempt": len(exempt_ids),
        "exempt_ids": exempt_ids,
        "exempt_by_category": dict(sorted(by_category.items())),
        "deferred": len(deferred_ids),
        "deferred_ids": deferred_ids,
        "deferred_by_story": dict(sorted(by_story.items())),
        "findings": len(matrix.findings),
        "findings_by_severity": {
            s.value: by_severity.get(s.value, 0) for s in Severity
        },
        "findings_by_kind": dict(sorted(by_kind.items())),
    }


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def _cell(text: str, limit: int = 110) -> str:
    text = text.replace("|", "\\|")
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _short(nodeid: str) -> str:
    return nodeid.split("::", 1)[1] if "::" in nodeid else nodeid


def render_markdown(matrix: Matrix) -> str:
    s = matrix.summary
    out: list[str] = []
    add = out.append

    add("# Traceability matrix")
    add("")
    add("**Generated — do not edit.** Regenerate with "
        "`python -m tests.traceability.matrix` (QA-012).")
    add("")
    add("## How to read this")
    add("")
    add("Every requirement in the specification should be demonstrated by an executable")
    add("scenario, that scenario should be implemented by a test, and every claim an")
    add("attestation is allowed to make should rest on a requirement that is itself")
    add("demonstrated. That is the four-link chain QA-010 requires:")
    add("")
    add("```")
    add("requirement ID  →  scenario ID  →  test ID  →  assertion ID")
    add("   CM-008       →   CM-S-004    →  test_lattice_caps_level  →  A-06")
    add("```")
    add("")
    add("A requirement that genuinely cannot carry a scenario — a process rule, a")
    add("statement about what a document says — may be marked non-testable in the")
    add("document that defines it, with a written reason. Those markings are listed in")
    add("full below rather than subtracted from a total: an exemption you can see and")
    add("argue with is honest, one that has been netted off is not.")
    add("")

    add("## Summary")
    add("")
    add("| | Count |")
    add("|---|---|")
    add(f"| Requirements | {s['requirements']} |")
    add(f"| — with a scenario | {s['requirements_with_scenario']} |")
    add(f"| — marked non-testable | {s['exempt']} |")
    add(f"| — deferred to a later story | {s['deferred']} |")
    add(f"| — neither (orphans) | "
        f"{s['requirements'] - s['requirements_with_scenario'] - s['exempt'] - s['deferred']} |")
    add(f"| Scenarios | {s['scenarios']} |")
    add(f"| — with a test | {s['scenarios_with_test']} |")
    add(f"| Tests collected | {s['tests']} |")
    add(f"| Assertions in the catalogue | {s['assertions']} |")
    add(f"| Stories with a Satisfies field | {s['stories']} |")
    add(f"| — landed in reachable history | {len(s['landed_stories'])} |")
    add("")
    if s["excluded_citation_paths"]:
        add("One exclusion applies, stated here rather than buried in configuration: "
            "requirement")
        add("IDs written in "
            + ", ".join(f"`{p}`" for p in s["excluded_citation_paths"])
            + " are not read as citations. That file is this")
        add("generator's own test suite and names deliberately fictional requirements as")
        add("fixture data. Its tests are collected and counted like any others.")
        add("")

    add("## Findings")
    add("")
    if not matrix.findings:
        add("None.")
        add("")
    else:
        counts = s["findings_by_severity"]
        add(f"{s['findings']} total — "
            + ", ".join(f"{counts[k.value]} {k.value}" for k in Severity if counts[k.value]))
        add("")
        for severity in Severity:
            group = [f for f in matrix.findings if f.severity is severity]
            if not group:
                continue
            add(f"### {severity.value.capitalize()} ({len(group)})")
            add("")
            for kind in sorted({f.kind for f in group}):
                rows = [f for f in group if f.kind == kind]
                add(f"**{kind}** — {FINDING_HELP.get(kind, '')} ({len(rows)})")
                add("")
                add("| Subject | Where | Detail |")
                add("|---|---|---|")
                for finding in rows:
                    add(f"| `{finding.subject}` | `{_cell(finding.location, 70)}` "
                        f"| {_cell(finding.detail)} |")
                add("")

    add("## Exemptions")
    add("")
    add(f"{s['exempt']} requirements are marked non-testable. Each one is a claim that no")
    add("scenario is possible, made in the document that defines the requirement.")
    add("")
    if s["exempt_by_category"]:
        add("| Category | Count |")
        add("|---|---|")
        for category, count in s["exempt_by_category"].items():
            add(f"| {category} | {count} |")
        add("")
    if s["exempt"]:
        add("| Requirement | Category | Reason | Source |")
        add("|---|---|---|---|")
        for rid in s["exempt_ids"]:
            e = matrix.requirements[rid].exemption
            assert e is not None
            source = e.source + (" (document default)" if e.inherited_from else "")
            add(f"| `{rid}` | {e.category} | {_cell(e.reason, 160)} | `{source}` |")
        add("")

    add("## Deferred")
    add("")
    add(f"{s['deferred']} requirements are testable in principle and have no scenario yet.")
    add("This is debt, not an exemption, and is reported separately so it cannot be")
    add("mistaken for one.")
    add("")
    if s["deferred"]:
        add("| Requirement | Owed by | Reason | Source |")
        add("|---|---|---|---|")
        for rid in s["deferred_ids"]:
            e = matrix.requirements[rid].exemption
            assert e is not None
            add(f"| `{rid}` | {e.story or '**unassigned**'} | {_cell(e.reason, 160)} "
                f"| `{e.source}` |")
        add("")

    add("## Assertion coverage")
    add("")
    add("Every claim an attestation may make, and what demonstrates it.")
    add("")
    add("| Assertion | Claim | Basis | Scenarios | Tests |")
    add("|---|---|---|---|---|")
    for aid, assertion in sorted(matrix.assertions.items()):
        sids: list[str] = []
        for rid in assertion.basis:
            req = matrix.requirements.get(rid)
            if req:
                sids.extend(req.scenarios)
        nodeids = sorted(
            {n for sid in sids for n in matrix.scenarios[sid].tests if sid in matrix.scenarios}
        )
        add(f"| `{aid}` | {_cell(assertion.text, 70)} "
            f"| {', '.join(f'`{b}`' for b in assertion.basis) or '**none**'} "
            f"| {', '.join(f'`{x}`' for x in sorted(set(sids))) or '**none**'} "
            f"| {len(nodeids)} |")
    add("")

    add("## Matrix")
    add("")
    add("One row per requirement, in ID order. `Status` is `traced` when a scenario")
    add("exists, `exempt` when it is marked non-testable, `deferred` when a story owes")
    add("one, and `ORPHAN` when it is none of those.")
    add("")
    add("| Requirement | Status | Requirement text | Scenarios | Tests | Assertions | Stories |")
    add("|---|---|---|---|---|---|---|")
    assertions_by_req: dict[str, list[str]] = defaultdict(list)
    for aid, assertion in sorted(matrix.assertions.items()):
        for rid in assertion.basis:
            assertions_by_req[rid].append(aid)
    for rid, req in sorted(matrix.requirements.items()):
        if req.scenarios:
            status = "traced"
        elif req.exemption is None:
            status = "**ORPHAN**"
        elif req.exemption.category == "deferred":
            status = "deferred"
        else:
            status = f"exempt ({req.exemption.category})"
        nodeids = sorted({n for sid in req.scenarios for n in matrix.scenarios[sid].tests})
        add(
            f"| `{rid}` | {status} | {_cell(req.text, 90)} "
            f"| {', '.join(f'`{x}`' for x in req.scenarios) or '—'} "
            f"| {', '.join(f'`{_short(n)}`' for n in nodeids) or '—'} "
            f"| {', '.join(f'`{a}`' for a in assertions_by_req.get(rid, [])) or '—'} "
            f"| {', '.join(f'`{x}`' for x in req.claimed_by) or '—'} |"
        )
    add("")

    add("## How each scenario is demonstrated")
    add("")
    add("`pytest-bdd` means the test executes the scenario's documented Given/When/Then")
    add("steps. `test name` and `cited in body` mean the test asserts the same behaviour")
    add("and its author says so, but the documented steps are not what runs. Both are")
    add("real links; they are not equally strong, and an auditor should not have to guess")
    add("which kind they are reading.")
    add("")
    add("| Scenario | Test | Link |")
    add("|---|---|---|")
    for sid, scenario in sorted(matrix.scenarios.items()):
        for nodeid in scenario.tests:
            kind = dict(matrix.tests[nodeid].link_kind).get(sid, "unknown")
            add(f"| `{sid}` | `{_cell(_short(nodeid), 70)}` | {kind} |")
    if not any(s2.tests for s2 in matrix.scenarios.values()):
        add("| — | — | — |")
    add("")

    add("## Scenarios without a test")
    add("")
    untested = [s2 for s2 in matrix.scenarios.values() if not s2.tests]
    if not untested:
        add("None.")
    else:
        add("| Scenario | Title | Source | Requirements | Acceptance owner |")
        add("|---|---|---|---|---|")
        for scenario in sorted(untested, key=lambda x: x.sid):
            add(f"| `{scenario.sid}` | {_cell(scenario.title, 70)} "
                f"| `{scenario.doc}:{scenario.line}` "
                f"| {', '.join(f'`{r}`' for r in scenario.refs) or '—'} "
                f"| {', '.join(f'`{s}`' for s in scenario.accepted_by) or '**unowned**'} |")
    add("")
    return "\n".join(out) + "\n"


def render_json(matrix: Matrix) -> str:
    payload: dict[str, Any] = {
        "schema": "traceability-matrix/1",
        "summary": matrix.summary,
        "requirements": [
            {
                "id": rid,
                "document": req.doc,
                "line": req.line,
                "text": req.text,
                "scenarios": list(req.scenarios),
                "tests": sorted({n for sid in req.scenarios for n in matrix.scenarios[sid].tests}),
                "claimed_by": list(req.claimed_by),
                "exemption": (
                    None
                    if req.exemption is None
                    else {
                        "category": req.exemption.category,
                        "story": req.exemption.story,
                        "reason": req.exemption.reason,
                        "source": req.exemption.source,
                        "inherited_from": req.exemption.inherited_from,
                    }
                ),
            }
            for rid, req in sorted(matrix.requirements.items())
        ],
        "scenarios": [
            {
                "id": sid,
                "title": scenario.title,
                "document": scenario.doc,
                "line": scenario.line,
                "requirements": list(scenario.refs),
                "tests": list(scenario.tests),
                "accepted_by": list(scenario.accepted_by),
                "link_kind": {
                    nodeid: dict(matrix.tests[nodeid].link_kind).get(sid, "unknown")
                    for nodeid in scenario.tests
                },
            }
            for sid, scenario in sorted(matrix.scenarios.items())
        ],
        "tests": [
            {
                "id": nodeid,
                "file": test.file,
                "scenarios": list(test.scenarios),
                "link_kind": dict(test.link_kind),
                "requirements": list(test.citations),
            }
            for nodeid, test in sorted(matrix.tests.items())
        ],
        "assertions": [
            {
                "id": aid,
                "claim": assertion.text,
                "basis": list(assertion.basis),
                "document": assertion.doc,
                "line": assertion.line,
            }
            for aid, assertion in sorted(matrix.assertions.items())
        ],
        "exemptions": [
            {
                "requirement": rid,
                "category": matrix.requirements[rid].exemption.category,  # type: ignore[union-attr]
                "story": matrix.requirements[rid].exemption.story,  # type: ignore[union-attr]
                "reason": matrix.requirements[rid].exemption.reason,  # type: ignore[union-attr]
                "source": matrix.requirements[rid].exemption.source,  # type: ignore[union-attr]
                "inherited_from": (
                    matrix.requirements[rid].exemption.inherited_from  # type: ignore[union-attr]
                ),
            }
            for rid in matrix.summary["exempt_ids"]
        ],
        "deferred": [
            {
                "requirement": rid,
                "story": matrix.requirements[rid].exemption.story,  # type: ignore[union-attr]
                "reason": matrix.requirements[rid].exemption.reason,  # type: ignore[union-attr]
                "source": matrix.requirements[rid].exemption.source,  # type: ignore[union-attr]
            }
            for rid in matrix.summary["deferred_ids"]
        ],
        "stories": {story: list(rids) for story, rids in sorted(matrix.stories.items())},
        "story_acceptance": {
            story: list(sids) for story, sids in sorted(matrix.story_acceptance.items())
        },
        "landed_stories": list(matrix.landed_stories),
        "findings": [
            {
                "kind": f.kind,
                "severity": f.severity.value,
                "subject": f.subject,
                "location": f.location,
                "detail": f.detail,
            }
            for f in matrix.findings
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=False, ensure_ascii=False) + "\n"


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _print_report(matrix: Matrix) -> None:
    s = matrix.summary
    orphans = (
        s["requirements"] - s["requirements_with_scenario"] - s["exempt"] - s["deferred"]
    )
    print("Traceability matrix")
    print(f"  requirements       {s['requirements']:4}  "
          f"({s['requirements_with_scenario']} traced, {s['exempt']} exempt, "
          f"{s['deferred']} deferred, {orphans} orphaned)")
    print(f"  scenarios          {s['scenarios']:4}  ({s['scenarios_with_test']} with a test)")
    print(f"  tests collected    {s['tests']:4}")
    print(f"  assertions         {s['assertions']:4}")
    if s["excluded_citation_paths"]:
        print("  citations not read from: " + ", ".join(s["excluded_citation_paths"]))
    # QA-011: the orphan count and the severity breakdown print on every build,
    # at every stage, enforced or not. Staging changes what fails, never what is
    # reported.
    print()
    print(f"Orphans: {orphans} requirement(s) with no scenario and no exemption.")
    counts = s["findings_by_severity"]
    print("Findings: " + ", ".join(f"{counts[k.value]} {k.value}" for k in Severity))
    print()
    if not matrix.findings:
        print("No findings.")
        return
    for severity in Severity:
        group = [f for f in matrix.findings if f.severity is severity]
        if not group:
            continue
        print(f"-- {severity.value.upper()} ({len(group)})")
        for finding in group:
            print(f"   {finding.kind:32} {finding.subject:10} {finding.location}")
        print()


def main(
    argv: list[str] | None = None,
    *,
    real_today: date | None = None,
    baseline_ref: str = DEFAULT_BASELINE_REF,
    today: date | None = None,
) -> int:
    """The invariant, stated once: **no input the caller controls may produce a
    more permissive verdict than the default invocation.**

    That is a property over the whole argument space, not a claim about the list
    of flags that happen to exist today, and
    `tests/traceability/test_argument_space.py` asserts it as one. Deleting
    flags was the previous three attempts at this, and each time the next
    review found the knob that had been kept because *this* one was obviously
    safe. So the flags stay and every one of them is closed by construction:

      --mode, --fail-on      may only strengthen the QA-011 schedule
      --exclude-citations    adds to the defaults. A caller-added exclusion
                             withholds the verdict because it can hide an
                             invalid citation as well as remove a valid one.
      --collect-from         reported, never clears a missing-test finding, and
                             withholds the verdict: an omitted node can hide a
                             retired citation even when fabricated nodes do not
                             clear scenarios.
      --docs, --features,    redirected inputs withhold the verdict. The corpus
      --repo-root, --tests   floor additionally catches an empty or implausibly
                             shrunken default corpus.
      --out-md, --out-json   output only

    The keyword-only parameters below are Python-callable seams and are closed
    the same way, because reachable-only-from-Python is not closed:

      real_today   forward-only. mandated_threshold() is monotone in the date,
                   so the effective calendar is max(UTC today, supplied). A
                   past date is ignored; a future one rehearses a later stage.
      today        forward-only, by the same rule.
      baseline_ref additive. DEFAULT_BASELINE_REF is always evaluated; a
                   supplied ref adds a second comparison and the findings are
                   unioned. Pointing it at HEAD no longer suppresses anything,
                   because it no longer replaces anything.

    `regression_gate` is gone from this function entirely. It was the last
    parameter whose only effect was to make the build greener, and there is no
    version of that which is safe. `build_matrix()` still has it, because a
    library caller assembling a matrix over a corpus with no history is asking a
    different question from the one the exit status answers.
    """
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    ap.add_argument("--repo-root", type=Path, default=Path.cwd())
    ap.add_argument("--docs", type=Path, default=None, help="default <repo-root>/docs")
    ap.add_argument("--features", type=Path, default=None,
                    help="default <repo-root>/tests/features")
    ap.add_argument("--tests", default="tests", help="what to hand pytest --collect-only")
    ap.add_argument("--collect-from", type=Path, default=None,
                    help="read node ids from a file instead of running pytest; the report "
                         "is diagnostic and its verdict is withheld")
    ap.add_argument("--exclude-citations", action="append", default=None,
                    metavar="PREFIX",
                    help="an ADDITIONAL path prefix whose tests are collected but whose "
                         "requirement IDs are not read as citations. Adds to the built-in "
                         "defaults, never replaces them; caller-added exclusions produce a "
                         "diagnostic report whose verdict is withheld")
    ap.add_argument("--out-md", type=Path, default=None)
    ap.add_argument("--out-json", type=Path, default=None)
    ap.add_argument("--mode", choices=("report", "enforce"), default="report",
                    help="report exits 0; enforce exits 1 on findings. Either way the "
                         "QA-011 schedule applies once its dates pass, and a request "
                         "weaker than the schedule mandates is overridden")
    ap.add_argument("--fail-on", choices=[s.value for s in Severity], default="low",
                    help="in enforce mode, the least severe finding that fails the build. "
                         "May only strengthen the QA-011 schedule, never weaken it")
    args = ap.parse_args(argv)

    root = args.repo_root.resolve()
    docs = args.docs or root / "docs"
    features = args.features or root / "tests" / "features"

    # Redirecting an observation asks a different question from main([]). A
    # count floor catches empty and truncated document corpora, but it cannot
    # prove equivalence for a same-sized alternate corpus, a different feature
    # tree, a subset of tests, or an exclusion that hides a retired citation.
    # Keep producing the report -- it is useful diagnostic evidence -- but do
    # not certify it as comparable with the default invocation.
    default_root = Path.cwd().resolve()
    unverified_inputs: list[str] = []
    if root != default_root:
        unverified_inputs.append(f"--repo-root={root}")
    if docs.resolve() != (root / "docs").resolve():
        unverified_inputs.append(f"--docs={docs.resolve()}")
    if features.resolve() != (root / "tests" / "features").resolve():
        unverified_inputs.append(f"--features={features.resolve()}")
    if args.tests != "tests":
        unverified_inputs.append(f"--tests={args.tests}")
    if args.exclude_citations:
        unverified_inputs.extend(
            f"--exclude-citations={prefix}" for prefix in args.exclude_citations
        )

    collection_supplied = args.collect_from is not None
    if args.collect_from is not None:
        node_ids = sorted(
            {ln.strip() for ln in args.collect_from.read_text(encoding="utf-8").split()}
        )
    else:
        node_ids = collect_node_ids(root, args.tests)

    # Additive, not a replacement. Supplying a prefix used to discard the
    # built-in ones, so `--exclude-citations nothing/` re-enabled the fixture
    # IDs in test_matrix.py as real citations and quietly traced requirements
    # that nothing tests.
    exclude = tuple(
        {*DEFAULT_EXCLUDED_CITATION_PATHS, *(args.exclude_citations or ())}
    )

    ar_relpath = str(Path(docs.name) / "attestation-reliance.md")
    baseline, baseline_description = baseline_assertions(root, DEFAULT_BASELINE_REF, ar_relpath)
    extra_baselines: tuple[tuple[dict[str, CatalogueEntry] | None, str], ...] = ()
    if baseline_ref != DEFAULT_BASELINE_REF:
        extra_baselines = (baseline_assertions(root, baseline_ref, ar_relpath),)

    # The floor comes from the same commit the catalogue baseline does: the last
    # state the integration branch was known good at.
    # Always `docs`, never `docs.name`. The floor is the size of the corpus
    # this repository was last known good at, and that corpus lives at `docs/`.
    # Reading it from whatever directory `--docs` names would let the floor be
    # redirected alongside the thing it exists to bound: point both at a stub
    # and the stub is measured against itself, which is a pass by construction.
    base_commit, _ = merge_base(root, DEFAULT_BASELINE_REF)
    corpus_floor = None if base_commit is None else baseline_corpus(root, base_commit, "docs")

    matrix = build_matrix(
        repo_root=root,
        docs_dir=docs,
        features_dir=features,
        node_ids=node_ids,
        exclude_citations=exclude,
        baseline=baseline,
        baseline_description=baseline_description,
        extra_baselines=extra_baselines,
        regression_gate=True,
        collection_supplied=collection_supplied,
        corpus_floor=corpus_floor,
    )

    if unverified_inputs:
        matrix.findings.append(
            Finding(
                kind="UNVERIFIED_INPUTS",
                severity=Severity.CRITICAL,
                subject="redirected inputs",
                location=str(root),
                detail="cannot compare this run with the default invocation because the "
                       "caller redirected: " + ", ".join(unverified_inputs),
            )
        )
        matrix.findings.sort(key=Finding.sort_key)
        matrix.summary = _summarise(matrix)

    # The QA-011 ratchet, and the one place a date could ever weaken it.
    #
    # `mandated_threshold` is monotone in its argument -- a later date mandates
    # at least as much as an earlier one -- so "forward-only" is just `max`.
    # Both supplied dates go through it and neither can move the calendar
    # backwards. The calendar itself is UTC, not the process timezone: see
    # utc_today().
    calendar = utc_today()
    real = max(calendar, real_today) if real_today is not None else calendar
    asof = max(real, today) if today is not None else real

    requested = Severity(args.fail_on) if args.mode == "enforce" else None
    threshold, why = effective_threshold(requested, asof, real)

    # Written into the published matrix, not only printed: QA-010 says the chain
    # is evidence for an auditor, and a matrix that does not record which gate
    # it was evaluated under leaves them to guess.
    matrix.summary["enforcement"] = {
        "utc_today": calendar.isoformat(),
        "real": real.isoformat(),
        "as_of": asof.isoformat(),
        "requested": None if requested is None else requested.value,
        "threshold": None if threshold is None else threshold.value,
        "reason": why,
        "baseline": baseline_description,
        "collection_supplied": collection_supplied,
    }

    if args.out_md:
        args.out_md.parent.mkdir(parents=True, exist_ok=True)
        args.out_md.write_text(render_markdown(matrix), encoding="utf-8")
        print(f"wrote {args.out_md}")
    if args.out_json:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(render_json(matrix), encoding="utf-8")
        print(f"wrote {args.out_json}")

    _print_report(matrix)

    print(f"\nBaseline for the QA-S-001 regression gate: {baseline_description}.")
    for _, extra_description in extra_baselines:
        print(f"Additional baseline requested by the caller: {extra_description}. "
              f"Findings from both are unioned; a supplied ref adds a comparison and "
              f"never replaces the default one.")
    print(f"QA-011 enforcement as of {real.isoformat()} (UTC today is "
          f"{calendar.isoformat()}): {why}.")
    if asof != real:
        print(f"(evaluated as of {asof.isoformat()}; a supplied date may bring a stage "
              f"forward, never defer one.)")

    # QA-S-001 is not staged. A regression blocks whatever the schedule says.
    immediate = [f for f in matrix.findings if f.kind in ALWAYS_BLOCKING]
    staged = (
        []
        if threshold is None
        else [f for f in matrix.findings if SEVERITY_RANK[f.severity] <= SEVERITY_RANK[threshold]]
    )
    blocking = immediate + [f for f in staged if f.kind not in ALWAYS_BLOCKING]

    if immediate:
        print(f"\n{len(immediate)} finding(s) fail immediately, outside the QA-011 schedule:")
        for finding in immediate:
            print(f"   {finding.kind:28} {finding.subject:10} {finding.location}")
            print(f"      {finding.detail}")

    if blocking:
        print(f"\nFAIL: {len(blocking)} blocking finding(s) "
              f"({len(immediate)} immediate, {len(blocking) - len(immediate)} staged).")
        return 1
    if threshold is None:
        print("\nNo finding fails this build. Every finding above is still counted, named,")
        print("and written to the matrix. Next stage: critical from "
              f"{ENFORCEMENT_SCHEDULE[0][0].isoformat()}.")
        return 0
    print(f"\nOK: no finding at or above {threshold.value}, and no regression.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
