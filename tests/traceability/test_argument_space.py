"""The invariant, asserted as a property rather than argued from a flag list.

    No input the caller controls may produce a more permissive verdict than the
    default invocation.

Three reviews in a row found an off switch here, and each was closed by deleting
the flag that carried it: `--no-baseline`, then `--baseline-ref`, then
`--today`. Each removal was justified by an argument about the flag that had
just been removed, and each time the next review found the one that had been
kept because *that* one was obviously safe. Deleting flags is not the fix. The
fix is to state the property over the whole argument space and check it, so that
a flag added next year is covered by a test written this year.

What "more permissive" means
---------------------------
A run's verdict is the triple (exit status, enforced threshold, findings). A
variant is more permissive than the default if it exits 0 where the default
exits 1, if it enforces a weaker threshold, or if any finding the default
reported is missing from it. Anything else -- more findings, a stricter
threshold, the same verdict -- is fine.

Fail-closed is not permissive
-----------------------------
An input that redirects the corpus is asking a different question, and the
answer to a different question cannot be compared with the default's. Those
runs are required to say so: `CORPUS_UNAVAILABLE`, `BASELINE_UNAVAILABLE` or
`STORY_HISTORY_UNAVAILABLE`, and a non-zero exit. Reporting nothing found is
not permitted to look like finding nothing -- CM-001 and CM-009 say the same
thing about an unestablished denominator, and the generator is held to its own
methodology.

Speed
-----
`collect_node_ids` is stubbed so that a run does not spawn pytest, but the stub
still distinguishes "the tool collected this" from "the caller handed it in",
because that distinction is exactly what one of the properties turns on.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tests.traceability import matrix as matrix_module
from tests.traceability.corpus import commit_as_develop, git
from tests.traceability.matrix import (
    DEFAULT_BASELINE_REF,
    DEFAULT_EXCLUDED_CITATION_PATHS,
    Severity,
    main,
    strictness,
    utc_today,
)

# A run reporting one of these has declined to certify anything. It is the
# fail-closed answer, and it must also be a failing one.
CANNOT_ESTABLISH = frozenset(
    {
        "CORPUS_UNAVAILABLE",
        "BASELINE_UNAVAILABLE",
        "STORY_HISTORY_UNAVAILABLE",
        "UNVERIFIED_COLLECTION",
        "UNVERIFIED_INPUTS",
    }
)

REAL_NODE_IDS = ["tests/steps/test_probe_steps.py::test_cm_s_801_probe"]

# Node ids that would clear every scenario in the corpus if the tool believed a
# collection it did not perform. The names are chosen to link by function name
# as well as by decorator, so nothing here depends on which linking path runs.
FABRICATED_NODE_IDS = [
    "tests/steps/test_probe_steps.py::test_cm_s_801_probe",
    "tests/steps/test_invented.py::test_cm_s_802_invented",
]


DOCS_COVERAGE = """# Fixture corpus: coverage

**CM-801** — A requirement with a scenario and a test, so the default run has a
complete chain in it and a variant that loses the chain is visible.

**CM-802** — A requirement with a scenario and no test.

**CM-803** — A requirement with no scenario at all, so the default run has an
orphan finding a variant could try to hide.

**CM-804** — A requirement excused by a marking, so exemption parsing is
exercised on every variant rather than only on the default.

> **Non-testable — process.** Enforced by review rather than by executable
> behaviour, and this reason is long enough to satisfy the minimum.

### CM-S-801 — The demonstrated scenario *(CM-801)*

```gherkin
Given a denominator of class C5
When coverage is computed
Then no ratio is emitted
```

### CM-S-802 — The undemonstrated scenario *(CM-802)*

```gherkin
Given a scenario nobody has implemented
When the matrix is generated
Then the scenario is reported as untested
```
"""

DOCS_CATALOGUE = """# Fixture corpus: catalogue

## 2. Assertion catalogue

| ID | Assertion | Basis |
|---|---|---|
| **A-01** | A claim demonstrated all the way down | CM-801 |
| **A-02** | A claim resting on a requirement nothing demonstrates | CM-803 |
"""

DOCS_PRD = """# Fixture corpus: stories

#### EV-80 — The story that owns the demonstrated scenario
**Touches:** `nowhere/`
**Satisfies:** CM-801, CM-802
**Acceptance:** CM-S-801, CM-S-802
"""

FEATURE = """# GENERATED FILE -- DO NOT EDIT.

Feature: Coverage fixture

  @CM-S-801 @CM-801
  Scenario: CM-S-801 The demonstrated scenario
    Given a denominator of class C5
    When coverage is computed
    Then no ratio is emitted

  @CM-S-802 @CM-802
  Scenario: CM-S-802 The undemonstrated scenario
    Given a scenario nobody has implemented
    When the matrix is generated
    Then the scenario is reported as untested
"""

STEPS = '''"""Fixture step definitions. Read as source by the matrix, never executed.

CM-899 is deliberately retired. It makes citation exclusion and supplied
collection counterexamples observable: either input could hide this critical
finding if a fail-closed verdict did not cover the whole observation.
"""

from pytest_bdd import scenario


@scenario("coverage.feature", "CM-S-801 The demonstrated scenario")
def test_cm_s_801_probe() -> None:
    """Implements the demonstrated scenario."""
'''


@pytest.fixture(scope="module")
def corpus(tmp_path_factory) -> Path:
    """One repository, built once, that every variant is run against.

    The corpus is fixed on purpose. Varying the arguments over a moving corpus
    would compare two different questions and prove nothing about either.
    """
    root = tmp_path_factory.mktemp("argument_space")
    (root / "docs").mkdir()
    (root / "docs" / "coverage-methodology.md").write_text(DOCS_COVERAGE, encoding="utf-8")
    (root / "docs" / "attestation-reliance.md").write_text(DOCS_CATALOGUE, encoding="utf-8")
    (root / "docs" / "prd.md").write_text(DOCS_PRD, encoding="utf-8")
    (root / "tests" / "features").mkdir(parents=True)
    (root / "tests" / "features" / "coverage.feature").write_text(FEATURE, encoding="utf-8")
    (root / "tests" / "steps").mkdir(parents=True)
    (root / "tests" / "steps" / "test_probe_steps.py").write_text(STEPS, encoding="utf-8")

    # The inputs a variant may point at instead of the real ones.
    (root / "empty-docs").mkdir()
    (root / "stub-docs").mkdir()
    (root / "stub-docs" / "coverage-methodology.md").write_text(
        "# Stub\n\n**CM-801** — One requirement, so the corpus is not empty.\n",
        encoding="utf-8",
    )
    (root / "empty.txt").write_text("", encoding="utf-8")
    (root / "everything.txt").write_text("\n".join(FABRICATED_NODE_IDS), encoding="utf-8")
    (root / "real.txt").write_text("\n".join(REAL_NODE_IDS), encoding="utf-8")

    commit_as_develop(root, "argument-space corpus")
    return root


@pytest.fixture(autouse=True)
def _in_corpus(corpus: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Make `main([])` -- with no arguments at all -- the default invocation."""
    monkeypatch.chdir(corpus)

    def _collect(repo_root: Path, target: str = "tests") -> list[str]:
        if target != "tests" or not (Path(repo_root) / target).is_dir():
            raise SystemExit("pytest collected no tests; the matrix would be meaningless")
        return list(REAL_NODE_IDS)

    monkeypatch.setattr(matrix_module, "collect_node_ids", _collect)


@dataclass(frozen=True)
class Verdict:
    exit_code: int
    threshold: Severity | None
    findings: frozenset[tuple[str, str]]
    # The calendar the run actually ratcheted against, and the exclusions it
    # actually applied. Both are recorded in the published matrix rather than
    # only printed, so a property can assert on them without parsing stdout --
    # and so an auditor reading the artefact can see which gate produced it.
    utc_today: date = date.min
    real: date = date.min
    as_of: date = date.min
    exclusions: frozenset[str] = frozenset()

    @property
    def cannot_establish(self) -> bool:
        return any(kind in CANNOT_ESTABLISH for kind, _ in self.findings)


def run(tmp_path: Path, argv: list[str], **kwargs: Any) -> Verdict:
    """Invoke the CLI exactly as CI does and read the published matrix back."""
    out = tmp_path / f"m{abs(hash((tuple(argv), tuple(sorted(kwargs.items())))))}.json"
    try:
        code = main([*argv, "--out-json", str(out)], **kwargs)
    except SystemExit as stop:
        # Refusing to run at all is the strictest verdict there is.
        return Verdict(exit_code=1, threshold=None, findings=frozenset({("REFUSED", str(stop))}))
    payload = json.loads(out.read_text(encoding="utf-8"))
    enforcement = payload["summary"]["enforcement"]
    threshold = enforcement["threshold"]
    return Verdict(
        exit_code=code,
        threshold=None if threshold is None else Severity(threshold),
        findings=frozenset((f["kind"], f["subject"]) for f in payload["findings"]),
        utc_today=date.fromisoformat(enforcement["utc_today"]),
        real=date.fromisoformat(enforcement["real"]),
        as_of=date.fromisoformat(enforcement["as_of"]),
        exclusions=frozenset(payload["summary"]["excluded_citation_paths"]),
    )


def assert_not_more_permissive(variant: Verdict, default: Verdict, what: str) -> None:
    if variant.cannot_establish:
        assert variant.exit_code != 0, (
            f"{what}: the run declined to certify anything and still exited 0. "
            f"Cannot establish must fail closed, not report clean"
        )
        return
    assert variant.exit_code >= default.exit_code, (
        f"{what}: exits {variant.exit_code} where the default invocation exits "
        f"{default.exit_code}"
    )
    assert strictness(variant.threshold) >= strictness(default.threshold), (
        f"{what}: enforces {variant.threshold} where the default enforces {default.threshold}"
    )
    missing = default.findings - variant.findings
    assert not missing, f"{what}: hides {len(missing)} finding(s) the default reports: {missing}"


def assert_calendar_is_forward_only(verdict: Verdict, what: str) -> None:
    """No supplied date may move the ratchet backwards.

    Asserted on the dates the run recorded rather than on its exit status,
    because a corpus with no critical findings, or a date before the first
    stage, would make an exit-status check pass while the seam was wide open.
    This holds on every calendar day, including before the first stage exists.
    """
    assert verdict.real >= verdict.utc_today, (
        f"{what}: ratcheted against {verdict.real}, behind UTC today {verdict.utc_today}"
    )
    assert verdict.as_of >= verdict.real, (
        f"{what}: evaluated as of {verdict.as_of}, behind the calendar floor {verdict.real}"
    )


def assert_defaults_still_excluded(verdict: Verdict, what: str) -> None:
    assert set(DEFAULT_EXCLUDED_CITATION_PATHS) <= verdict.exclusions, (
        f"{what}: dropped a built-in citation exclusion. Supplying a prefix must add to "
        f"the defaults, never replace them"
    )


# --- the default invocation ----------------------------------------------


def test_the_default_invocation_reports_the_corpus(tmp_path: Path) -> None:
    """The precondition every property below leans on.

    A default run that found nothing would make every comparison vacuously
    true, which is the shape of a property test that passes while asserting
    nothing.
    """
    default = run(tmp_path, [])
    kinds = {kind for kind, _ in default.findings}
    assert not default.cannot_establish, "the fixture corpus must be establishable"
    assert "REQUIREMENT_NO_SCENARIO_SPEC" in kinds, "an orphan a variant could hide"
    assert "SCENARIO_NO_TEST_UNBUILT" in kinds, "a missing test a variant could hide"
    assert "ASSERTION_NO_SCENARIO" in kinds, "an unmapped assertion a variant could hide"


# --- group A: arguments that do not redirect the corpus -------------------
#
# Over a fixed corpus, no combination of these may weaken the verdict.

MODES = [
    [],
    ["--mode", "report"],
    ["--mode", "enforce", "--fail-on", "critical"],
    ["--mode", "enforce", "--fail-on", "high"],
    ["--mode", "enforce", "--fail-on", "medium"],
    ["--mode", "enforce", "--fail-on", "low"],
]

EXCLUSIONS = [
    [],
    ["--exclude-citations", "tests/steps"],
    ["--exclude-citations", "nothing-matches-this/"],
    ["--exclude-citations", "tests/", "--exclude-citations", "docs/"],
]

BASELINE_REFS = [DEFAULT_BASELINE_REF, "HEAD", "work", "no-such-ref-anywhere"]

DATES = [
    None,
    date(2020, 1, 1),
    date(2026, 8, 7),
    date(2026, 8, 8),
    date(2026, 9, 1),
    date(2030, 1, 1),
]


@settings(
    max_examples=60,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(
    mode=st.sampled_from(MODES),
    exclusions=st.sampled_from(EXCLUSIONS),
    baseline_ref=st.sampled_from(BASELINE_REFS),
    real_today=st.sampled_from(DATES),
    today=st.sampled_from(DATES),
)
def test_no_argument_combination_weakens_the_verdict(
    tmp_path: Path,
    mode: list[str],
    exclusions: list[str],
    baseline_ref: str,
    real_today: date | None,
    today: date | None,
) -> None:
    """The property, over the product of every non-corpus input.

    Note what is *not* enumerated here: a list of flags known to be safe. The
    strategy samples the argument space, so a knob added to `main()` later is
    covered the moment it is wired into these axes -- and one that is wired
    into `main()` without being added here is the omission this file is meant
    to make obvious.
    """
    default = run(tmp_path, [])
    variant = run(
        tmp_path,
        [*mode, *exclusions],
        baseline_ref=baseline_ref,
        real_today=real_today,
        today=today,
    )
    what = (
        f"argv={mode + exclusions} baseline_ref={baseline_ref} "
        f"real_today={real_today} today={today}"
    )
    assert_not_more_permissive(variant, default, what)
    assert_calendar_is_forward_only(variant, what)
    assert_defaults_still_excluded(variant, what)


@pytest.mark.parametrize("days_back", [1, 30, 3650])
def test_a_past_real_today_cannot_defer_a_live_stage(tmp_path: Path, days_back: int) -> None:
    """`real_today` is forward-only, like `today`.

    It was the last calendar seam that could move backwards, and it was reached
    from Python rather than from argv -- which is not the same as closed. A date
    in the past is ignored outright.
    """
    supplied = utc_today() - timedelta(days=days_back)
    variant = run(tmp_path, [], real_today=supplied)
    assert_calendar_is_forward_only(variant, f"real_today={supplied}")
    assert variant == run(tmp_path, []), "a past date must be ignored outright"


def test_a_future_real_today_still_rehearses_a_later_stage(tmp_path: Path) -> None:
    """Closing a seam in one direction must not close the legitimate use."""
    rehearsed = run(tmp_path, [], real_today=date(2030, 1, 1))
    assert rehearsed.threshold is Severity.LOW
    assert rehearsed.exit_code == 1


def test_a_supplied_baseline_ref_adds_a_comparison_and_never_replaces_one(
    tmp_path: Path,
) -> None:
    """`--baseline-ref HEAD` was the off switch spelled as a ref.

    Comparing the catalogue against itself finds nothing new by construction.
    The default ref is now always evaluated as well, so the supplied one can
    only add findings.
    """
    default = run(tmp_path, [])
    for ref in ("HEAD", "work", "no-such-ref-anywhere"):
        assert_not_more_permissive(run(tmp_path, [], baseline_ref=ref), default, f"ref={ref}")


def test_a_supplied_ref_cannot_hide_what_the_default_ref_finds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The regression this closes, with a corpus where the refs actually differ.

    On the shared corpus above `origin/develop` is HEAD, so every ref agrees and
    a substituted ref would go unnoticed -- which is how `--baseline-ref HEAD`
    survived the first two reviews. Here `origin/develop` predates an assertion
    that nothing demonstrates, so the default comparison finds it and a
    self-comparison against HEAD does not. The default ref is always evaluated,
    so the supplied one cannot subtract that finding.
    """
    root = tmp_path / "history"
    (root / "docs").mkdir(parents=True)
    (root / "docs" / "coverage-methodology.md").write_text(DOCS_COVERAGE, encoding="utf-8")
    (root / "docs" / "attestation-reliance.md").write_text(
        "# Baseline catalogue\n\n## 2. Assertion catalogue\n\n"
        "| ID | Assertion | Basis |\n|---|---|---|\n",
        encoding="utf-8",
    )
    (root / "tests" / "features").mkdir(parents=True)
    (root / "tests" / "features" / "coverage.feature").write_text(FEATURE, encoding="utf-8")
    (root / "tests" / "steps").mkdir(parents=True)
    (root / "tests" / "steps" / "test_probe_steps.py").write_text(STEPS, encoding="utf-8")
    commit_as_develop(root, "baseline without the assertion")

    # Now commit an assertion whose basis nothing demonstrates. It has to be
    # committed, not merely present in the working tree: relative to
    # origin/develop it is new, and relative to HEAD it is not, which is the
    # whole of what `--baseline-ref HEAD` used to buy.
    (root / "docs" / "attestation-reliance.md").write_text(DOCS_CATALOGUE, encoding="utf-8")
    git(root, "add", "-A")
    git(root, "-c", "user.email=t@example.com", "-c", "user.name=t",
        "commit", "-q", "-m", "add an unmapped assertion")
    monkeypatch.chdir(root)

    for ref in (DEFAULT_BASELINE_REF, "HEAD", "work"):
        verdict = run(tmp_path, [], baseline_ref=ref)
        assert ("NEW_ASSERTION_NO_SCENARIO", "A-02") in verdict.findings, (
            f"baseline_ref={ref} suppressed a newly unmapped assertion the default "
            f"comparison finds"
        )
        assert verdict.exit_code == 1, f"baseline_ref={ref}: QA-S-001 is never staged"


def test_excluding_citations_adds_to_the_defaults(tmp_path: Path) -> None:
    """Supplying a prefix used to discard the built-in ones.

    Replacing the defaults re-enabled fixture IDs as real citations, which
    traced requirements nothing tests. Additive exclusions close that bypass,
    but a new exclusion can also hide an invalid citation. Such a run is useful
    as a diagnostic report but cannot certify the default corpus.
    """
    default = run(tmp_path, [])
    widened = run(tmp_path, ["--exclude-citations", "tests/"])
    irrelevant = run(tmp_path, ["--exclude-citations", "nothing-matches-this/"])
    assert_not_more_permissive(widened, default, "--exclude-citations tests/")
    assert widened.cannot_establish
    assert widened.exit_code == 1
    assert_defaults_still_excluded(widened, "--exclude-citations tests/")
    assert_defaults_still_excluded(irrelevant, "--exclude-citations nothing-matches-this/")
    assert irrelevant.cannot_establish
    assert irrelevant.exit_code == 1


def test_excluding_a_file_cannot_hide_its_retired_citation(tmp_path: Path) -> None:
    default = run(tmp_path, [])
    assert ("RETIRED_REQUIREMENT_REF", "CM-899") in default.findings

    excluded = run(tmp_path, ["--exclude-citations", "tests/steps/"])
    assert ("RETIRED_REQUIREMENT_REF", "CM-899") not in excluded.findings, (
        "the counterexample must genuinely remove the default finding"
    )
    assert excluded.cannot_establish
    assert excluded.exit_code == 1


# --- group B: inputs that redirect the corpus -----------------------------
#
# These ask a different question, so their verdict is not comparable with the
# default's. They are required to say so and to fail while saying it.


@pytest.mark.parametrize(
    ("what", "argv"),
    [
        ("docs directory with nothing in it", ["--docs", "empty-docs"]),
        ("docs directory that does not exist", ["--docs", "no-such-directory"]),
        ("docs directory holding a stub corpus", ["--docs", "stub-docs"]),
    ],
)
def test_a_redirected_corpus_fails_closed(tmp_path: Path, what: str, argv: list[str]) -> None:
    """Zero requirements is an unknown, not a pass.

    Every bypass in this tool's history eventually takes this shape: point it
    somewhere with nothing in it and all the findings disappear at once, leaving
    an exit status of 0 that reads exactly like a clean run. CM-001 and CM-009
    forbid the coverage engine from reporting 0% where it cannot establish the
    population; the generator obeys the same rule about itself.
    """
    verdict = run(tmp_path, argv)
    assert verdict.cannot_establish, f"{what}: must report CORPUS_UNAVAILABLE"
    assert verdict.exit_code == 1, f"{what}: must fail, not exit 0 with nothing to say"


def test_a_stub_corpus_is_caught_by_the_floor_not_by_being_empty(tmp_path: Path) -> None:
    """The floor is relative to the last known good run, not to zero.

    A corpus with one requirement in it is not empty, so the emptiness check
    alone would wave it through. What makes it wrong is that the merge base had
    far more.
    """
    kinds = {(kind, subject) for kind, subject in run(tmp_path, ["--docs", "stub-docs"]).findings}
    assert ("CORPUS_UNAVAILABLE", "requirements") in kinds
    assert ("CORPUS_UNAVAILABLE", "assertions") in kinds, (
        "an emptied catalogue silences every assertion check and must be caught too"
    )


def test_the_floor_is_not_redirected_along_with_the_corpus(tmp_path: Path) -> None:
    """Reading the floor from `--docs` would measure the stub against itself.

    The floor is the size of the corpus this repository was last known good at,
    and that corpus is at `docs/`. If the baseline were read from whatever
    directory `--docs` names, pointing both at a stub would pass by
    construction -- the bypass, reintroduced inside the check written to stop it.
    """
    stub = run(tmp_path, ["--docs", "stub-docs"])
    assert stub.cannot_establish
    assert stub.exit_code == 1


@pytest.mark.parametrize(
    ("what", "collection"),
    [
        ("an empty collection", "empty.txt"),
        ("the real collection", "real.txt"),
        ("a collection covering every scenario", "everything.txt"),
    ],
)
def test_a_supplied_collection_never_clears_a_missing_test_finding(
    tmp_path: Path, what: str, collection: str
) -> None:
    """`--collect-from` is the caller asserting what the tool would have found.

    A file of node ids is cheap to write and impossible to verify from here, so
    accepting it as evidence would let any scenario be marked demonstrated by
    typing a line of text. The ids are still linked and published -- the chain
    stays visible -- but they do not clear the finding, and the run says plainly
    that it did not do its own collection.
    """
    default = run(tmp_path, [])
    variant = run(tmp_path, ["--collect-from", collection])
    assert_not_more_permissive(variant, default, f"--collect-from {what}")
    assert ("UNVERIFIED_COLLECTION", "pytest collection") in variant.findings
    assert ("SCENARIO_NO_TEST_UNBUILT", "CM-S-801") in variant.findings, (
        "the scenario the fabricated collection claims to demonstrate must still be reported"
    )


def test_pointing_features_elsewhere_adds_findings_rather_than_removing_them(
    tmp_path: Path,
) -> None:
    """The agreement check used to run in one direction only.

    Every feature tag had to resolve to a document; nothing asked whether every
    documented scenario reached the suite. So `--features` pointed at an empty
    path removed every finding on this axis and added none, which is a bypass
    whatever it is called.
    """
    default = run(tmp_path, [])
    variant = run(tmp_path, ["--features", "no-such-directory"])
    assert_not_more_permissive(variant, default, "--features no-such-directory")
    assert variant.cannot_establish
    assert ("FEATURE_TAG_MISSING", "CM-S-801") in variant.findings


def test_a_same_sized_docs_redirect_still_withholds_the_verdict(
    corpus: Path, tmp_path: Path
) -> None:
    alternate = corpus / "alternate-docs"
    alternate.mkdir()
    for source in (corpus / "docs").glob("*.md"):
        (alternate / source.name).write_text(source.read_text(encoding="utf-8"), encoding="utf-8")

    verdict = run(tmp_path, ["--docs", str(alternate)])
    assert ("CORPUS_UNAVAILABLE", "requirements") not in verdict.findings
    assert ("UNVERIFIED_INPUTS", "redirected inputs") in verdict.findings
    assert verdict.exit_code == 1


def test_a_different_same_sized_repository_withholds_the_verdict(
    corpus: Path, tmp_path: Path
) -> None:
    alternate = tmp_path / "alternate-repository"
    import shutil

    shutil.copytree(corpus, alternate)
    verdict = run(tmp_path, ["--repo-root", str(alternate)])
    assert ("UNVERIFIED_INPUTS", "redirected inputs") in verdict.findings
    assert verdict.exit_code == 1


def test_corpus_floor_uses_an_exact_ninety_percent_comparison() -> None:
    matrix = matrix_module.Matrix()
    matrix.requirements = {f"CM-{n:03}": object() for n in range(9)}  # type: ignore[assignment]
    findings = matrix_module._check_corpus(
        matrix, {"requirements": 11, "assertions": 0}
    )
    assert any(f.kind == "CORPUS_UNAVAILABLE" and f.subject == "requirements" for f in findings)


def test_collecting_from_a_directory_with_no_tests_refuses_to_run(tmp_path: Path) -> None:
    """`--tests` pointed at nothing collects nothing, and nothing is not clean."""
    verdict = run(tmp_path, ["--tests", "no-such-directory"])
    assert verdict.exit_code == 1
    assert verdict.cannot_establish or verdict.findings == frozenset(
        {("REFUSED", "pytest collected no tests; the matrix would be meaningless")}
    )


def test_the_ratchet_calendar_does_not_move_with_the_process_timezone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`date.today()` made the hard expiry depend on `$TZ`.

    Every other seam here was closed on the argument that a knob nobody can see
    is worse than one they can, and an implicit dependency on the process
    timezone is exactly that knob: at UTC-11 a runner stayed on 7 August for
    eleven hours after the critical stage went live in UTC, and
    `TZ=Etc/GMT+12 make test` shifted the ratchet without touching an argument
    or a line of code. The published schedule is in calendar dates without a
    zone, so the calendar has to be the one both ends of the world agree on.

    `Etc/GMT-14` and `Etc/GMT+12` are 26 hours apart, so their local dates never
    agree. At least one of them therefore disagrees with UTC at every instant,
    which is what makes this test bite rather than merely pass.
    """
    zones = ("Etc/GMT+12", "Etc/GMT-14", "Pacific/Kiritimati", "Pacific/Midway")
    monkeypatch.setattr(time, "tzset", time.tzset)  # documents the dependency
    try:
        reference = utc_today()
        local_dates = set()
        for zone in zones:
            monkeypatch.setenv("TZ", zone)
            time.tzset()
            assert utc_today() == reference, f"TZ={zone} moved the ratchet calendar"
            local_dates.add(date.today())
        assert len(local_dates) > 1, (
            "the zones chosen must actually disagree, or this test proves nothing"
        )
        assert local_dates - {reference}, (
            "at least one zone must disagree with UTC, so that a run reading the local "
            "calendar would ratchet against a different date than this one"
        )
    finally:
        monkeypatch.undo()
        time.tzset()


def test_output_paths_cannot_change_the_verdict(tmp_path: Path) -> None:
    """The only arguments that are allowed to be inert, asserted to be inert."""
    default = run(tmp_path, [])
    with_markdown = run(tmp_path, ["--out-md", str(tmp_path / "m.md")])
    assert with_markdown.findings == default.findings
    assert with_markdown.exit_code == default.exit_code
    assert with_markdown.threshold == default.threshold
