"""Acceptance bindings for EV-22's own requirements: QA-010, QA-011, QA-012.

These are `@scenario` bindings, not name-links. `tests/features/meta.feature`
was unparseable Gherkin until this change -- `testing-qa.md` headed QA-S-002
with `*(QA-005 property 6)*`, and `extract_features.py` splits reference lists
on commas only, so it emitted the tag `@QA-005 property 6`. A Gherkin tag may
not contain whitespace, so pytest-bdd refused the whole file and nothing could
bind to any QA-S-nnn scenario. The heading now reads
`QA-S-002 — Gap conservation holds, property 6 *(QA-005)*`: the annotation
moved into the title, where it is prose, and the reference list contains only a
requirement ID. No scenario body changed.

Everything here asserts through the command-line interface -- exit status and
printed output -- because that is what CI runs (AG-006, QA-S-005). The corpora
are files under `fixtures/`, never inline strings, because the matrix reads
requirement IDs written in test modules as citations.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import date
from pathlib import Path

import pytest
from pytest_bdd import given, scenario, then, when

from tests.traceability.matrix import main

FIXTURES = Path(__file__).parent / "fixtures"
CHAIN = FIXTURES / "chain"


@scenario("meta.feature", "QA-S-006 The four-link chain is generated and published")
def test_qa_s_006_four_link_chain_is_generated_and_published() -> None:
    """QA-010."""


@scenario("meta.feature", "QA-S-007 An orphaned requirement fails the traceability check")
def test_qa_s_007_orphaned_requirement_fails_the_check() -> None:
    """QA-011."""


@scenario("meta.feature", "QA-S-008 The matrix is generated, never hand-maintained")
def test_qa_s_008_matrix_is_generated_never_hand_maintained() -> None:
    """QA-012."""


@scenario("meta.feature", "QA-S-009 A malformed non-testable marking exempts nothing")
def test_qa_s_009_malformed_marking_exempts_nothing() -> None:
    """QA-015."""


@scenario("meta.feature", "QA-S-001 Assertion without scenario fails CI")
def test_qa_s_001_assertion_without_scenario_fails_ci() -> None:
    """QA-002, bound properly now that meta.feature parses.

    The CLI-level assertions for this scenario live in `test_acceptance.py`;
    this binding is what makes the scenario itself demonstrated rather than
    merely name-linked.
    """


# --- shared plumbing ------------------------------------------------------


def _corpus(tmp_path: Path, name: str) -> Path:
    root = tmp_path / name
    shutil.copytree(FIXTURES / name, root)
    (root / "collected.txt").write_text("", encoding="utf-8")
    return root


def _run(root: Path, *extra: str, **kwargs: object) -> tuple[int, Path]:
    out_json = root / "matrix.json"
    code = main(
        [
            "--repo-root", str(root),
            "--docs", str(root / "docs"),
            "--features", str(root / "no-features"),
            "--collect-from", str(root / "collected.txt"),
            "--out-json", str(out_json),
            *extra,
        ],
        real_today=date(2026, 8, 1),
        regression_gate=False,
        **kwargs,  # type: ignore[arg-type]
    )
    return code, out_json


# --- QA-S-006: the four-link chain ---------------------------------------


@given(
    "a requirement with a scenario, an implementing test, and an assertion citing it as basis",
    target_fixture="corpus",
)
def _chain_corpus(tmp_path: Path) -> Path:
    root = tmp_path / "chain"
    shutil.copytree(CHAIN, root)
    shutil.copy(CHAIN / "collected.txt", root / "collected.txt")
    return root


@when("the traceability matrix is generated", target_fixture="generated")
def _generate(corpus: Path, capsys: pytest.CaptureFixture[str]) -> dict[str, object]:
    """One When for both scenarios that use this wording; the Given differs."""
    out_md, out_json = corpus / "m.md", corpus / "m.json"
    main(
        [
            "--repo-root", str(corpus),
            "--docs", str(corpus / "docs"),
            "--features", str(corpus / "no-features"),
            "--collect-from", str(corpus / "collected.txt"),
            "--out-md", str(out_md),
            "--out-json", str(out_json),
        ],
        real_today=date(2026, 8, 1),
        regression_gate=False,
    )
    capsys.readouterr()
    return {
        "markdown": out_md.read_text(encoding="utf-8"),
        "payload": json.loads(out_json.read_text(encoding="utf-8")),
    }


@then("the matrix links the requirement to the scenario to the test to the assertion")
def _chain_is_linked(generated: dict[str, object]) -> None:
    payload = generated["payload"]
    assert isinstance(payload, dict)
    requirement = next(r for r in payload["requirements"] if r["id"] == "CM-401")
    assert requirement["scenarios"] == ["CM-S-401"], "requirement -> scenario"
    scenario_row = next(s for s in payload["scenarios"] if s["id"] == "CM-S-401")
    assert scenario_row["tests"], "scenario -> test"
    assertion = next(a for a in payload["assertions"] if a["id"] == "A-01")
    assert assertion["basis"] == ["CM-401"], "assertion -> requirement"


@then("it is published in both human-readable and machine-readable form")
def _published_both_ways(generated: dict[str, object]) -> None:
    markdown = generated["markdown"]
    assert isinstance(markdown, str)
    assert "# Traceability matrix" in markdown
    assert "CM-401" in markdown and "A-01" in markdown
    payload = generated["payload"]
    assert isinstance(payload, dict)
    assert payload["schema"] == "traceability-matrix/1"


# --- QA-S-007: an orphaned requirement fails ------------------------------


@given(
    "a requirement with no scenario and no non-testable marking",
    target_fixture="orphan_corpus",
)
def _orphan_corpus(tmp_path: Path) -> Path:
    return _corpus(tmp_path, "orphan_only")


@when("the traceability check runs with that severity enforced", target_fixture="orphan_result")
def _run_enforced(
    orphan_corpus: Path, capsys: pytest.CaptureFixture[str]
) -> tuple[int, str]:
    code, _ = _run(orphan_corpus, "--mode", "enforce", "--fail-on", "medium")
    return code, capsys.readouterr().out


@then("the check fails")
def _check_fails(orphan_result: tuple[int, str]) -> None:
    assert orphan_result[0] == 1


@then("the failure names the requirement")
def _failure_names_requirement(orphan_result: tuple[int, str]) -> None:
    assert "CM-401" in orphan_result[1], "the orphan must be named, not merely counted"


# --- QA-S-008: generated, never hand-maintained ---------------------------


@given("the traceability matrix generator", target_fixture="generator_corpus")
def _generator_corpus(tmp_path: Path) -> Path:
    return _corpus(tmp_path, "orphan_only")


@when("it runs twice over unchanged inputs", target_fixture="twice_result")
def _run_twice(
    generator_corpus: Path, capsys: pytest.CaptureFixture[str]
) -> dict[str, object]:
    before = sorted(p.relative_to(generator_corpus) for p in generator_corpus.rglob("*"))
    first = generator_corpus / "a.json"
    second = generator_corpus / "b.json"
    for target in (first, second):
        main(
            [
                "--repo-root", str(generator_corpus),
                "--docs", str(generator_corpus / "docs"),
                "--features", str(generator_corpus / "no-features"),
                "--collect-from", str(generator_corpus / "collected.txt"),
                "--out-json", str(target),
            ],
            real_today=date(2026, 8, 1),
            regression_gate=False,
        )
    # A run with no output path must leave the tree untouched.
    bare = generator_corpus / "bare"
    bare.mkdir()
    shutil.copytree(generator_corpus / "docs", bare / "docs")
    (bare / "collected.txt").write_text("", encoding="utf-8")
    untouched_before = sorted(p.relative_to(bare) for p in bare.rglob("*"))
    main(
        [
            "--repo-root", str(bare),
            "--docs", str(bare / "docs"),
            "--features", str(bare / "no-features"),
            "--collect-from", str(bare / "collected.txt"),
        ],
        real_today=date(2026, 8, 1),
        regression_gate=False,
    )
    capsys.readouterr()
    return {
        "first": first.read_bytes(),
        "second": second.read_bytes(),
        "untouched_before": untouched_before,
        "untouched_after": sorted(p.relative_to(bare) for p in bare.rglob("*")),
        "repo_before": before,
    }


@then("both runs produce byte-identical output")
def _byte_identical(twice_result: dict[str, object]) -> None:
    assert twice_result["first"] == twice_result["second"]


@then("neither run writes a matrix into the repository for a human to edit")
def _no_matrix_written(twice_result: dict[str, object]) -> None:
    assert twice_result["untouched_after"] == twice_result["untouched_before"], (
        "a run with no output path must write nothing"
    )
    repo_root = Path(__file__).resolve().parents[2]
    tracked = subprocess.run(  # noqa: S603 - fixed argv
        [shutil.which("git") or "git", "ls-files"],
        cwd=repo_root, capture_output=True, text=True, check=False,
    ).stdout.split()
    committed = [
        f for f in tracked
        if Path(f).name.startswith("traceability-matrix.")
        or Path(f).name in ("matrix.md", "matrix.json")
    ]
    assert not committed, f"QA-012: no matrix may be committed, found {committed}"


# --- QA-S-009: a malformed marking exempts nothing ------------------------


@given(
    "a requirement with no scenario and a non-testable marking whose category is not in "
    "the closed enum",
    target_fixture="corpus",
)
def _malformed_corpus(tmp_path: Path) -> Path:
    return _corpus(tmp_path, "malformed_marking")


@then("the marking exempts nothing")
def _exempts_nothing(generated: dict[str, object]) -> None:
    payload = generated["payload"]
    assert isinstance(payload, dict)
    assert payload["exemptions"] == []
    requirement = next(
        r for r in payload["requirements"] if r["id"] == "CM-402"
    )
    assert requirement["exemption"] is None


@then("the requirement is still reported as an orphan")
def _still_an_orphan(generated: dict[str, object]) -> None:
    payload = generated["payload"]
    assert isinstance(payload, dict)
    kinds = {
        f["kind"] for f in payload["findings"] if f["subject"] == "CM-402"
    }
    assert "MALFORMED_EXEMPTION" in kinds
    assert any(k.startswith("REQUIREMENT_NO_SCENARIO") for k in kinds)


# --- QA-S-001: a new assertion with no scenario ---------------------------


@given("a new assertion added to the catalogue", target_fixture="qa_s_001_corpus")
def _new_assertion(tmp_path: Path) -> Path:
    """A real repository whose baseline commit does not contain the assertion.

    QA-S-001 says *new*. The gate compares against the merge base, so the
    fixture needs history: the assertion exists in the working tree and not at
    the baseline, which is what makes it new rather than backlog.
    """
    regression = FIXTURES / "regression"
    root = tmp_path / "qa_s_001"
    docs = root / "docs"
    docs.mkdir(parents=True)
    (root / "collected.txt").write_text("", encoding="utf-8")
    shutil.copy(regression / "requirements.md", docs / "coverage-methodology.md")
    shutil.copy(regression / "catalogue-empty.md", docs / "attestation-reliance.md")

    git = shutil.which("git")
    assert git is not None, "the QA-S-001 gate reads history; git is required"
    author = ["-c", "user.email=t@example.com", "-c", "user.name=t"]

    def run(*args: str) -> None:
        subprocess.run([git, *args], cwd=root, check=True)  # noqa: S603 - resolved path

    run("init", "-q", "-b", "base")
    run("add", "-A")
    run(*author, "commit", "-q", "-m", "baseline without the assertion")
    run("checkout", "-q", "-b", "work")

    shutil.copy(regression / "catalogue-unmapped.md", docs / "attestation-reliance.md")
    return root


@given("no scenario referencing it")
def _no_scenario_references_it(qa_s_001_corpus: Path) -> None:
    text = (qa_s_001_corpus / "docs" / "coverage-methodology.md").read_text(encoding="utf-8")
    assert "CM-S-402" not in text, "the fixture must leave the assertion's basis untraced"


@when("CI runs", target_fixture="ci_result")
def _ci_runs(
    qa_s_001_corpus: Path, capsys: pytest.CaptureFixture[str]
) -> tuple[int, str]:
    """The literal ci.yml argv: --mode report, before any QA-011 stage is live."""
    code = main(
        [
            "--repo-root", str(qa_s_001_corpus),
            "--docs", str(qa_s_001_corpus / "docs"),
            "--features", str(qa_s_001_corpus / "no-features"),
            "--collect-from", str(qa_s_001_corpus / "collected.txt"),
            "--mode", "report",
        ],
        real_today=date(2026, 8, 1),
        baseline_ref="base",
    )
    return code, capsys.readouterr().out


@then("the traceability check fails")
def _traceability_check_fails(ci_result: tuple[int, str]) -> None:
    assert ci_result[0] == 1, "a newly unmapped assertion must fail the real CI invocation"


@then("the failure names the unmapped assertion")
def _names_unmapped_assertion(ci_result: tuple[int, str]) -> None:
    assert "A-01" in ci_result[1], "the failure must name the assertion, not merely count it"
