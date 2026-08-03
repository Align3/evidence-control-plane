"""Building a fixture corpus the generator will actually pass judgement on.

Every corpus here is a real git repository with a real `origin/develop`, and
that is not incidental scaffolding. `main()` no longer takes `regression_gate`,
and its baseline ref is additive rather than substitutable, so a corpus with no
history now blocks with `BASELINE_UNAVAILABLE` exactly as CI would -- which is
the intended behaviour and the reason the parameter is gone. The way to get a
green fixture run is to give the fixture the history a real build has, not to
hand the tool a flag that tells it not to look.

`origin/develop` is created as a remote-tracking ref rather than a branch
because that is what `actions/checkout` leaves behind, and the merge base is
what the QA-S-001 gate reads.
"""

from __future__ import annotations

import shutil
import subprocess
from contextlib import chdir
from datetime import date
from pathlib import Path
from unittest.mock import patch

from tests.traceability import matrix as matrix_module
from tests.traceability.matrix import (
    ENFORCEMENT_SCHEDULE,
    SEVERITY_RANK,
    Severity,
    mandated_threshold,
    utc_today,
)

FIXTURES = Path(__file__).parent / "fixtures"
_AUTHOR = ("-c", "user.email=t@example.com", "-c", "user.name=t")


def git(root: Path, *args: str) -> None:
    binary = shutil.which("git")
    assert binary is not None, "these fixtures are git repositories; git is required"
    subprocess.run([binary, *args], cwd=root, check=True)  # noqa: S603 - resolved path


def commit_as_develop(root: Path, message: str = "baseline") -> None:
    """Commit everything and point `origin/develop` at it.

    The merge base is then HEAD, which is the legitimate state of a push build
    to the integration branch: the content was gated before it merged, so
    nothing in it can be new. The tool says so rather than reporting a clean
    comparison, which is what `test_a_baseline_equal_to_head_is_reported_as_vacuous`
    pins down.
    """
    git(root, "init", "-q", "-b", "work")
    git(root, "add", "-A")
    git(root, *_AUTHOR, "commit", "-q", "-m", message)
    git(root, "update-ref", "refs/remotes/origin/develop", "HEAD")


def corpus(tmp_path: Path, name: str) -> Path:
    """A fixture corpus as a repository, with an empty supplied collection."""
    root = tmp_path / name
    shutil.copytree(FIXTURES / name, root)
    (root / "collected.txt").write_text("", encoding="utf-8")
    commit_as_develop(root, f"fixture corpus {name}")
    return root


def run_default(root: Path, *argv: str, **kwargs: object) -> int:
    """Run the real default observation over a fixture repository.

    CLI acceptance tests used to redirect `--repo-root`, `--features`, and
    `--collect-from`. Those are precisely the inputs whose fail-closed behavior
    the suite now checks, so using them in unrelated tests makes a red exit
    vacuous. Chdir makes `main([])` select the fixture naturally, while the
    collection patch stands in for pytest without becoming caller-supplied
    evidence at the CLI boundary.
    """
    collected = root / "collected.txt"
    node_ids = collected.read_text(encoding="utf-8").split() if collected.is_file() else []
    with chdir(root), patch.object(matrix_module, "collect_node_ids", return_value=node_ids):
        return matrix_module.main(list(argv), **kwargs)  # type: ignore[arg-type]


def expected_code(worst: Severity) -> int:
    """What the QA-011 schedule says this run's exit status must be today.

    Hard-coding 0 here used to work because `real_today` froze the calendar at
    1 August in every fixture call. Closing that seam means an assertion about a
    green build has to move with the schedule the same way CI does -- a test
    that pins "this stays green" past a hard expiry is the ratchet being
    disabled in the test suite instead of in the tool.

    `worst` is the most severe finding the corpus contains. The build goes red
    on the first date the schedule reaches it.
    """
    mandated = mandated_threshold(utc_today())
    if mandated is None:
        return 0
    return 1 if SEVERITY_RANK[mandated] >= SEVERITY_RANK[worst] else 0


def first_stage() -> date:
    return ENFORCEMENT_SCHEDULE[0][0]
