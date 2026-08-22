from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "tools" / "demo_evidence_pipeline.py"


def test_committed_evidence_pipeline_demo_is_literal_and_fast() -> None:
    started = time.monotonic()
    completed = subprocess.run(  # noqa: S603
        [sys.executable, str(SCRIPT)],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    elapsed = time.monotonic() - started

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "Population            1                 1" in completed.stdout
    assert "Matched               0                 1" in completed.stdout
    assert "Coverage ratio        0.0000            1.0000" in completed.stdout
    assert (
        "This action exists in Salesforce but has no signed evidence trail on our side — "
        "we refuse to claim credit for it."
    ) in completed.stdout
    assert (
        "This action has a genuine signed ActionProposal and ExecutionReceipt — "
        "the coverage claim is earned, not assumed."
    ) in completed.stdout
    assert (
        "Independently verified by a Go binary that has never read this project's Python code."
        in completed.stdout
    )
    assert completed.stdout.count("VALID AttestationWindow") == 2
    assert completed.stdout.count("VERDICT unchecked_revocation") == 2
    assert completed.stdout.count("checks run       [coverage]") == 2
    assert (
        "This pair runs against a mock destination, not the live Salesforce org used in "
        "Stages 1 and 2."
        in completed.stdout
    )
    assert "Population            1                     1" in completed.stdout
    assert "Matched               1                     1" in completed.stdout
    assert "Coverage ratio        1.0000                1.0000" in completed.stdout
    assert "A-08                  present               absent" in completed.stdout
    assert "Review timing         12ms BEFORE           10ms AFTER" in completed.stdout
    assert (
        "Coverage is identical in both cases: 1/1, 1.0000. Coverage isn't what's different "
        "here."
    ) in completed.stdout
    assert "Reviewed while the action could still be stopped. Oversight counts." in completed.stdout
    assert "Exclusion: human_review_ineffective" in completed.stdout
    assert (
        "Reviewed after the action had already committed. The decision was 'approve' — "
        "it doesn't matter. Oversight after the fact isn't oversight."
    ) in completed.stdout
    assert (
        "Neither fixture tells the evaluator which answer to produce. The only difference "
        "between the two runs is WHEN the review happened; the same code decided both outcomes."
    ) in completed.stdout
    assert elapsed < 60
