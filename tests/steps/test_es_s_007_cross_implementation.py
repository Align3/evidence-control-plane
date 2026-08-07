"""ES-S-007 -- the Python writer and the Go verifier agree byte-for-byte (ES-001).

This is the acceptance test EV-05 exists to make runnable. It is the only place
in the suite where AC-011's independence claim is actually checked, so it is
built to be hard to satisfy accidentally.

Two properties the implementation of this test has to have, or it proves
nothing:

* It **runs the real Go binary**. Re-deriving the canonical form in Python and
  comparing that to Python would demonstrate only that Python agrees with
  itself. Every comparison below is against bytes that came out of a compiled
  `verify` process over a pipe.
* It **builds that binary itself**, rather than assuming some earlier CI step
  left one lying around. `make all` runs `test` before `go-test`, so at the
  moment pytest executes there is no built binary; a test that silently skipped
  when the binary were missing would be green on exactly the pipeline it is
  meant to guard. Build failure and absent toolchain are failures here, not
  skips -- with one deliberate exception noted at `_go_toolchain`.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import pytest
from pytest_bdd import given, scenario, then, when

from sdk_python.evidence.canonical import canonicalize as python_canonicalize

REPO = Path(__file__).resolve().parents[2]
VECTORS = REPO / "tests" / "vectors" / "vectors-v0.1.json"
VERIFIER_DIR = REPO / "verifier-go"


@scenario("evidence.feature", "ES-S-007 Cross-implementation canonicalization")
def test_es_s_007() -> None:
    """Bound by pytest-bdd."""


def _go_toolchain() -> str:
    # A missing Go toolchain is the one thing this test cannot fail the build
    # for: it would break every contributor without Go for a reason unrelated to
    # the change under test. CI installs Go, so the guarantee still holds where
    # it matters, and the skip names itself loudly rather than passing quietly.
    go = shutil.which("go")
    if go is None:
        pytest.skip("no Go toolchain; ES-S-007 cannot be demonstrated in this environment")
    return go


@pytest.fixture(scope="module")
def go_verifier() -> Path:
    """Build the verifier under test and return the binary path."""
    go = _go_toolchain()
    out = Path(tempfile.mkdtemp(prefix="es-s-007-")) / "verify"
    result = subprocess.run(  # noqa: S603
        [go, "build", "-o", str(out), "./cmd/verify"],
        cwd=VERIFIER_DIR,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            "the Go verifier does not build, so ES-S-007 cannot be "
            f"demonstrated:\n{result.stdout}\n{result.stderr}"
        )
    return out


def _go_canonicalize(binary: Path, payload: str) -> tuple[bytes, str]:
    """Canonicalise through the compiled binary, returning bytes and digest."""
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        handle.write(payload)
        path = handle.name
    try:
        result = subprocess.run(  # noqa: S603
            [str(binary), "-mode", "canonicalize", path],
            capture_output=True,
            check=False,
        )
    finally:
        Path(path).unlink(missing_ok=True)
    if result.returncode != 0:
        raise AssertionError(
            f"Go verifier refused input it should have canonicalised: "
            f"{result.stderr.decode(errors='replace')}"
        )
    # The binary prints canonical bytes on stdout and "digest sha256:..." on
    # stderr. Both are compared: agreeing on bytes but not on the digest would
    # mean the two sides hash differently, which ES-003 does not permit.
    canonical = result.stdout.rstrip(b"\n")
    digest = ""
    for line in result.stderr.decode(errors="replace").splitlines():
        if line.startswith("digest "):
            digest = line.split(" ", 1)[1].strip()
    return canonical, digest


def _subjects(corpus: dict[str, Any]) -> list[tuple[str, Any]]:
    """Every JSON value in the corpus that both sides must canonicalise alike.

    Drawn from the whole corpus rather than the canonicalize vectors alone: the
    records carry nested objects, arrays, unicode keys and unknown body members,
    which is where two canonicalisers actually diverge.
    """
    out: list[tuple[str, Any]] = []
    for vector in corpus["vectors"]:
        vid = vector["id"]
        if vector["operation"] == "canonicalize" and vector["expected"].get("accepted"):
            out.append((f"{vid}:input", json.loads(vector["input_json"])))
        for key in ("record", "unsigned_record"):
            value = vector.get(key)
            if isinstance(value, dict) and "record_id" in value:
                out.append((f"{vid}:{key}", value))
        for index, record in enumerate(vector.get("records") or []):
            out.append((f"{vid}:records[{index}]", record))
        signed = (vector.get("expected") or {}).get("signed_record")
        if isinstance(signed, dict):
            out.append((f"{vid}:signed_record", signed))
    return out


@given("the published conformance vectors", target_fixture="subjects")
def _published_vectors() -> list[tuple[str, Any]]:
    corpus = json.loads(VECTORS.read_text(encoding="utf-8"))
    subjects = _subjects(corpus)
    # ES-029 makes the corpus normative; an empty or shrunken one would make
    # this scenario pass without demonstrating anything (CM-001 applied to our
    # own test suite).
    if len(subjects) < 40:
        raise AssertionError(
            f"only {len(subjects)} comparable values found in the corpus; "
            "refusing to report cross-implementation agreement on a corpus "
            "this small"
        )
    return subjects


@when("the Python writer and the Go verifier each canonicalize them",
      target_fixture="comparison")
def _canonicalize_both(
    subjects: list[tuple[str, Any]], go_verifier: Path
) -> list[tuple[str, bytes, bytes, str, str]]:
    results = []
    for label, value in subjects:
        payload = json.dumps(value)
        go_bytes, go_digest = _go_canonicalize(go_verifier, payload)
        py_bytes = python_canonicalize(value)
        py_digest = "sha256:" + hashlib.sha256(py_bytes).hexdigest()
        results.append((label, go_bytes, py_bytes, go_digest, py_digest))
    return results


@then("both produce byte-identical output")
def _bytes_identical(comparison: list[tuple[str, bytes, bytes, str, str]]) -> None:
    divergent = [
        (label, go, py) for label, go, py, _, _ in comparison if go != py
    ]
    if divergent:
        label, go, py = divergent[0]
        raise AssertionError(
            f"{len(divergent)} of {len(comparison)} values canonicalise "
            f"differently. First: {label}\n  go     {go!r}\n  python {py!r}"
        )


@then("both compute identical digests")
def _digests_identical(comparison: list[tuple[str, bytes, bytes, str, str]]) -> None:
    for label, _, _, go_digest, py_digest in comparison:
        if not go_digest:
            raise AssertionError(f"{label}: Go verifier reported no digest")
        if go_digest != py_digest:
            raise AssertionError(
                f"{label}: digests differ\n  go     {go_digest}\n  python {py_digest}"
            )
