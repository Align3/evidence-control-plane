"""Require every committed live attestation fixture to be CLI-valid wire.

This gate intentionally invokes the compiled Go verifier. Recomputing a
signature in Python would miss the defect this protects against: a signed
canonical record can be reparsed and pretty-printed without changing its
semantic content or signed digest, while the resulting received bytes are no
longer the RFC 8785 artifact ES-001 requires.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
VERIFIER_DIR = REPO / "verifier-go"
FIXTURE_ROOT = Path("tests/fixtures")
ATTESTATION_FILENAME = "08-attestation-window.json"
MANIFEST_FILENAME = "09-manifest.json"


def _executable(name: str) -> str:
    resolved = shutil.which(name)
    if resolved is None:
        raise RuntimeError(f"{name} is required to verify committed fixtures")
    return resolved


def _tracked_attestations(git: str) -> tuple[Path, ...]:
    completed = subprocess.run(  # noqa: S603
        [git, "ls-files", "--", str(FIXTURE_ROOT)],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=True,
    )
    paths = tuple(
        REPO / line
        for line in completed.stdout.splitlines()
        if Path(line).name == ATTESTATION_FILENAME
    )
    if not paths:
        raise RuntimeError("no committed attestation fixture records were found")
    return paths


def _keyring(manifest_path: Path) -> dict[str, dict[str, str]]:
    document: Any = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or not isinstance(
        document.get("verification_keys"), dict
    ):
        raise RuntimeError(f"{manifest_path} has no verification_keys object")

    result: dict[str, dict[str, str]] = {}
    for key_id, raw_entry in document["verification_keys"].items():
        if not isinstance(key_id, str) or not isinstance(raw_entry, dict):
            raise RuntimeError(f"{manifest_path} has a malformed key entry")
        namespace = raw_entry.get("namespace")
        public_key = raw_entry.get("public_key_base64url")
        if not isinstance(namespace, str) or not isinstance(public_key, str):
            raise RuntimeError(f"{manifest_path} has a malformed key entry {key_id!r}")
        result[key_id] = {"namespace": namespace, "public_key": public_key}
    return result


def _build_verifier(go: str, output: Path) -> None:
    completed = subprocess.run(  # noqa: S603
        [go, "build", "-o", str(output), "./cmd/verify"],
        cwd=VERIFIER_DIR,
        capture_output=True,
        text=True,
        env=os.environ.copy(),
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "the Go verifier did not build:\n" + completed.stdout + completed.stderr
        )


def main() -> int:
    git = _executable("git")
    go = _executable("go")
    failures: list[str] = []

    with tempfile.TemporaryDirectory(prefix="fixture-verifier-") as temporary:
        temporary_path = Path(temporary)
        verifier = temporary_path / "verify"
        _build_verifier(go, verifier)

        for index, attestation_path in enumerate(_tracked_attestations(git)):
            manifest_path = attestation_path.with_name(MANIFEST_FILENAME)
            keyring_path = temporary_path / f"keyring-{index}.json"
            keyring_path.write_text(
                json.dumps(_keyring(manifest_path), sort_keys=True, separators=(",", ":")),
                encoding="utf-8",
            )
            completed = subprocess.run(  # noqa: S603
                [
                    str(verifier),
                    "-mode",
                    "record",
                    "-keyring",
                    str(keyring_path),
                    str(attestation_path),
                ],
                cwd=REPO,
                capture_output=True,
                text=True,
                check=False,
            )
            literal = completed.stdout if completed.returncode == 0 else completed.stderr
            relative = attestation_path.relative_to(REPO)
            print(f"{relative}:\n{literal.rstrip()}")
            if completed.returncode != 0 or not literal.startswith("VALID "):
                failures.append(str(relative))

    if failures:
        print("fixture verifier refused: " + ", ".join(failures))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
