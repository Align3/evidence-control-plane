#!/usr/bin/env python3
"""
Generate executable .feature files from the normative markdown specifications.

The documents in docs/ are the single source of truth. Feature files are build
artifacts and MUST NOT be hand-edited -- edit the scenario in its owning document
and regenerate. This mirrors QA-012: generated, never hand-maintained.

Usage:
    python tools/extract_features.py --docs docs --out tests/features
    python tools/extract_features.py --docs docs --out tests/features --check

--check exits non-zero if the generated output differs from what is on disk,
which is the CI gate that stops the docs and the tests drifting apart.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

# Scenario heading, e.g.
#   ### CM-S-001 — Coverage ratio withheld at insufficient class *(CM-009, CM-011)*
HEADING = re.compile(
    r"^###\s+(?P<sid>[A-Z]{2}-S-\d{3})\s+[—-]\s+(?P<title>.+?)"
    r"(?:\s*\*\((?P<refs>[^)]*)\)\*)?\s*$"
)

GHERKIN_OPEN = re.compile(r"^```gherkin\s*$")
FENCE = re.compile(r"^```\s*$")

STEP = re.compile(r"^\s*(Given|When|Then|And|But)\s+\S")

DOMAINS = {
    "CM": ("coverage", "Coverage and assurance methodology"),
    "ES": ("evidence", "Agent evidence specification"),
    "TM": ("adversarial", "Threat model -- adversarial behaviour"),
    "AR": ("attestation", "Attestation and reliance framework"),
    "AC": ("architecture", "Architecture invariants"),
    "SE": ("security", "Security controls"),
    "IN": ("infrastructure", "Infrastructure and operations"),
    "QA": ("meta", "Test-system self-checks"),
    "RC": ("reconciliation", "Reconciliation classification"),
}


@dataclass
class Scenario:
    sid: str
    title: str
    refs: list[str]
    steps: list[str]
    source: str
    line: int

    @property
    def domain(self) -> str:
        return self.sid.split("-", 1)[0]

    def problems(self) -> list[str]:
        out = []
        if not self.steps:
            out.append("empty scenario body")
        if not self.refs:
            out.append("no requirement reference -- every scenario must trace to a requirement")
        starts = [s for s in self.steps if s.startswith(("Given", "When", "Then"))]
        if sum(1 for s in starts if s.startswith("Given")) > 1:
            out.append(
                "multiple Given blocks -- looks like two scenarios in one; split them "
                "in the source document"
            )
        if not any(s.startswith("Then") for s in self.steps):
            out.append("no Then step -- scenario asserts nothing")
        return out

    def render(self) -> str:
        tags = " ".join(f"@{t}" for t in [self.sid, *self.refs])
        body = "\n".join(f"    {s}" for s in self.steps)
        return (
            f"  {tags}\n"
            f"  # source: {self.source}:{self.line}\n"
            f"  Scenario: {self.sid} {self.title}\n"
            f"{body}\n"
        )


def parse(path: Path) -> list[Scenario]:
    scenarios: list[Scenario] = []
    lines = path.read_text(encoding="utf-8").splitlines()
    i = 0
    while i < len(lines):
        m = HEADING.match(lines[i])
        if not m:
            i += 1
            continue

        sid = m.group("sid")
        title = m.group("title").strip()
        raw_refs = m.group("refs") or ""
        refs = [r.strip() for r in raw_refs.split(",") if r.strip()]
        heading_line = i + 1

        # Find the next gherkin fence before the following heading.
        j = i + 1
        steps: list[str] = []
        while j < len(lines) and not HEADING.match(lines[j]):
            if GHERKIN_OPEN.match(lines[j]):
                j += 1
                while j < len(lines) and not FENCE.match(lines[j]):
                    if STEP.match(lines[j]):
                        steps.append(lines[j].strip())
                    j += 1
                break
            j += 1

        scenarios.append(
            Scenario(sid, title, refs, steps, path.name, heading_line)
        )
        i = j + 1
    return scenarios


def render_feature(domain: str, scenarios: list[Scenario]) -> str:
    _, description = DOMAINS[domain]
    header = (
        "# GENERATED FILE -- DO NOT EDIT.\n"
        "# Regenerate with: python tools/extract_features.py --docs docs --out tests/features\n"
        "# Edit the scenario in its owning document under docs/ instead.\n\n"
        f"Feature: {description}\n\n"
    )
    return header + "\n".join(s.render() for s in sorted(scenarios, key=lambda s: s.sid))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--docs", type=Path, default=Path("docs"))
    ap.add_argument("--out", type=Path, default=Path("tests/features"))
    ap.add_argument("--check", action="store_true",
                    help="fail if on-disk output differs from generated")
    args = ap.parse_args()

    all_scenarios: list[Scenario] = []
    for md in sorted(args.docs.glob("*.md")):
        all_scenarios.extend(parse(md))

    if not all_scenarios:
        print(f"no scenarios found under {args.docs}", file=sys.stderr)
        return 1

    # Validation
    failed = False
    seen: dict[str, Scenario] = {}
    for s in all_scenarios:
        if s.sid in seen:
            print(f"ERROR duplicate scenario id {s.sid}: "
                  f"{seen[s.sid].source} and {s.source}", file=sys.stderr)
            failed = True
        seen[s.sid] = s
        for p in s.problems():
            print(f"ERROR {s.sid} ({s.source}:{s.line}): {p}", file=sys.stderr)
            failed = True
        if s.domain not in DOMAINS:
            print(f"ERROR {s.sid}: unknown domain prefix", file=sys.stderr)
            failed = True

    if failed:
        return 1

    by_domain: dict[str, list[Scenario]] = {}
    for s in all_scenarios:
        by_domain.setdefault(s.domain, []).append(s)

    args.out.mkdir(parents=True, exist_ok=True)
    drift = False
    for domain, scenarios in sorted(by_domain.items()):
        name, _ = DOMAINS[domain]
        target = args.out / f"{name}.feature"
        content = render_feature(domain, scenarios)
        if args.check:
            existing = target.read_text(encoding="utf-8") if target.exists() else ""
            if existing != content:
                print(f"DRIFT {target} differs from the documents", file=sys.stderr)
                drift = True
        else:
            target.write_text(content, encoding="utf-8")
            print(f"{target}  ({len(scenarios)} scenarios)")

    if args.check and drift:
        print("\nRegenerate feature files and commit them.", file=sys.stderr)
        return 1

    print(f"\n{len(all_scenarios)} scenarios across {len(by_domain)} feature files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
