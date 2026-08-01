"""Differential test: canonicalize() against an independent ECMAScript JCS.

Every other property test in this suite is self-referential -- determinism,
byte-stability across processes, invariance to input ordering. All of them
still pass if the canonicalizer is consistently wrong, which is the defect
class ES-S-007 exists to catch and which cannot be tested against the real Go
verifier until EV-05. This test closes that window using the reference in
``jcs_reference.js``; see that file for why ECMAScript is a legitimate oracle
for RFC 8785 and why this does not violate AC-011.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from sdk_python.evidence.canonical import CanonicalizationError, canonicalize

REFERENCE = Path(__file__).with_name("jcs_reference.js")

pytestmark = pytest.mark.skipif(
    shutil.which("node") is None,
    reason="node is required for the independent JCS reference",
)

C = chr
SAFE_INTEGER = 9_007_199_254_740_991


def _reference(cases: list[Any]) -> list[str]:
    completed = subprocess.run(  # noqa: S603 - fixed interpreter, static script
        [shutil.which("node") or "node", str(REFERENCE)],
        input=json.dumps(cases, ensure_ascii=True).encode(),
        capture_output=True,
        check=True,
    )
    decoded: list[str] = json.loads(completed.stdout)
    return decoded


def _actual(value: Any) -> str:
    try:
        return canonicalize(value).decode()
    except CanonicalizationError as exc:  # pragma: no cover - corpus is valid
        return f"ERROR:{exc}"


# Cases chosen where a plausible-but-wrong implementation diverges: the
# surrogate boundary (code-point order disagrees with UTF-16 order), non-ASCII
# output (ensure_ascii escaping), C0 controls, and Unicode normalisation.
CORPUS: list[Any] = [
    {C(0xE000): 1, C(0x1F600): 2},
    {
        "€": "Euro Sign",
        "\r": "Carriage Return",
        "דּ": "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        C(0x1F600): "Emoji: Grinning Face",
        C(0x80): "Control",
        "ö": "Latin Small Letter O With Diaeresis",
    },
    {"text": "\b\t\n\f\r" + C(0) + '\\"/€'},
    {"ctrl": "".join(C(i) for i in range(0x20))},
    {"del": C(0x7F)},
    {"k": "Iñtërnâtiônàlizætiøn☃"},
    {"": "empty key"},
    {"a": [], "b": {}, "c": None, "d": True, "e": False},
    {"n": 0},
    {"n": -1},
    {"n": SAFE_INTEGER},
    {"n": -SAFE_INTEGER},
    {"nested": [{"b": 1, "a": 2}, [1, [2, [3]]]]},
    {C(0x10FFFF): 1, C(0xFFFF): 2, C(0xD7FF): 3},
    {C(0x10000): 1, C(0xE000): 2, C(0xFFFD): 3},
    {"ﬃ": 1, C(0x1D400): 2, "z": 3},
    {"á": 1, "á": 2},  # NFC and NFD are distinct keys, never folded
    {C(c): i for i, c in enumerate([0xD7FF, 0xE000, 0xFFFF, 0x10000, 0x1F600, 0x10FFFF, 0x41])},
]


def test_canonicalisation_matches_an_independent_implementation_on_known_edges() -> None:
    mismatches = [
        (case, expected, actual)
        for case, expected in zip(CORPUS, _reference(CORPUS), strict=True)
        if (actual := _actual(case)) != expected
    ]
    assert not mismatches, f"diverged from the ECMAScript reference: {mismatches!r}"


TEXT = st.text(st.characters(blacklist_categories=("Cs",)), max_size=8)
SCALAR = st.none() | st.booleans() | st.integers(-SAFE_INTEGER, SAFE_INTEGER) | TEXT
VALUE = st.recursive(
    SCALAR,
    lambda children: st.lists(children, max_size=3)
    | st.dictionaries(TEXT, children, max_size=4),
    max_leaves=8,
)


@given(st.lists(st.dictionaries(TEXT, VALUE, max_size=5), min_size=1, max_size=40))
@settings(
    max_examples=25,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)
def test_canonicalisation_matches_an_independent_implementation_on_random_input(
    batch: list[dict[str, Any]],
) -> None:
    for case, expected in zip(batch, _reference(batch), strict=True):
        assert _actual(case) == expected, f"diverged on {case!r}"
