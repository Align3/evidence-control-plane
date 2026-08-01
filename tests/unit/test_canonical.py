"""Focused RFC 8785 and ES-001..003 tests."""

from __future__ import annotations

import pytest

from sdk_python.evidence.canonical import CanonicalizationError, canonical_digest, canonicalize


def test_jcs_uses_utf16_code_unit_key_order() -> None:
    # U+1F600 sorts before U+E000 by UTF-16 code units. Python code-point
    # ordering produces the opposite order, so this catches sort_keys shortcuts.
    assert canonicalize({"\ue000": 1, "😀": 2}) == '{"😀":2,"\ue000":1}'.encode()


def test_jcs_matches_the_rfc_8785_property_sorting_vector() -> None:
    value = {
        "€": "Euro Sign",
        "\r": "Carriage Return",
        "דּ": "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        "😀": "Emoji: Grinning Face",
        "\u0080": "Control",
        "ö": "Latin Small Letter O With Diaeresis",
    }
    expected = (
        '{"\\r":"Carriage Return","1":"One","\u0080":"Control",'
        '"ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign",'
        '"😀":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}'
    )
    assert canonicalize(value) == expected.encode()


def test_jcs_uses_ecmascript_string_escaping() -> None:
    value = {"text": "\b\t\n\f\r\u0000\u001f\\\"/€"}
    assert canonicalize(value) == b'{"text":"\\b\\t\\n\\f\\r\\u0000\\u001f\\\\\\\"/\xe2\x82\xac"}'


def test_digest_has_required_algorithm_prefix_and_lowercase_hex() -> None:
    assert canonical_digest({"a": 1}) == (
        "sha256:015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5ceb"
        "eae62276a97f862"
    )


@pytest.mark.parametrize(
    "invalid",
    [
        {"value": 1.0},
        {"nested": [0, {"value": float("nan")}]},
        {"too_large": 9_007_199_254_740_992},
        {1: "non-string key"},
        {"surrogate": "\ud800"},
    ],
)
def test_canonicalization_refuses_values_that_cannot_be_portable_jcs(invalid: object) -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize(invalid)
