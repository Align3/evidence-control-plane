"""RFC 8785 JSON Canonicalization Scheme (JCS) for evidence records.

Evidence records deliberately exclude IEEE-754 values (ES-002), and ES-002a
requires a conformant canonicalizer to *reject* rather than serialize any
non-integer number, any integer outside the interoperable safe range, and the
non-JSON tokens NaN/Infinity. The ECMAScript number-serialization portion of
JCS therefore reduces to safe integers and never executes against conformant
input, which is what lets an independent implementation agree with this one
without either side implementing floating-point formatting. The remaining
rules are implemented directly: UTF-16 property ordering, minimal string
escaping, UTF-8 output, and whitespace-free syntax.

This module MUST NOT be shared with the Go verifier (AC-011).
"""

from __future__ import annotations

from hashlib import sha256

from pydantic import BaseModel

MAX_SAFE_INTEGER = 9_007_199_254_740_991


class CanonicalizationError(ValueError):
    """Raised when a value cannot be represented as portable JCS JSON."""


def _utf16_sort_key(value: str) -> bytes:
    """Return RFC 8785's lexicographic UTF-16 code-unit ordering key."""

    try:
        return value.encode("utf-16-be")
    except UnicodeEncodeError as exc:
        raise CanonicalizationError("JSON strings must not contain lone surrogates") from exc


def _quote(value: str) -> str:
    # RFC 8785 delegates string serialization to ECMAScript JSON.stringify:
    # escape control characters, quote and reverse solidus; emit all other
    # Unicode code points verbatim.
    escapes = {
        "\b": "\\b",
        "\t": "\\t",
        "\n": "\\n",
        "\f": "\\f",
        "\r": "\\r",
        '"': '\\"',
        "\\": "\\\\",
    }
    pieces = ['"']
    for character in value:
        code_point = ord(character)
        if 0xD800 <= code_point <= 0xDFFF:
            raise CanonicalizationError("JSON strings must not contain lone surrogates")
        if character in escapes:
            pieces.append(escapes[character])
        elif code_point <= 0x1F:
            pieces.append(f"\\u{code_point:04x}")
        else:
            pieces.append(character)
    pieces.append('"')
    return "".join(pieces)


def _serialize(value: object) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise CanonicalizationError(
                "ES-002a: integer is outside the interoperable JCS range"
            )
        return str(value)
    if isinstance(value, float):
        # ES-002a: reject rather than apply RFC 8785 ECMAScript number rules.
        raise CanonicalizationError("IEEE-754 floats are forbidden in signed records")
    if isinstance(value, str):
        return _quote(value)
    if isinstance(value, list):
        return "[" + ",".join(_serialize(item) for item in value) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise CanonicalizationError("JSON object keys must be strings")
        keys = sorted(value, key=_utf16_sort_key)
        return "{" + ",".join(f"{_quote(key)}:{_serialize(value[key])}" for key in keys) + "}"
    raise CanonicalizationError(f"unsupported JSON value type: {type(value).__name__}")


def canonicalize(value: object) -> bytes:
    """Serialize a JSON value or Pydantic model to RFC 8785 canonical bytes."""

    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json", exclude_unset=True)
    return _serialize(value).encode("utf-8")


def canonical_digest(value: object) -> str:
    """Return the ES-003 digest of a value's canonical representation."""

    return f"sha256:{sha256(canonicalize(value)).hexdigest()}"
