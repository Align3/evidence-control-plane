"""ES-035 and CM-025: the published version registries.

A verifier obliged to support "every published version" of a set nobody wrote
down cannot check membership at all, so these tests are about the *closure* of
the sets rather than about any one version in them.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from sdk_python.evidence.versions import (
    METHODOLOGY_VERSION_REGISTRY,
    SCHEMA_VERSION_REGISTRY,
    UnpublishedVersionError,
    VersionStatus,
    published_versions,
    require_published_methodology_version,
    require_published_schema_version,
)

DOCS = Path(__file__).resolve().parents[2] / "docs"


@pytest.mark.parametrize(
    "version", ["0.9.0", "1.0.1", "1.1.0", "3.0.0", "1.0.0-rc1", "", "latest"]
)
def test_an_unpublished_schema_version_is_refused(version: str) -> None:
    """ES-S-024: and not verified under a neighbouring version's rules."""

    with pytest.raises(UnpublishedVersionError, match="not a published version"):
        require_published_schema_version(version)


def test_a_reserved_schema_version_is_refused_rather_than_guessed_at() -> None:
    """2.0.0 exists in the table and is still a refusal.

    ES-031 changes the constitutive-record enumeration at that version. Its
    rules are allocated, not written; verifying under 1.0.0's rules because
    they are the nearest available is exactly the inference ES-035 forbids.
    """

    with pytest.raises(UnpublishedVersionError, match="reserved"):
        require_published_schema_version("2.0.0")
    assert SCHEMA_VERSION_REGISTRY["2.0.0"] is VersionStatus.RESERVED
    assert "2.0.0" not in published_versions(SCHEMA_VERSION_REGISTRY)


def test_reserved_and_absent_are_distinguished_in_the_diagnostic() -> None:
    with pytest.raises(UnpublishedVersionError) as absent:
        require_published_schema_version("4.0.0")
    with pytest.raises(UnpublishedVersionError) as reserved:
        require_published_schema_version("2.0.0")
    assert str(absent.value) != str(reserved.value)


def test_the_published_schema_version_is_accepted() -> None:
    assert require_published_schema_version("1.0.0") == "1.0.0"


@pytest.mark.parametrize("version", ["0.1", "0.1.0", "2.0.0", "Draft v0.1"])
def test_an_unpublished_methodology_version_is_refused(version: str) -> None:
    """CM-S-011, including the prose status line's own spelling.

    "Draft v0.1" is a different namespace from the ``methodology_version``
    values attestations carry, which is the confusion CM-025 was written to
    end; it must not be accepted merely because it appears in the document.
    """

    with pytest.raises(UnpublishedVersionError, match="methodology_version"):
        require_published_methodology_version(version)


def test_the_published_methodology_version_is_accepted() -> None:
    assert require_published_methodology_version("1.0.0") == "1.0.0"


@pytest.mark.parametrize(
    "value", [None, 1, 1.0, True, ["1.0.0"], {"version": "1.0.0"}]
)
def test_a_non_string_version_is_refused(value: object) -> None:
    with pytest.raises(UnpublishedVersionError):
        require_published_schema_version(value)
    with pytest.raises(UnpublishedVersionError):
        require_published_methodology_version(value)


def test_neither_registry_can_be_widened_by_a_caller() -> None:
    with pytest.raises(TypeError):
        SCHEMA_VERSION_REGISTRY["9.9.9"] = VersionStatus.PUBLISHED  # type: ignore[index]
    with pytest.raises(TypeError):
        METHODOLOGY_VERSION_REGISTRY["9.9.9"] = VersionStatus.PUBLISHED  # type: ignore[index]


def _table_rows(document: Path, heading: str, column: str) -> dict[str, str]:
    text = document.read_text(encoding="utf-8")
    start = text.index(heading)
    table = text[start : text.index("\n\n", text.index(f"| `{column}`", start))]
    rows = {}
    for line in table.splitlines():
        match = re.match(r"^\|\s*`([^`]+)`\s*\|\s*([^|]+?)\s*\|", line)
        if match and match.group(1) != column:  # skip the header row
            rows[match.group(1)] = match.group(2)
    return rows


def test_the_schema_registry_transcribes_the_es_035_table() -> None:
    """The registry is data copied from a document; drift is the failure mode."""

    rows = _table_rows(DOCS / "evidence-spec.md", "**ES-035", "schema_version")
    assert set(rows) == set(SCHEMA_VERSION_REGISTRY)
    for version, status in rows.items():
        expected = (
            VersionStatus.PUBLISHED
            if status.strip() == "published"
            else VersionStatus.RESERVED
        )
        assert SCHEMA_VERSION_REGISTRY[version] is expected


def test_the_methodology_registry_transcribes_the_cm_025_table() -> None:
    rows = _table_rows(
        DOCS / "coverage-methodology.md", "**CM-025", "methodology_version"
    )
    assert set(rows) == set(METHODOLOGY_VERSION_REGISTRY)
    for version, status in rows.items():
        assert status.strip() == "published"
        assert METHODOLOGY_VERSION_REGISTRY[version] is VersionStatus.PUBLISHED
