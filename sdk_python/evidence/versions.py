"""Published version registries (ES-035, CM-025).

Both requirements exist because ES-027 and CM-023 oblige a verifier to support
"every published version" of sets that no document enumerated.  Membership of a
set nobody wrote down cannot be checked, so each registry is transcribed here
as data and consulted before any version-dependent rule is applied.

Two states are distinguished and they fail for different reasons.  A version
*absent* from the registry was never published and there are no rules to apply.
A version listed as *reserved* has been allocated but its rules are not yet
written, and ES-035 requires refusing it rather than guessing at them.  Both are
refusals; keeping them apart means the diagnostic says which mistake was made.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType
from typing import Final


class VersionStatus(StrEnum):
    """The publication states ES-035's table distinguishes."""

    PUBLISHED = "published"
    RESERVED = "reserved"


class UnpublishedVersionError(ValueError):
    """A version outside the published set of its registry."""


#: ES-035.  Adding a row is a specification change requiring a vector.
SCHEMA_VERSION_REGISTRY: Final[Mapping[str, VersionStatus]] = MappingProxyType(
    {
        "1.0.0": VersionStatus.PUBLISHED,
        # ES-031 changes the constitutive-record enumeration at this version.
        # No implementation supports it and no vector carries it.
        "2.0.0": VersionStatus.RESERVED,
    }
)

#: CM-025.  Adding a row is a material change under CM-024.
METHODOLOGY_VERSION_REGISTRY: Final[Mapping[str, VersionStatus]] = MappingProxyType(
    {
        "1.0.0": VersionStatus.PUBLISHED,
    }
)


def _require_published(
    value: object,
    *,
    registry: Mapping[str, VersionStatus],
    label: str,
) -> str:
    if not isinstance(value, str):
        raise UnpublishedVersionError(f"{label} is required and must be a string")
    status = registry.get(value)
    if status is None:
        raise UnpublishedVersionError(
            f"{label} {value!r} is not a published version: "
            f"published versions are {sorted(published_versions(registry))}"
        )
    if status is not VersionStatus.PUBLISHED:
        raise UnpublishedVersionError(
            f"{label} {value!r} is reserved and not yet published: its rules are not "
            "written, and a verifier must refuse rather than guess at them"
        )
    return value


def published_versions(registry: Mapping[str, VersionStatus]) -> frozenset[str]:
    """Return only the versions a verifier is obliged to support."""

    return frozenset(
        version
        for version, status in registry.items()
        if status is VersionStatus.PUBLISHED
    )


def require_published_schema_version(value: object) -> str:
    """ES-035: refuse a ``schema_version`` outside the published set."""

    return _require_published(
        value, registry=SCHEMA_VERSION_REGISTRY, label="schema_version"
    )


def require_published_methodology_version(value: object) -> str:
    """CM-025: refuse a ``methodology_version`` outside the published set."""

    return _require_published(
        value, registry=METHODOLOGY_VERSION_REGISTRY, label="methodology_version"
    )
