"""Mutation guards: proof that the tests above would notice being wrong.

A passing suite says nothing about whether it *could* fail.  AR-030's
discriminator and AR-031's boundary are single operators, and both have a
plausible inverse that a careless reading produces — ``is None`` for
``is not None``, ``>=`` for ``>``.  Each mutant below is compiled from the real
module source with one operator changed, and the same assertions the ordinary
tests make are then required to fail against it.

A mutant that still passes is the finding: it means the assertion was decorative
and the requirement is undemonstrated regardless of how green the suite is.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

from sdk_python.evidence.canonical import canonicalize
from sdk_python.evidence.instants import parse_instant
from sdk_python.evidence.revocation import RevocationStatus
from sdk_python.evidence.schema import RevocationRecord
from tests.bundle_support import (
    bundle_bytes,
    linked_evidence_stream,
    signed_attestation,
    signed_revocation,
    verification_keys,
)

SDK = Path(__file__).resolve().parents[2] / "sdk_python" / "evidence"
NOW = "2026-08-01T12:00:00.000Z"


def _mutant(module_name: str, original: str, replacement: str) -> ModuleType:
    """Compile a one-decision mutation of a real module."""

    source = (SDK / f"{module_name}.py").read_text(encoding="utf-8")
    occurrences = source.count(original)
    assert occurrences == 1, (
        f"the mutation target appears {occurrences} times in {module_name}.py; it "
        "must select exactly one decision or the mutant proves nothing"
    )
    name = f"mutant_{module_name}"
    mutated = ModuleType(name)
    mutated.__dict__["__file__"] = str(SDK / f"{module_name}.py")
    # Dataclass field resolution looks the defining module up by name.
    sys.modules[name] = mutated
    try:
        exec(  # noqa: S102 - compiling a deliberate mutant is this file's purpose
            compile(
                source.replace(original, replacement), f"<mutant {module_name}>", "exec"
            ),
            mutated.__dict__,
        )
    finally:
        sys.modules.pop(name, None)
    return mutated


SUPERSESSION_DECISION = """        RevocationStatus.SUPERSEDED
        if superseding_ref is not None
        else RevocationStatus.REVOKED"""


def _classified(module: ModuleType, effective_at: str, superseding_ref: str | None):
    record = signed_revocation(
        attestation_ref="01890f47-2f58-7cc0-98c4-000000000001",
        effective_at=effective_at,
        superseding_ref=superseding_ref,
    )
    assert isinstance(record, RevocationRecord)
    return module.classify_revocation(record, evaluated_at=parse_instant(NOW))


# --------------------------------------------------------------------------
# AR-030 — the superseding_ref discriminator
# --------------------------------------------------------------------------


def test_inverting_the_superseding_discriminator_fails_the_assertions() -> None:
    mutant = _mutant(
        "revocation",
        SUPERSESSION_DECISION,
        SUPERSESSION_DECISION.replace("SUPERSEDED", "_TMP")
        .replace("REVOKED", "SUPERSEDED")
        .replace("_TMP", "REVOKED"),
    )

    superseded = _classified(mutant, "2026-07-01T00:00:00.000Z", "attestation-2")
    revoked = _classified(mutant, "2026-07-01T00:00:00.000Z", None)

    # The real implementation reports SUPERSEDED and REVOKED respectively.
    assert superseded.status != RevocationStatus.SUPERSEDED
    assert revoked.status != RevocationStatus.REVOKED
    # And the mutant is not merely different, it is exactly inverted.
    assert superseded.status == RevocationStatus.REVOKED
    assert revoked.status == RevocationStatus.SUPERSEDED


def test_a_discriminator_that_always_supersedes_fails_the_assertions() -> None:
    """The other plausible slip: reading `reason` and defaulting the state."""

    mutant = _mutant(
        "revocation",
        SUPERSESSION_DECISION,
        SUPERSESSION_DECISION.replace(
            "if superseding_ref is not None", "if superseding_ref is not None or True"
        ),
    )
    assert (
        _classified(mutant, "2026-07-01T00:00:00.000Z", None).status
        != RevocationStatus.REVOKED
    )


# --------------------------------------------------------------------------
# AR-031 — the effective-date comparison
# --------------------------------------------------------------------------


def test_relaxing_the_effective_date_boundary_fails_the_equality_case() -> None:
    """`>=` for `>` moves the exact boundary AR-031 pins, and nothing else.

    This is the mutation a test suite is most likely to miss, because every
    strictly-before and strictly-after case still passes against it.
    """

    mutant = _mutant(
        "revocation",
        "if effective_at > evaluated_at:",
        "if effective_at >= evaluated_at:",
    )

    # Strictly later and strictly earlier are unchanged: the mutant survives
    # any suite that only tests those.
    assert _classified(mutant, "2026-08-01T12:00:00.001Z", None).status == (
        RevocationStatus.VALID
    )
    assert _classified(mutant, "2026-08-01T11:59:59.999Z", None).status == (
        RevocationStatus.REVOKED
    )
    # The boundary case is what catches it.
    assert _classified(mutant, NOW, None).status != RevocationStatus.REVOKED
    assert _classified(mutant, NOW, None).status == RevocationStatus.VALID


def test_inverting_the_effective_date_comparison_fails_the_assertions() -> None:
    mutant = _mutant(
        "revocation",
        "if effective_at > evaluated_at:",
        "if effective_at < evaluated_at:",
    )

    assert _classified(mutant, "2026-08-01T12:00:00.001Z", None).status != (
        RevocationStatus.VALID
    )
    assert _classified(mutant, "2026-08-01T11:59:59.999Z", None).status != (
        RevocationStatus.REVOKED
    )


def test_comparing_timestamps_as_strings_fails_the_offset_case() -> None:
    """AR-031's "never on strings", stated as a mutation.

    Lexically `13:00:00.000+01:00` sorts after `12:00:00.000Z`, so a string
    comparison reports a revocation already in effect as still pending.
    """

    zulu = "2026-08-01T12:00:00.000Z"
    offset = "2026-08-01T13:00:00.000+01:00"
    assert parse_instant(zulu).same_instant_as(parse_instant(offset))
    assert offset > zulu  # the mutant's verdict
    assert not parse_instant(offset) > parse_instant(zulu)  # the real one


# --------------------------------------------------------------------------
# AR-029 — the unchecked default
# --------------------------------------------------------------------------


def test_treating_an_unrecognised_answer_as_nothing_published_fails() -> None:
    """AR-029's asymmetry: the opposite default is wrong and fatal."""

    mutant = _mutant(
        "revocation",
        "if response.status_code == NOT_FOUND:",
        "if response.status_code != OK:",
    )
    attestation = signed_attestation()
    outcome = mutant.check_revocation(
        attestation,
        endpoint="https://issuer.example.invalid/api",
        transport=lambda url: mutant.RevocationResponse(503),
        verification_keys=verification_keys(),
        evaluated_at=NOW,
    )
    assert outcome.status != RevocationStatus.UNCHECKED
    assert outcome.status == RevocationStatus.VALID


# --------------------------------------------------------------------------
# ES-034 — routing by record_type rather than by position
# --------------------------------------------------------------------------


def test_routing_by_position_misfiles_the_adversarial_bundle() -> None:
    """The mutation makes the index the role, which is the defect ES-034 rules out."""

    mutant = _mutant(
        "bundle",
        "index.setdefault(record.record_type, []).append(record)",
        "index.setdefault(_POSITIONAL[len(index)], []).append(record)",
    )
    mutant.__dict__["_POSITIONAL"] = [
        "PopulationRecord",
        "CoverageGap",
        "AttestationWindow",
    ]

    gap, attestation = linked_evidence_stream()
    raw = bundle_bytes([gap, attestation])

    # The real parser files the gap as a gap.
    from sdk_python.evidence.bundle import parse_bundle

    real = parse_bundle(raw, verification_keys=verification_keys())
    assert [record.record_id for record in real.of_type("CoverageGap")] == [
        gap.record_id
    ]

    # The positional mutant files it as the denominator, and then cannot even
    # find the attestation it is required to carry.
    with pytest.raises(Exception) as raised:
        mutant.parse_bundle(raw, verification_keys=verification_keys())
    assert "AttestationWindow" in str(raised.value)


def test_accepting_a_keyed_container_would_admit_a_misfiled_record() -> None:
    """Why the shape refusal is not merely pedantry.

    With the array requirement removed, a container whose keys disagree with
    its contents parses, and the record's role is then whatever the assembler
    wrote — a statement no signature covers.
    """

    gap, attestation = linked_evidence_stream()
    keyed = canonicalize(
        {
            "PopulationRecord": [json.loads(canonicalize(gap))],
            "AttestationWindow": [json.loads(canonicalize(attestation))],
        }
    )

    from sdk_python.evidence.bundle import BundleShapeError, parse_bundle

    with pytest.raises(BundleShapeError):
        parse_bundle(keyed, verification_keys=verification_keys())

    # Demonstrate what acceptance would have meant: the keys say the
    # CoverageGap is the denominator, and nothing in the record agrees.
    decoded = json.loads(keyed)
    assert decoded["PopulationRecord"][0]["record_type"] == "CoverageGap"
