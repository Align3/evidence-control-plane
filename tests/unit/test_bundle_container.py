"""ES-034: the bundle container, and the misfiling it must make impossible.

Negative-first per AG-007.  The question asked of every test here is not "does
the bundle parse" but "under what input would this report a record's role
wrongly, and does it refuse instead".
"""

from __future__ import annotations

import json

import pytest

from sdk_python.evidence.bundle import (
    BrokenStreamLinkError,
    BundleCardinalityError,
    BundleOrderError,
    BundleShapeError,
    NonCanonicalBundleError,
    assemble_bundle,
    parse_bundle,
)
from sdk_python.evidence.canonical import canonical_digest, canonicalize
from sdk_python.evidence.versions import UnpublishedVersionError
from tests.bundle_support import (
    as_json,
    bundle_bytes,
    linked_evidence_stream,
    raw_bundle_bytes,
    signed_attestation,
    signed_coverage_gap,
    signed_population,
    verification_keys,
)

# --------------------------------------------------------------------------
# The container shape itself
# --------------------------------------------------------------------------


def test_a_keyed_container_is_refused_rather_than_read() -> None:
    """The defective shape is refused at the door, not corrected on the way in.

    A mapping from role name to record makes each record's role a second
    statement, supplied by the assembler and outside the signature that covers
    the record.  ES-034 says the role "is read from its own record_type and from
    nowhere else", which a keyed container cannot honour even when its keys
    happen to be right: the parser would have to choose which of two statements
    to believe, and the safe choice is to have only one.
    """

    gap = signed_coverage_gap()
    attestation = signed_attestation()
    keyed = json.dumps(
        {"attestation": as_json(attestation), "gaps": [as_json(gap)]},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()

    with pytest.raises(BundleShapeError, match="array"):
        parse_bundle(keyed, verification_keys=verification_keys())


def test_a_keyed_container_with_correct_keys_is_still_refused() -> None:
    """Refusal is of the shape, not of a mismatch within it.

    Accepting a keyed container whose keys agree with its contents would make
    the check a consistency test between two statements rather than a rule that
    there is only one statement, and the next assembler to disagree with itself
    would then be the first to discover it.
    """

    attestation = signed_attestation()
    keyed = canonicalize({"AttestationWindow": [as_json(attestation)]})

    with pytest.raises(BundleShapeError, match="array"):
        parse_bundle(keyed, verification_keys=verification_keys())


def test_a_bare_record_is_not_a_bundle() -> None:
    attestation = signed_attestation()
    with pytest.raises(BundleShapeError, match="array"):
        parse_bundle(canonicalize(attestation), verification_keys=verification_keys())


def test_a_non_object_element_is_refused() -> None:
    attestation = signed_attestation()
    raw = raw_bundle_bytes(["not-a-record", as_json(attestation)])
    with pytest.raises(BundleShapeError, match="complete signed record"):
        parse_bundle(raw, verification_keys=verification_keys())


# --------------------------------------------------------------------------
# Routing: a record's role comes from the record (ES-S-022)
# --------------------------------------------------------------------------


def _gap_index(raw: bytes) -> int:
    elements = json.loads(raw)
    return next(
        index
        for index, element in enumerate(elements)
        if element["record_type"] == "CoverageGap"
    )


def test_position_cannot_override_record_type() -> None:
    """The same CoverageGap, at two different container positions, one verdict.

    The two bundles differ only in whether a PopulationRecord is disclosed, and
    that alone moves the gap from index 0 to index 1 because ES-034 orders
    elements by canonical bytes.  Any implementation that read a role from an
    index would answer these two differently.
    """

    gap, attestation = linked_evidence_stream()
    keys = verification_keys()

    without_population = bundle_bytes([gap, attestation])
    with_population = bundle_bytes([gap, attestation, signed_population()])
    assert _gap_index(without_population) != _gap_index(with_population)

    for raw in (without_population, with_population):
        bundle = parse_bundle(raw, verification_keys=keys)
        classified = bundle.of_type("CoverageGap")
        assert [record.record_id for record in classified] == [gap.record_id]
        assert gap.record_id not in {
            record.record_id for record in bundle.of_type("PopulationRecord")
        }
        assert bundle.attestation.record_id == attestation.record_id


def test_a_positional_convention_would_have_misfiled_this_bundle() -> None:
    """The adversarial input, and proof that it discriminates.

    Selective disclosure is the attack surface.  ES-026 lets a bundle withhold
    the PopulationRecord, and withholding it shifts every remaining index by
    one — so a reader that expects the denominator at index 0 finds a
    CoverageGap there and files it as the denominator.  Nothing about the gap
    changed; only what was disclosed alongside it.  The convention is written
    out here and shown to disagree with the record on the same bytes, because
    without that the position-independence test above could pass against an
    implementation that reads positions and merely happens to agree.
    """

    gap, attestation = linked_evidence_stream()
    raw = bundle_bytes([gap, attestation])
    elements = json.loads(raw)

    # A plausible, wrong convention: the first element is the population, the
    # last is the attestation, everything between is a gap.
    positional_population_ids = {elements[0]["record_id"]}
    positional_gap_ids = {element["record_id"] for element in elements[1:-1]}

    bundle = parse_bundle(raw, verification_keys=verification_keys())
    actual_gap_ids = {record.record_id for record in bundle.of_type("CoverageGap")}
    actual_population_ids = {
        record.record_id for record in bundle.of_type("PopulationRecord")
    }

    assert actual_gap_ids == {gap.record_id}
    assert actual_population_ids == set()
    # The gap is misfiled as the denominator by position, and correctly as a
    # gap by its own record_type.
    assert positional_population_ids == {gap.record_id}
    assert positional_population_ids != actual_population_ids
    assert positional_gap_ids != actual_gap_ids


def test_every_indexed_record_is_indexed_under_its_own_record_type() -> None:
    gap, attestation = linked_evidence_stream()
    bundle = parse_bundle(
        bundle_bytes([gap, attestation, signed_population()]),
        verification_keys=verification_keys(),
    )
    for record_type, group in bundle.by_type.items():
        assert all(record.record_type == record_type for record in group)
    assert sum(len(group) for group in bundle.by_type.values()) == len(bundle.records)


# --------------------------------------------------------------------------
# Cardinality
# --------------------------------------------------------------------------


def test_a_bundle_without_an_attestation_is_refused() -> None:
    with pytest.raises(BundleCardinalityError, match="exactly one"):
        parse_bundle(
            bundle_bytes([signed_coverage_gap()]), verification_keys=verification_keys()
        )


def test_two_attestations_are_refused() -> None:
    first = signed_attestation(record_id="01890f47-2f58-7cc0-98c4-000000000001")
    second = signed_attestation(record_id="01890f47-2f58-7cc0-98c4-000000000009")
    with pytest.raises(BundleCardinalityError, match="exactly one"):
        parse_bundle(
            bundle_bytes([first, second]), verification_keys=verification_keys()
        )


def test_many_gaps_are_permitted() -> None:
    attestation = signed_attestation()
    gaps = [
        signed_coverage_gap(
            record_id=f"01890f47-2f58-7cc0-98c4-00000000001{index}",
            stream_id=f"gap-collector-{index}",
            cause=cause,
        )
        for index, cause in enumerate(("fail_open", "sequence_break", "clock_skew"))
    ]
    bundle = parse_bundle(
        bundle_bytes([attestation, *gaps]), verification_keys=verification_keys()
    )
    assert len(bundle.of_type("CoverageGap")) == 3
    assert bundle.boundary is None


# --------------------------------------------------------------------------
# Canonical form and element order
# --------------------------------------------------------------------------


def test_a_non_canonical_bundle_fails_naming_the_canonical_form() -> None:
    """ES-S-023: the failure names the canonical form rather than a signature."""

    attestation = signed_attestation()
    pretty = json.dumps([as_json(attestation)], indent=2).encode()

    with pytest.raises(NonCanonicalBundleError) as raised:
        parse_bundle(pretty, verification_keys=verification_keys())
    message = str(raised.value).lower()
    assert "canonical" in message
    assert "signature" not in message


def test_reordered_object_members_within_an_element_are_non_canonical() -> None:
    attestation = signed_attestation()
    element = as_json(attestation)
    reversed_members = json.dumps(
        {key: element[key] for key in reversed(list(element))}, separators=(",", ":")
    )
    with pytest.raises(NonCanonicalBundleError):
        parse_bundle(
            f"[{reversed_members}]".encode(), verification_keys=verification_keys()
        )


def test_elements_out_of_canonical_byte_order_are_refused() -> None:
    gap, attestation = linked_evidence_stream()
    ordered = json.loads(bundle_bytes([gap, attestation]))
    reversed_bundle = raw_bundle_bytes(list(reversed(ordered)))

    with pytest.raises(BundleOrderError, match="ascending"):
        parse_bundle(reversed_bundle, verification_keys=verification_keys())


def test_assembly_produces_one_artifact_regardless_of_producer_order() -> None:
    """QA-008 compares bundles byte-for-byte; the order must not be an input."""

    gap, attestation = linked_evidence_stream()
    population = signed_population()
    first = assemble_bundle([gap, attestation, population])
    second = assemble_bundle([population, gap, attestation])
    assert first == second
    parse_bundle(first, verification_keys=verification_keys())


# --------------------------------------------------------------------------
# Signatures and version registries, applied per element
# --------------------------------------------------------------------------


def test_an_unsigned_element_is_refused() -> None:
    gap, attestation = linked_evidence_stream()
    tampered = as_json(gap)
    tampered["body"]["detection_source"] = "someone-else"
    raw = raw_bundle_bytes(sorted([tampered, as_json(attestation)], key=canonicalize))

    with pytest.raises(Exception) as raised:
        parse_bundle(raw, verification_keys=verification_keys())
    assert not isinstance(raised.value, NonCanonicalBundleError)


def test_an_element_carrying_a_reserved_schema_version_is_refused() -> None:
    attestation = signed_attestation(schema_version="2.0.0")
    with pytest.raises(UnpublishedVersionError, match="reserved"):
        parse_bundle(
            bundle_bytes([attestation]), verification_keys=verification_keys()
        )


def test_an_attestation_computed_under_an_unpublished_methodology_is_refused() -> None:
    attestation = signed_attestation(methodology_version="9.9.9")
    with pytest.raises(UnpublishedVersionError, match="methodology_version"):
        parse_bundle(
            bundle_bytes([attestation]), verification_keys=verification_keys()
        )


# --------------------------------------------------------------------------
# ES-026 selective disclosure and the ES-006a links a slice can carry
# --------------------------------------------------------------------------


def test_a_slice_need_not_be_anchored_at_sequence_one() -> None:
    """ES-034 forbids requiring a complete stream inside a bundle."""

    gap = signed_coverage_gap(sequence=7, prev_digest=canonical_digest(["earlier"]))
    attestation = signed_attestation(sequence=8, prev_digest=canonical_digest(gap))
    bundle = parse_bundle(
        bundle_bytes([gap, attestation]), verification_keys=verification_keys()
    )
    assert [link.checked for link in bundle.stream_links] == [True]


def test_a_link_across_an_omission_is_unchecked_not_verified_or_broken() -> None:
    gap = signed_coverage_gap(sequence=1)
    attestation = signed_attestation(
        sequence=5, prev_digest=canonical_digest(["a record not in this bundle"])
    )
    bundle = parse_bundle(
        bundle_bytes([gap, attestation]), verification_keys=verification_keys()
    )
    assert [link.checked for link in bundle.stream_links] == [False]
    assert bundle.unchecked_links[0].from_sequence == 1
    assert bundle.unchecked_links[0].to_sequence == 5


def test_a_broken_consecutive_link_is_refused_rather_than_reported_unchecked() -> None:
    gap = signed_coverage_gap(sequence=1)
    attestation = signed_attestation(
        sequence=2, prev_digest=canonical_digest(["the wrong predecessor"])
    )
    with pytest.raises(BrokenStreamLinkError, match="predecessor"):
        parse_bundle(
            bundle_bytes([gap, attestation]), verification_keys=verification_keys()
        )


def test_two_records_at_one_sequence_in_a_stream_are_refused() -> None:
    gap = signed_coverage_gap(
        record_id="01890f47-2f58-7cc0-98c4-000000000002", sequence=1
    )
    other = signed_coverage_gap(
        record_id="01890f47-2f58-7cc0-98c4-000000000012",
        sequence=1,
        cause="fail_open",
    )
    attestation = signed_attestation(sequence=2, prev_digest=canonical_digest(gap))
    with pytest.raises(BundleCardinalityError, match="sequence"):
        parse_bundle(
            bundle_bytes([gap, other, attestation]),
            verification_keys=verification_keys(),
        )
