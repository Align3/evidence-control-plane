"""Unit tests for the traceability matrix generator (EV-22, QA-010..012).

These run against `fixtures/sample`, a synthetic corpus in the 900 requirement
block -- never against the live `docs/` tree. The real corpus changes with every
story; asserting against it would make these tests flap for reasons that have
nothing to do with the generator.

Negative-first per AG-007: the cases that matter are the ones where the matrix
must *refuse* to report a clean link -- an unexempted orphan, an untested
scenario, an assertion with no basis, a test citing an ID that no longer
exists, and a malformed exemption that must fail closed rather than quietly
excusing a requirement.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.traceability.matrix import (
    Severity,
    build_matrix,
    expand_basis,
    expand_satisfies,
    render_json,
    render_markdown,
)

FIXTURE = Path(__file__).parent / "fixtures" / "sample"


@pytest.fixture(scope="module")
def matrix():
    node_ids = (FIXTURE / "collected.txt").read_text(encoding="utf-8").split()
    return build_matrix(
        repo_root=FIXTURE,
        docs_dir=FIXTURE / "docs",
        features_dir=FIXTURE / "tests" / "features",
        node_ids=node_ids,
    )


def subjects(matrix, kind: str) -> set[str]:
    return {f.subject for f in matrix.findings if f.kind == kind}


def severity_of(matrix, kind: str, subject: str) -> Severity:
    for f in matrix.findings:
        if f.kind == kind and f.subject == subject:
            return f.severity
    raise AssertionError(f"no {kind} finding for {subject}")


# --- the four links -------------------------------------------------------


def test_full_chain_is_linked_end_to_end(matrix):
    """CM-901 -> CM-S-901 -> test node -> A-01, the QA-010 chain."""
    req = matrix.requirements["CM-901"]
    assert req.scenarios == ("CM-S-901",)
    scenario = matrix.scenarios["CM-S-901"]
    assert scenario.tests == (
        "tests/steps/test_sample_steps.py::test_cm_s_901_coverage_ratio_withheld",
    )
    assert matrix.assertions["A-01"].basis == ("CM-901",)


def test_binding_does_not_cross_documents(matrix):
    """ES-901 sits in a second file and is unaffected by CM markers."""
    assert matrix.requirements["ES-901"].exemption is None
    assert matrix.requirements["ES-901"].scenarios == ("ES-S-901",)


def test_two_requirements_on_one_line_are_both_seen(matrix):
    """security.md:83 defines SE-019 and SE-020 in a single paragraph.

    Taking only the first match per line hid SE-020 from the matrix entirely,
    which is the worst possible failure here: a requirement nothing enforces
    and nothing reports as unenforced.
    """
    assert "ES-902" in matrix.requirements
    assert "ES-903" in matrix.requirements
    assert matrix.requirements["ES-902"].line == matrix.requirements["ES-903"].line
    assert "must not be swallowed" in matrix.requirements["ES-903"].text
    assert "must not be swallowed" not in matrix.requirements["ES-902"].text


# --- QA-011: the four failure classes -------------------------------------


def test_requirement_with_no_scenario_is_reported(matrix):
    """CM-903 has no scenario and no exemption, and a story claims it."""
    assert "CM-903" in subjects(matrix, "REQUIREMENT_NO_SCENARIO_CLAIMED")
    assert severity_of(matrix, "REQUIREMENT_NO_SCENARIO_CLAIMED", "CM-903") is Severity.HIGH


def test_unclaimed_orphan_ranks_below_a_claimed_one(matrix):
    """CM-905 is orphaned too, but nobody has committed to building it."""
    assert "CM-905" in subjects(matrix, "REQUIREMENT_NO_SCENARIO_SPEC")
    assert severity_of(matrix, "REQUIREMENT_NO_SCENARIO_SPEC", "CM-905") is Severity.MEDIUM


def test_scenario_with_no_test_is_reported(matrix):
    """CM-S-902 exists in the document and nothing implements it."""
    assert "CM-S-902" in subjects(matrix, "SCENARIO_NO_TEST")
    assert matrix.scenarios["CM-S-902"].tests == ()
    assert severity_of(matrix, "SCENARIO_NO_TEST", "CM-S-902") is Severity.HIGH


def test_assertion_with_no_requirement_is_reported(matrix):
    """A-03's basis column is empty -- AG-003 forbids emitting it."""
    assert "A-03" in subjects(matrix, "ASSERTION_NO_REQUIREMENT")
    assert severity_of(matrix, "ASSERTION_NO_REQUIREMENT", "A-03") is Severity.CRITICAL


def test_assertion_whose_only_basis_is_exempt_has_no_scenario(matrix):
    """An exempt requirement cannot be the sole basis for an emittable claim."""
    assert "A-02" in subjects(matrix, "ASSERTION_NO_SCENARIO")
    assert severity_of(matrix, "ASSERTION_NO_SCENARIO", "A-02") is Severity.CRITICAL


def test_test_citing_a_retired_requirement_is_reported(matrix):
    """The reverse case: a test naming an ID no document defines."""
    retired = {
        (f.subject, f.location)
        for f in matrix.findings
        if f.kind == "RETIRED_REQUIREMENT_REF"
    }
    cited_by_test = {
        loc for subject, loc in retired if subject == "CM-999" and "test_sample_unit" in loc
    }
    assert cited_by_test, "a test citing CM-999 must be reported"
    assert severity_of(matrix, "RETIRED_REQUIREMENT_REF", "CM-999") is Severity.CRITICAL


def test_story_citing_a_retired_requirement_is_reported(matrix):
    """EV-91 satisfies CM-999, which does not exist."""
    locations = {
        f.location for f in matrix.findings
        if f.kind == "RETIRED_REQUIREMENT_REF" and f.subject == "CM-999"
    }
    assert any("prd.md" in loc for loc in locations)


def test_assertion_citing_a_retired_requirement_is_reported(matrix):
    """A-04's basis expands to ES-901 and ES-999; only the first exists."""
    assert "ES-999" in subjects(matrix, "RETIRED_REQUIREMENT_REF")


# --- exemptions -----------------------------------------------------------


def test_properly_exempted_requirement_is_not_an_orphan(matrix):
    req = matrix.requirements["CM-902"]
    assert req.exemption is not None
    assert req.exemption.category == "process"
    assert "change-log" in req.exemption.reason
    assert "CM-902" not in subjects(matrix, "REQUIREMENT_NO_SCENARIO_CLAIMED")
    assert "CM-902" not in subjects(matrix, "REQUIREMENT_NO_SCENARIO_SPEC")


def test_exemption_survives_a_story_claiming_the_requirement(matrix):
    """EV-90 satisfies CM-901..903; CM-902 is exempt and stays exempt."""
    assert "EV-90" in matrix.requirements["CM-902"].claimed_by


def test_document_default_covers_requirements_without_their_own_marker(matrix):
    for rid in ("AG-901", "AG-902"):
        exemption = matrix.requirements[rid].exemption
        assert exemption is not None
        assert exemption.category == "meta"
        assert exemption.inherited_from == "agent-working-agreement.md"


def test_document_default_is_overridden_by_a_specific_marker(matrix):
    exemption = matrix.requirements["AG-903"].exemption
    assert exemption is not None
    assert exemption.category == "process"
    assert exemption.inherited_from is None
    assert "branch protection" in exemption.reason


def test_deferred_is_not_counted_as_a_permanent_exemption(matrix):
    exemption = matrix.requirements["CM-904"].exemption
    assert exemption is not None
    assert exemption.category == "deferred"
    assert exemption.story == "EV-99"
    assert "CM-904" in matrix.summary["deferred_ids"]
    assert "CM-904" not in matrix.summary["exempt_ids"]


def test_deferred_without_a_story_is_reported_as_debt(matrix):
    assert "CM-908" in subjects(matrix, "DEFERRED_UNASSIGNED")
    assert severity_of(matrix, "DEFERRED_UNASSIGNED", "CM-908") is Severity.MEDIUM


# --- exemptions must fail closed -----------------------------------------


def test_unknown_category_does_not_exempt_anything(matrix):
    """CM-905 carries a marker with a category outside the closed enum."""
    assert matrix.requirements["CM-905"].exemption is None
    assert "CM-905" in subjects(matrix, "MALFORMED_EXEMPTION")
    assert "CM-905" in subjects(matrix, "REQUIREMENT_NO_SCENARIO_SPEC")


def test_reason_too_short_does_not_exempt_anything(matrix):
    """A category with no argument attached is not an argument."""
    assert matrix.requirements["CM-907"].exemption is None
    assert "CM-907" in subjects(matrix, "MALFORMED_EXEMPTION")
    assert "CM-907" in subjects(matrix, "REQUIREMENT_NO_SCENARIO_SPEC")


def test_malformed_exemption_is_critical(matrix):
    """A marker nobody can read is a defect, not a silent pass."""
    assert severity_of(matrix, "MALFORMED_EXEMPTION", "CM-905") is Severity.CRITICAL


# --- feature-tag agreement ------------------------------------------------


def test_feature_tags_disagreeing_with_the_document_are_reported(matrix):
    """coverage.feature tags CM-S-902 with CM-907; the document says CM-906."""
    assert "CM-S-902" in subjects(matrix, "FEATURE_TAG_DRIFT")


def test_reference_list_carrying_prose_is_reported(matrix):
    """The live defect this caught: testing-qa.md:158 heads QA-S-002 with
    `*(QA-005 property 6)*`, so extract_features emits `@QA-005 property 6`,
    a tag containing whitespace, and pytest-bdd cannot load meta.feature at
    all. `--check` stays green because it only compares bytes to disk.
    """
    assert "CM-S-903" in subjects(matrix, "MALFORMED_SCENARIO_REF")
    assert severity_of(matrix, "MALFORMED_SCENARIO_REF", "CM-S-903") is Severity.HIGH
    # The usable part of the reference is still linked, so the requirement is
    # not double-reported as an orphan on top of the malformed reference.
    assert matrix.scenarios["CM-S-903"].refs == ("CM-909",)


# --- parsing helpers ------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("CM-901…903", ["CM-901", "CM-902", "CM-903"]),
        ("CM-901...903", ["CM-901", "CM-902", "CM-903"]),
        ("ES-901, CM-901", ["ES-901", "CM-901"]),
        ("ES-901 (record-shape portion — see note)", ["ES-901"]),
        ("QA-001 (L1)", ["QA-001"]),
    ],
)
def test_satisfies_expansion(raw, expected):
    assert expand_satisfies(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("ES-006/021", ["ES-006", "ES-021"]),
        ("CM-003/004", ["CM-003", "CM-004"]),
        ("ES-013/014", ["ES-013", "ES-014"]),
        ("CM-008", ["CM-008"]),
        ("", []),
    ],
)
def test_assertion_basis_expansion(raw, expected):
    assert expand_basis(raw) == expected


# --- output contract ------------------------------------------------------


def test_markdown_and_json_are_deterministic(matrix):
    """QA-012: same inputs, same bytes. A matrix that churns is not evidence."""
    node_ids = (FIXTURE / "collected.txt").read_text(encoding="utf-8").split()
    again = build_matrix(
        repo_root=FIXTURE,
        docs_dir=FIXTURE / "docs",
        features_dir=FIXTURE / "tests" / "features",
        node_ids=node_ids,
    )
    assert render_markdown(matrix) == render_markdown(again)
    assert render_json(matrix) == render_json(again)


def test_json_is_parseable_and_lists_every_exemption(matrix):
    payload = json.loads(render_json(matrix))
    exempt = {e["requirement"] for e in payload["exemptions"]}
    assert {"CM-902", "AG-901", "AG-902", "AG-903"} <= exempt
    assert payload["summary"]["exempt"] == len(payload["exemptions"])


def test_markdown_states_the_exemption_count_and_reasons(matrix):
    body = render_markdown(matrix)
    assert "## Exemptions" in body
    assert "CM-902" in body
    assert "change-log" in body, "the reason must be visible, not just the count"
