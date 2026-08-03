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
import shutil
from pathlib import Path

import pytest

from tests.traceability import matrix as matrix_module
from tests.traceability.matrix import (
    Severity,
    build_matrix,
    expand_basis,
    expand_satisfies,
    landed_story_ids,
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
        landed_stories=frozenset({"EV-90"}),
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


def test_a_test_links_to_a_scenario_by_its_function_name(matrix):
    """PR #6 review, blocker 2: the name-based link never fired.

    `SID_IN_NAME` anchored on `\\b`, but an underscore is a word character, so
    the boundary between `test_` and `qa_s_001` never matched. Every link that
    appeared to come from a function name was really coming from a pytest-bdd
    decorator elsewhere in the body, and a test named for a scenario it had no
    decorator for -- which is the whole point of the fallback -- linked to
    nothing.
    """
    nodeid = "tests/unit/test_sample_unit.py::test_cm_s_902_named_for_its_scenario"
    assert matrix.tests[nodeid].scenarios == ("CM-S-902",)
    assert dict(matrix.tests[nodeid].link_kind)["CM-S-902"] == "test name"
    assert "CM-S-902" not in subjects(matrix, "SCENARIO_NO_TEST")


def test_link_provenance_distinguishes_a_binding_from_a_mention(matrix):
    """How a link was established is itself evidence.

    A pytest-bdd binding executes the scenario's documented steps. A name or a
    mention is the author asserting the test covers it. An auditor reading the
    published chain should be able to tell those apart.
    """
    bdd = "tests/steps/test_sample_steps.py::test_cm_s_901_coverage_ratio_withheld"
    assert dict(matrix.tests[bdd].link_kind)["CM-S-901"] == "pytest-bdd"


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


def test_landed_story_scenario_with_no_test_is_a_defect(matrix):
    """EV-90 landed, so its missing CM-S-903 acceptance test is high severity."""
    assert "CM-S-903" in subjects(matrix, "SCENARIO_NO_TEST_LANDED")
    assert matrix.scenarios["CM-S-903"].tests == ()
    assert severity_of(matrix, "SCENARIO_NO_TEST_LANDED", "CM-S-903") is Severity.HIGH


def test_unbuilt_story_scenario_with_no_test_is_expected_debt(matrix):
    """EV-91 owns CM-S-904 but has not landed; shipping it is what clears the debt."""
    assert "CM-S-904" in subjects(matrix, "SCENARIO_NO_TEST_UNBUILT")
    assert severity_of(matrix, "SCENARIO_NO_TEST_UNBUILT", "CM-S-904") is Severity.MEDIUM


def test_a_tested_scenario_with_no_owner_is_still_reported(matrix):
    """Demonstration and ownership are separate records.

    ES-S-901 has a test and sits in no story's Acceptance field. Until this
    check existed the pairing produced no finding at all, because the ownership
    check only ran over untested scenarios -- which is how EV-22's own
    Acceptance field came to omit QA-S-006, QA-S-007 and QA-S-008 with its own
    tool reporting nothing. Medium, not high: the claim is demonstrated and only
    the owner is unrecorded.
    """
    assert "ES-S-901" in subjects(matrix, "SCENARIO_UNOWNED")
    assert matrix.scenarios["ES-S-901"].tests, "the precondition: it does have a test"
    assert matrix.scenarios["ES-S-901"].accepted_by == ()
    assert severity_of(matrix, "SCENARIO_UNOWNED", "ES-S-901") is Severity.MEDIUM


def test_a_tested_scenario_with_an_owner_is_not_reported(matrix):
    assert "CM-S-901" not in subjects(matrix, "SCENARIO_UNOWNED")
    assert matrix.scenarios["CM-S-901"].accepted_by == ("EV-90",)


def test_unowned_scenario_with_no_test_remains_a_defect(matrix):
    assert "CM-S-905" in subjects(matrix, "SCENARIO_NO_TEST_UNOWNED")
    assert severity_of(matrix, "SCENARIO_NO_TEST_UNOWNED", "CM-S-905") is Severity.HIGH


def test_acceptance_fields_are_the_scenario_ownership_source(matrix):
    assert matrix.story_acceptance["EV-90"] == ("CM-S-901", "CM-S-903")
    assert matrix.story_acceptance["EV-91"] == ("CM-S-904",)


def test_story_id_in_ordinary_prose_must_resolve_to_a_prd_heading(matrix):
    """EV-97 is prose as well as a deferral; both paths must fail closed."""
    assert "EV-97" in subjects(matrix, "DANGLING_STORY_REF")
    assert severity_of(matrix, "DANGLING_STORY_REF", "EV-97") is Severity.CRITICAL
    assert "EV-90" not in subjects(matrix, "DANGLING_STORY_REF")


def test_only_reachable_story_commit_subjects_count_as_landed(monkeypatch, tmp_path):
    history = "\n".join(
        [
            "EV-90: implemented story",
            "docs: mention EV-91 without landing it",
            "merge follow-up for EV-92: not the story commit",
        ]
    )
    monkeypatch.setattr(matrix_module, "_git", lambda *_args: history)
    assert landed_story_ids(tmp_path) == frozenset({"EV-90"})


def test_unavailable_story_history_fails_closed(monkeypatch):
    monkeypatch.setattr(matrix_module, "_git", lambda *_args: None)
    node_ids = (FIXTURE / "collected.txt").read_text(encoding="utf-8").split()
    without_history = build_matrix(
        repo_root=FIXTURE,
        docs_dir=FIXTURE / "docs",
        features_dir=FIXTURE / "tests" / "features",
        node_ids=node_ids,
    )
    assert "story commit history" in subjects(without_history, "STORY_HISTORY_UNAVAILABLE")
    assert (
        severity_of(without_history, "STORY_HISTORY_UNAVAILABLE", "story commit history")
        is Severity.CRITICAL
    )


def test_duplicate_assertion_id_does_not_overwrite_the_first(matrix):
    """PR #6 review, blocker 4: a second A-01 silently replaced the first.

    AR-003 closes the catalogue, so last-write-wins here quietly rewrites a
    claim's text and basis while the matrix still reports a complete chain --
    part of the published evidence erased with nothing said about it.
    """
    assert matrix.assertions["A-01"].basis == ("CM-901",), "the first row must win"
    assert matrix.assertions["A-01"].text == "A fully traced assertion"
    assert "A-01" in subjects(matrix, "DUPLICATE_ASSERTION")
    assert severity_of(matrix, "DUPLICATE_ASSERTION", "A-01") is Severity.CRITICAL


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
    """EV-90 satisfies CM-901..904; CM-902 is exempt and stays exempt."""
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
    assert exemption.story == "EV-90"
    assert "CM-904" in matrix.summary["deferred_ids"]
    assert "CM-904" not in matrix.summary["exempt_ids"]


def test_deferral_to_a_nonexistent_story_is_revoked(matrix):
    """PR #6 review, blocker 3: a typo in a story reference silently retired debt.

    CM-910 defers to EV-97, which prd.md does not define. Validating only the
    `EV-nn` shape accepted it and suppressed the orphan outright. The deferral
    must be revoked -- reported *and* the requirement returned to the orphan
    list, not merely reported while still counting as excused.
    """
    assert matrix.requirements["CM-910"].exemption is None, "the deferral must be revoked"
    assert "CM-910" in subjects(matrix, "DEFERRED_UNKNOWN_STORY")
    assert severity_of(matrix, "DEFERRED_UNKNOWN_STORY", "CM-910") is Severity.CRITICAL
    assert "CM-910" in subjects(matrix, "REQUIREMENT_NO_SCENARIO_SPEC")
    assert "CM-910" not in matrix.summary["deferred_ids"]
    assert "CM-910" not in matrix.summary["exempt_ids"]


def test_deferral_to_a_story_that_does_not_claim_it_is_reported(matrix):
    """CM-911 defers to EV-91, which exists but does not list it under Satisfies.

    The deferral stands -- a legitimate deferral often names the story that will
    write the scenario rather than the one that claimed the requirement -- but
    nobody has recorded the commitment, and that is worth saying out loud.
    """
    exemption = matrix.requirements["CM-911"].exemption
    assert exemption is not None
    assert exemption.story == "EV-91"
    assert "CM-911" in subjects(matrix, "DEFERRED_STORY_DOES_NOT_CLAIM")
    assert severity_of(matrix, "DEFERRED_STORY_DOES_NOT_CLAIM", "CM-911") is Severity.MEDIUM


def test_a_fully_accounted_deferral_produces_no_finding(matrix):
    """CM-904 defers to EV-90, which exists and claims it. Nothing to report."""
    assert matrix.requirements["CM-904"].exemption is not None
    assert "CM-904" not in subjects(matrix, "DEFERRED_UNKNOWN_STORY")
    assert "CM-904" not in subjects(matrix, "DEFERRED_STORY_DOES_NOT_CLAIM")
    assert "CM-904" not in subjects(matrix, "DEFERRED_UNASSIGNED")


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


def test_feature_tags_disagreeing_with_the_document_are_reported(tmp_path):
    """A generated tag is corrupted after extraction; the document still wins."""
    root = tmp_path / "drift"
    shutil.copytree(FIXTURE, root)
    feature = root / "tests" / "features" / "coverage.feature"
    feature.write_text(
        feature.read_text(encoding="utf-8").replace(
            "@CM-S-902 @CM-906", "@CM-S-902 @CM-907"
        ),
        encoding="utf-8",
    )
    node_ids = (root / "collected.txt").read_text(encoding="utf-8").split()
    drifted = build_matrix(
        repo_root=root,
        docs_dir=root / "docs",
        features_dir=root / "tests" / "features",
        node_ids=node_ids,
        landed_stories=frozenset({"EV-90"}),
    )
    assert "CM-S-902" in subjects(drifted, "FEATURE_TAG_DRIFT")


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
        landed_stories=frozenset({"EV-90"}),
    )
    assert render_markdown(matrix) == render_markdown(again)
    assert render_json(matrix) == render_json(again)


def test_json_is_parseable_and_lists_every_exemption(matrix):
    payload = json.loads(render_json(matrix))
    exempt = {e["requirement"] for e in payload["exemptions"]}
    assert {"CM-902", "AG-901", "AG-902", "AG-903"} <= exempt
    assert payload["summary"]["exempt"] == len(payload["exemptions"])
    assert payload["story_acceptance"]["EV-90"] == ["CM-S-901", "CM-S-903"]
    assert payload["landed_stories"] == ["EV-90"]
    scenarios = {scenario["id"]: scenario for scenario in payload["scenarios"]}
    assert scenarios["CM-S-904"]["accepted_by"] == ["EV-91"]


def test_markdown_states_the_exemption_count_and_reasons(matrix):
    body = render_markdown(matrix)
    assert "## Exemptions" in body
    assert "CM-902" in body
    assert "change-log" in body, "the reason must be visible, not just the count"


# --- dangling story references -------------------------------------------


DANGLING = Path(__file__).parent / "fixtures" / "dangling_story"


@pytest.fixture
def dangling(tmp_path):
    return build_matrix(
        repo_root=tmp_path,
        docs_dir=DANGLING / "docs",
        features_dir=None,
        node_ids=[],
        landed_stories=frozenset(),
    )


def test_a_reference_to_an_undefined_story_is_reported(dangling):
    """The blind spot QA-011 fell into.

    The staged schedule named two stories before either was written, and
    nothing caught it: the matrix validated requirement ids and scenario ids
    but never story ids in prose, so a normative schedule could hang off a
    story that did not exist.
    """
    assert {"EV-97", "EV-98"} <= subjects(dangling, "DANGLING_STORY_REF")
    assert severity_of(dangling, "DANGLING_STORY_REF", "EV-97") is Severity.CRITICAL


def test_a_story_defined_without_satisfies_is_not_dangling(dangling):
    """Defined-ness comes from the heading, not from having a Satisfies field.

    EV-91 declares no Satisfies, so it never enters the story->requirement map.
    Checking membership of that map instead of the set of headings would report
    a story that plainly exists.
    """
    assert "EV-91" not in subjects(dangling, "DANGLING_STORY_REF")
    assert "EV-91" not in dangling.stories, "the precondition this test exists to cover"
    assert "EV-90" not in subjects(dangling, "DANGLING_STORY_REF")


def test_a_story_heading_outside_prd_does_not_define_a_story(dangling):
    """Heading detection is constrained to prd.md.

    Scanning every document for `#### EV-nn` would let any dangling reference be
    silenced by writing its heading beside itself -- the reference re-spelt, not
    resolved. EV-99 has a heading in the fixture's testing-qa.md and must still
    be reported.
    """
    assert "EV-99" in subjects(dangling, "DANGLING_STORY_REF")
    assert "EV-99" not in dangling.story_definitions
