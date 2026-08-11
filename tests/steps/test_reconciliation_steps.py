"""Acceptance steps for EV-15's exact, closed reconciliation classifier."""

from __future__ import annotations

from collections import Counter
from copy import deepcopy

from pytest_bdd import given, scenario, then, when

from services.computation.reconciliation import (
    PopulationIdentifierDigestUnsupportedError,
    PopulationIntegrityError,
    reconcile,
)
from tests.reconciliation_support import confirmation, digest, population, proposal, receipt


@scenario("architecture.feature", "AC-S-002 Computation purity")
def test_ac_s_002_computation_purity() -> None:
    """Reconciliation replay neither changes the ledger nor drifts."""


@scenario("adversarial.feature", "TM-S-006 Duplicate destination records not merged")
def test_tm_s_006_duplicate_destination_records_not_merged() -> None:
    """Distinct destination events with identical content both survive."""


@scenario("reconciliation.feature", "RC-S-001 Approximate evidence is never matched")
def test_rc_s_001_approximate_evidence_is_never_matched() -> None:
    """Near values cannot substitute for exact stable identity."""


@scenario("reconciliation.feature", "RC-S-002 Ambiguity wins over unmatched evidence")
def test_rc_s_002_ambiguity_wins_over_unmatched_evidence() -> None:
    """No confirmation candidate is selected by ordering."""


@scenario(
    "reconciliation.feature",
    "RC-S-003 Distinct duplicate destination records remain visible",
)
def test_rc_s_003_distinct_duplicate_destination_records_remain_visible() -> None:
    """Destination duplication conserves both population entries."""


@scenario(
    "reconciliation.feature",
    "RC-S-004 Unclassifiable population representations are refused",
)
def test_rc_s_004_unclassifiable_population_representations_are_refused() -> None:
    """Malformed or opaque populations fail closed without partial output."""


@scenario(
    "reconciliation.feature",
    "RC-S-005 Reconciliation conserves immutable inputs and output cardinality",
)
def test_rc_s_005_reconciliation_conserves_inputs_and_cardinality() -> None:
    """A derived store can be rebuilt byte-for-value from the same inputs."""


def _matched_context() -> dict[str, object]:
    pop = population(["destination-1"])
    evidence = (proposal("action-1"), receipt("action-1", "destination-1"))
    confirmations = (confirmation("action-1", "destination-1"),)
    return {"population": pop, "evidence": evidence, "confirmations": confirmations}


@given("a ledger state L", target_fixture="reconciliation_context")
def ledger_state() -> dict[str, object]:
    context = _matched_context()
    context["before"] = deepcopy(context)
    return context


@when("reconciliation and coverage run")
def run_reconciliation_twice(reconciliation_context: dict[str, object]) -> None:
    inputs = (
        reconciliation_context["population"],
        reconciliation_context["evidence"],
        reconciliation_context["confirmations"],
    )
    reconciliation_context["first"] = reconcile(*inputs)  # type: ignore[arg-type]
    reconciliation_context["second"] = reconcile(*inputs)  # type: ignore[arg-type]


@then("the ledger state is unchanged")
def ledger_is_unchanged(reconciliation_context: dict[str, object]) -> None:
    before = reconciliation_context["before"]
    assert isinstance(before, dict)
    assert reconciliation_context["population"] == before["population"]
    assert reconciliation_context["evidence"] == before["evidence"]
    assert reconciliation_context["confirmations"] == before["confirmations"]


@then("a second run produces identical output")
def second_run_is_identical(reconciliation_context: dict[str, object]) -> None:
    assert reconciliation_context["first"] == reconciliation_context["second"]


@given(
    "two destination records with identical content and distinct identifiers",
    target_fixture="reconciliation_context",
)
@given(
    "two distinct population identifiers with identical confirmed content",
    target_fixture="reconciliation_context",
)
def distinct_duplicate_destinations() -> dict[str, object]:
    same_content = digest("d")
    return {
        "population": population(["destination-1", "destination-2"]),
        "evidence": (
            proposal("action-1", serial=10),
            receipt("action-1", "destination-1", serial=20),
            proposal("action-2", serial=11),
            receipt("action-2", "destination-2", serial=21),
        ),
        "confirmations": (
            confirmation("action-1", "destination-1", digest=same_content, serial=30),
            confirmation("action-2", "destination-2", digest=same_content, serial=31),
        ),
    }


@when("reconciliation runs")
@when("reconciliation runs against the population")
def run_reconciliation(reconciliation_context: dict[str, object]) -> None:
    reconciliation_context["results"] = reconcile(
        reconciliation_context["population"],  # type: ignore[arg-type]
        reconciliation_context["evidence"],  # type: ignore[arg-type]
        reconciliation_context["confirmations"],  # type: ignore[arg-type]
    )


@then('both are classified "duplicate"')
@then('both population entries are classified "duplicate"')
def both_are_duplicate(reconciliation_context: dict[str, object]) -> None:
    results = reconciliation_context["results"]
    assert [result.status for result in results] == ["duplicate", "duplicate"]  # type: ignore[union-attr]


@then("neither is silently discarded")
@then("two reconciliation results are retained")
def duplicate_results_are_retained(reconciliation_context: dict[str, object]) -> None:
    assert len(reconciliation_context["results"]) == 2  # type: ignore[arg-type]


@then("the counts in the attestation reflect the duplication")
def downstream_counts_reflect_duplicates(reconciliation_context: dict[str, object]) -> None:
    counts = Counter(result.status for result in reconciliation_context["results"])  # type: ignore[union-attr]
    assert counts == {"duplicate": 2}


@given(
    "a population record and evidence whose amounts and timestamps are close but "
    "whose stable identities differ",
    target_fixture="reconciliation_context",
)
def near_but_not_equal_identity() -> dict[str, object]:
    return {
        "population": population(["destination-100"]),
        "evidence": (
            proposal("action-100"),
            receipt("action-100", "destination-101"),
        ),
        "confirmations": (confirmation("action-100", "destination-101"),),
    }


@then('the population entry is classified "unmatched_without_evidence"')
def entry_is_unmatched_without_evidence(
    reconciliation_context: dict[str, object],
) -> None:
    (result,) = reconciliation_context["results"]  # type: ignore[misc]
    assert result.status == "unmatched_without_evidence"


@then("no confidence score or approximate match is emitted")
def no_approximation_fields(reconciliation_context: dict[str, object]) -> None:
    (result,) = reconciliation_context["results"]  # type: ignore[misc]
    assert not hasattr(result, "confidence")
    assert not hasattr(result, "score")


@given(
    "one population entry with one execution receipt and two candidate confirmations",
    target_fixture="reconciliation_context",
)
def multiple_confirmations() -> dict[str, object]:
    return {
        "population": population(["destination-1"]),
        "evidence": (proposal("action-1"), receipt("action-1", "destination-1")),
        "confirmations": (
            confirmation("action-1", "destination-1", serial=30),
            confirmation("action-1", "destination-1", serial=31),
        ),
    }


@then('the population entry is classified "ambiguous"')
def entry_is_ambiguous(reconciliation_context: dict[str, object]) -> None:
    (result,) = reconciliation_context["results"]  # type: ignore[misc]
    assert result.status == "ambiguous"


@then("no candidate confirmation is selected")
def no_candidate_is_selected(reconciliation_context: dict[str, object]) -> None:
    (result,) = reconciliation_context["results"]  # type: ignore[misc]
    assert result.confirmation_record_id is None


@given(
    "one population with a repeated identifier and one digest-only population",
    target_fixture="reconciliation_context",
)
def unclassifiable_populations() -> dict[str, object]:
    return {
        "repeated": population(["destination-1", "destination-1"], serial=1),
        "digest_only": population(None, count=2, serial=2),
        "evidence": (),
        "confirmations": (),
    }


@when("per-record reconciliation is requested for each population")
def reconcile_unclassifiable_populations(
    reconciliation_context: dict[str, object],
) -> None:
    errors: list[Exception] = []
    for key in ("repeated", "digest_only"):
        try:
            reconcile(
                reconciliation_context[key],  # type: ignore[arg-type]
                reconciliation_context["evidence"],  # type: ignore[arg-type]
                reconciliation_context["confirmations"],  # type: ignore[arg-type]
            )
        except (PopulationIntegrityError, PopulationIdentifierDigestUnsupportedError) as error:
            errors.append(error)
    reconciliation_context["errors"] = errors


@then("both populations are refused with named integrity errors")
def both_populations_are_refused(reconciliation_context: dict[str, object]) -> None:
    errors = reconciliation_context["errors"]
    assert [type(error) for error in errors] == [
        PopulationIntegrityError,
        PopulationIdentifierDigestUnsupportedError,
    ]


@then("no partial reconciliation results are emitted")
def no_partial_results(reconciliation_context: dict[str, object]) -> None:
    assert all(not hasattr(error, "partial_results") for error in reconciliation_context["errors"])  # type: ignore[union-attr]


@given(
    "a valid inline population and immutable reconciliation inputs",
    target_fixture="reconciliation_context",
)
def immutable_inputs() -> dict[str, object]:
    context = _matched_context()
    context["before"] = deepcopy(context)
    return context


@when("reconciliation is replayed twice")
def reconciliation_is_replayed(reconciliation_context: dict[str, object]) -> None:
    run_reconciliation_twice(reconciliation_context)


@then("both runs produce identical ordered results")
def replay_results_are_identical(reconciliation_context: dict[str, object]) -> None:
    second_run_is_identical(reconciliation_context)


@then("the inputs are unchanged")
def inputs_are_unchanged(reconciliation_context: dict[str, object]) -> None:
    ledger_is_unchanged(reconciliation_context)


@then("the result count equals the population count")
def result_count_matches_population(reconciliation_context: dict[str, object]) -> None:
    population_record = reconciliation_context["population"]
    assert len(reconciliation_context["first"]) == population_record.body.count  # type: ignore[union-attr,arg-type]
