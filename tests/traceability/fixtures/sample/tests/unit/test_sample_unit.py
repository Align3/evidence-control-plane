"""Fixture unit tests. Never executed -- read as source by the matrix."""


def test_cites_a_retired_requirement() -> None:
    """Asserts the behaviour required by CM-999, which no document defines."""
    assert True


def test_cites_a_live_requirement() -> None:
    """Covers CM-901 from the unit layer as well as the acceptance layer."""
    assert True


def test_cm_s_902_named_for_its_scenario() -> None:
    """The scenario id appears only in this function's name.

    No pytest-bdd decorator and no mention in the body, deliberately: this is
    the case the name-based fallback exists for, and the case that silently
    linked to nothing until the PR #6 review.
    """
    assert True
