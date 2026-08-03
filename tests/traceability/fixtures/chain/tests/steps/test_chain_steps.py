"""Fixture step definitions. Never executed -- read as source by the matrix."""

from pytest_bdd import scenario


@scenario("coverage.feature", "CM-S-401 The traced scenario")
def test_cm_s_401_the_traced_scenario() -> None:
    """Implements the scenario at the middle of the chain."""
