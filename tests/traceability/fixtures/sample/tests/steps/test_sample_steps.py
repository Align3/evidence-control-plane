"""Fixture step definitions. Never executed -- read as source by the matrix."""

from pytest_bdd import scenario


@scenario("coverage.feature", "CM-S-901 Coverage ratio withheld")
def test_cm_s_901_coverage_ratio_withheld() -> None:
    """The scenario link is carried by the decorator and the function name."""


@scenario("evidence.feature", "ES-S-901 Record is canonical")
def test_es_s_901_record_is_canonical() -> None:
    """Exercises ES-901."""
