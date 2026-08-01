# GENERATED FILE -- DO NOT EDIT.

Feature: Coverage fixture

  @CM-S-901 @CM-901
  Scenario: CM-S-901 Coverage ratio withheld
    Given a denominator of class C5
    When coverage is computed
    Then no ratio is emitted

  @CM-S-902 @CM-907
  Scenario: CM-S-902 Second scenario
    Given a scenario nobody has implemented
    When the matrix is generated
    Then the scenario is reported as untested
