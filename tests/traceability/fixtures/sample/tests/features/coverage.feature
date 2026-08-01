# GENERATED FILE -- DO NOT EDIT.
# Regenerate with: python tools/extract_features.py --docs docs --out tests/features
# Edit the scenario in its owning document under docs/ instead.

Feature: Coverage and assurance methodology

  @CM-S-901 @CM-901
  # source: coverage-methodology.md:62
  Scenario: CM-S-901 Coverage ratio withheld
    Given a denominator of class C5
    When coverage is computed
    Then no ratio is emitted

  @CM-S-902 @CM-906
  # source: coverage-methodology.md:70
  Scenario: CM-S-902 Second scenario
    Given a scenario nobody has implemented
    When the matrix is generated
    Then the scenario is reported as untested

  @CM-S-903 @CM-909 property 6
  # source: coverage-methodology.md:78
  Scenario: CM-S-903 Reference list carrying prose
    Given a reference list with prose in it
    When the feature file is generated
    Then the tag contains whitespace and Gherkin refuses the file

  @CM-S-904 @CM-906
  # source: coverage-methodology.md:86
  Scenario: CM-S-904 Future story acceptance remains visible
    Given a scenario owned by a story that has not landed
    When the traceability matrix is generated
    Then the missing test is reported as expected roadmap debt

  @CM-S-905 @CM-906
  # source: coverage-methodology.md:94
  Scenario: CM-S-905 Scenario ownership is mandatory
    Given a scenario no story lists under Acceptance
    When the traceability matrix is generated
    Then missing ownership is reported as a defect
