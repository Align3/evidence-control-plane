# GENERATED FILE -- DO NOT EDIT.
# Regenerate with: python tools/extract_features.py --docs docs --out tests/features
# Edit the scenario in its owning document under docs/ instead.

Feature: Test-system self-checks

  @QA-S-001 @QA-002
  # source: testing-qa.md:187
  Scenario: QA-S-001 Assertion without scenario fails CI
    Given a new assertion added to the catalogue
    And no scenario referencing it
    When CI runs
    Then the traceability check fails
    And the failure names the unmapped assertion

  @QA-S-002 @QA-005
  # source: testing-qa.md:197
  Scenario: QA-S-002 Gap conservation holds, property 6
    Given any generated evidence set over window W
    When coverage is computed
    Then covered intervals and gap intervals partition W exactly
    And no interval is both
    And no interval is neither

  @QA-S-003 @QA-008
  # source: testing-qa.md:207
  Scenario: QA-S-003 Golden diff blocks merge
    Given a change to canonicalisation
    When golden attestations are regenerated
    And any bundle differs byte-for-byte from its fixture
    Then CI fails
    And the failure requires an explicit reviewed fixture update

  @QA-S-004 @QA-013
  # source: testing-qa.md:217
  Scenario: QA-S-004 Cross-implementation reproduction
    Given a PR touching the evidence schema
    When CI runs
    Then the Go verifier reproduces the Python writer's canonical output
    And any divergence fails the build before merge

  @QA-S-005 @QA-003
  # source: testing-qa.md:226
  Scenario: QA-S-005 Acceptance tests assert through the verifier
    Given an acceptance test in layer L6
    When it is executed
    Then its assertions derive from verifier output
    And it does not reference internal computation state

  @QA-S-006 @QA-010
  # source: testing-qa.md:235
  Scenario: QA-S-006 The four-link chain is generated and published
    Given a requirement with a scenario, an implementing test, and an assertion citing it as basis
    When the traceability matrix is generated
    Then the matrix links the requirement to the scenario to the test to the assertion
    And it is published in both human-readable and machine-readable form

  @QA-S-007 @QA-011
  # source: testing-qa.md:244
  Scenario: QA-S-007 An orphaned requirement fails the traceability check
    Given a requirement with no scenario and no non-testable marking
    When the traceability check runs with that severity enforced
    Then the check fails
    And the failure names the requirement

  @QA-S-008 @QA-012
  # source: testing-qa.md:253
  Scenario: QA-S-008 The matrix is generated, never hand-maintained
    Given the traceability matrix generator
    When it runs twice over unchanged inputs
    Then both runs produce byte-identical output
    And neither run writes a matrix into the repository for a human to edit

  @QA-S-009 @QA-011
  # source: testing-qa.md:262
  Scenario: QA-S-009 A malformed non-testable marking exempts nothing
    Given a requirement with no scenario and a non-testable marking whose category is not in the closed enum
    When the traceability matrix is generated
    Then the marking exempts nothing
    And the requirement is still reported as an orphan

  @QA-S-010 @QA-011
  # source: testing-qa.md:276
  Scenario: QA-S-010 Every requirement and scenario is classified after triage
    Given the live corpus after triage
    When the traceability matrix is generated
    Then every requirement has a scenario, a reasoned non-testable marking, or a deferral to a story that prd.md defines
    And every scenario is listed under the Acceptance field of a story, whether or not it has a test
    And no requirement claimed by a story is reported without a scenario
    And no scenario is reported as having no Acceptance owner
    And untested scenarios owned by unlanded stories remain reported as roadmap debt
