# GENERATED FILE -- DO NOT EDIT.
# Regenerate with: python tools/extract_features.py --docs docs --out tests/features
# Edit the scenario in its owning document under docs/ instead.

Feature: Test-system self-checks

  @QA-S-001 @QA-002
  # source: testing-qa.md:148
  Scenario: QA-S-001 Assertion without scenario fails CI
    Given a new assertion added to the catalogue
    And no scenario referencing it
    When CI runs
    Then the traceability check fails
    And the failure names the unmapped assertion

  @QA-S-002 @QA-005 property 6
  # source: testing-qa.md:158
  Scenario: QA-S-002 Gap conservation holds
    Given any generated evidence set over window W
    When coverage is computed
    Then covered intervals and gap intervals partition W exactly
    And no interval is both
    And no interval is neither

  @QA-S-003 @QA-008
  # source: testing-qa.md:168
  Scenario: QA-S-003 Golden diff blocks merge
    Given a change to canonicalisation
    When golden attestations are regenerated
    And any bundle differs byte-for-byte from its fixture
    Then CI fails
    And the failure requires an explicit reviewed fixture update

  @QA-S-004 @QA-013
  # source: testing-qa.md:178
  Scenario: QA-S-004 Cross-implementation reproduction
    Given a PR touching the evidence schema
    When CI runs
    Then the Go verifier reproduces the Python writer's canonical output
    And any divergence fails the build before merge

  @QA-S-005 @QA-003
  # source: testing-qa.md:187
  Scenario: QA-S-005 Acceptance tests assert through the verifier
    Given an acceptance test in layer L6
    When it is executed
    Then its assertions derive from verifier output
    And it does not reference internal computation state
