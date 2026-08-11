# GENERATED FILE -- DO NOT EDIT.
# Regenerate with: python tools/extract_features.py --docs docs --out tests/features
# Edit the scenario in its owning document under docs/ instead.

Feature: Reconciliation classification

  @RC-S-001 @RC-001 @RC-002
  # source: reconciliation.md:115
  Scenario: RC-S-001 Approximate evidence is never matched
    Given a population record and evidence whose amounts and timestamps are close but whose stable identities differ
    When reconciliation runs against the population
    Then the population entry is classified "unmatched_without_evidence"
    And no confidence score or approximate match is emitted

  @RC-S-002 @RC-002
  # source: reconciliation.md:124
  Scenario: RC-S-002 Ambiguity wins over unmatched evidence
    Given one population entry with one execution receipt and two candidate confirmations
    When reconciliation runs against the population
    Then the population entry is classified "ambiguous"
    And no candidate confirmation is selected

  @RC-S-003 @RC-003
  # source: reconciliation.md:133
  Scenario: RC-S-003 Distinct duplicate destination records remain visible
    Given two distinct population identifiers with identical confirmed content
    When reconciliation runs against the population
    Then both population entries are classified "duplicate"
    And two reconciliation results are retained

  @RC-S-004 @RC-004
  # source: reconciliation.md:142
  Scenario: RC-S-004 Unclassifiable population representations are refused
    Given one population with a repeated identifier and one digest-only population
    When per-record reconciliation is requested for each population
    Then both populations are refused with named integrity errors
    And no partial reconciliation results are emitted

  @RC-S-005 @RC-005 @RC-006
  # source: reconciliation.md:151
  Scenario: RC-S-005 Reconciliation conserves immutable inputs and output cardinality
    Given a valid inline population and immutable reconciliation inputs
    When reconciliation is replayed twice
    Then both runs produce identical ordered results
    And the inputs are unchanged
    And the result count equals the population count
