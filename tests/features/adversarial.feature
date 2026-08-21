# GENERATED FILE -- DO NOT EDIT.
# Regenerate with: python tools/extract_features.py --docs docs --out tests/features
# Edit the scenario in its owning document under docs/ instead.

Feature: Threat model -- adversarial behaviour

  @TM-S-001 @TM-001
  # source: threat-model.md:194
  Scenario: TM-S-001 Uninstrumented actions surface as unmatched
    Given denominator class C1 for action family "refund.issue"
    And the vendor instruments only 60 of 100 refunds in window W
    When coverage is computed
    Then 40 actions are classified unmatched-without-evidence
    And the coverage ratio reflects 60/100
    And the attestation does not report 100% of the instrumented set

  @TM-S-002 @TM-002 @TM-003
  # source: threat-model.md:205
  Scenario: TM-S-002 Boundary narrowing is visible
    Given attestation A1 covering action families [X, Y]
    When a later attestation A2 covers only [X]
    Then A2 renders its scope adjacent to its coverage claim
    And the boundary version history shows the removal of Y

  @TM-S-003 @TM-009
  # source: threat-model.md:214
  Scenario: TM-S-003 Clean collector stop is caught by the denominator
    Given a collector stopped cleanly at a stream boundary at 14:00
    And restarted at 15:00 with a new stream
    And 30 actions executed between 14:00 and 15:00
    When coverage is computed with a C1 denominator
    Then those 30 actions appear as unmatched-without-evidence
    And the window does not claim enforced coverage for 14:00-15:00

  @TM-S-004 @TM-014
  # source: threat-model.md:225
  Scenario: TM-S-004 Offline verifier reports unchecked revocation
    Given the verifier is run without network access
    When it validates an attestation bundle
    Then signature and chain verification succeed
    And revocation_status is reported as "unchecked"
    And the output does not state that the attestation is valid

  @TM-S-005 @TM-013
  # source: threat-model.md:235
  Scenario: TM-S-005 Retroactive upgrade rejected by verifier
    Given a QualificationRecord assigning class C1 dated 2026-09-01
    And an attestation for a window starting 2026-08-01 claiming class C1
    When the verifier validates it
    Then verification fails with "qualification postdates window"

  @TM-S-006 @TM-010
  # source: threat-model.md:244
  Scenario: TM-S-006 Duplicate destination records not merged
    Given two destination records with identical content and distinct identifiers
    When reconciliation runs
    Then both are classified "duplicate"
    And neither is silently discarded
    And the counts in the attestation reflect the duplication
