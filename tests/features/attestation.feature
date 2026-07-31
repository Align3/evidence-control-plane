# GENERATED FILE -- DO NOT EDIT.
# Regenerate with: python tools/extract_features.py --docs docs --out tests/features
# Edit the scenario in its owning document under docs/ instead.

Feature: Attestation and reliance framework

  @AR-S-001 @AR-003
  # source: attestation-reliance.md:162
  Scenario: AR-S-001 No assertion outside the catalogue
    Given an attestation generation request
    When the assertion set is assembled
    Then every assertion maps to a catalogue ID
    And any unmapped assertion causes generation to fail

  @AR-S-002 @AR-004
  # source: attestation-reliance.md:171
  Scenario: AR-S-002 No aggregate score
    When an attestation is rendered
    Then no single composite score, rating, or grade appears
    And each assertion carries its own scope and counts

  @AR-S-003 @AR-006
  # source: attestation-reliance.md:179
  Scenario: AR-S-003 Excluded scope disclosed
    Given a customer operating action families [X, Y, Z]
    And a boundary covering only [X]
    When an attestation is issued
    Then it states that other families exist and are out of scope

  @AR-S-004 @AR-009
  # source: attestation-reliance.md:188
  Scenario: AR-S-004 Expired verifies as expired
    Given an attestation whose validity_until has passed
    When the verifier validates it
    Then the result is "expired"
    And the result is not "valid"

  @AR-S-005 @AR-011
  # source: attestation-reliance.md:197
  Scenario: AR-S-005 Supersession preserves the original
    Given attestation A and superseding attestation A'
    When either is verified
    Then A remains independently verifiable
    And A' references A
    And A is reported as superseded, not invalid

  @AR-S-006 @AR-025
  # source: attestation-reliance.md:207
  Scenario: AR-S-006 Phase 0 artefact language check
    Given a phase 0 evidence pack
    When it is reviewed before release
    Then it contains none of: attestation, certification, assurance, verified, audited
    And it carries the full §9 header
