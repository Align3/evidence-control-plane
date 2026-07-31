# GENERATED FILE -- DO NOT EDIT.
# Regenerate with: python tools/extract_features.py --docs docs --out tests/features
# Edit the scenario in its owning document under docs/ instead.

Feature: Agent evidence specification

  @ES-S-001 @ES-006
  # source: evidence-spec.md:233
  Scenario: ES-S-001 Fork detection
    Given a stream containing a record at sequence 42
    When a second record with the same stream_id and sequence 42 is submitted
    Then verification fails with "stream fork"
    And no attestation may be issued covering that stream

  @ES-S-002 @ES-011 @ES-012
  # source: evidence-spec.md:242
  Scenario: ES-S-002 Truncated enumeration blocks ratio
    Given a PopulationRecord with result_cap_hit true
    When an attestation window is generated
    Then coverage_ratio is null
    And the attestation states that enumeration was truncated

  @ES-S-003 @ES-014
  # source: evidence-spec.md:251
  Scenario: ES-S-003 Review after commitment is not effective oversight
    Given a HumanReview with action_state_at_review "committed"
    And decision "approve"
    When oversight effectiveness is evaluated
    Then the review is not counted as effective oversight
    And the attestation records it as "review after commitment"

  @ES-S-004 @ES-016
  # source: evidence-spec.md:261
  Scenario: ES-S-004 Offline gap emission
    Given hosted ingestion is unreachable
    When the SDK detects a collection gap
    Then a signed CoverageGap record is produced locally
    And it is accepted on reconnection with its original signature intact

  @ES-S-005 @ES-024
  # source: evidence-spec.md:270
  Scenario: ES-S-005 Rotation without continuity breaks the chain
    Given records signed with key K1
    When subsequent records are signed with K2 and no KeyContinuity assertion exists
    Then verification reports a chain break at the rotation point
    And the attestation window terminates there

  @ES-S-006 @ES-017
  # source: evidence-spec.md:279
  Scenario: ES-S-006 Null ratio is explicit, not omitted
    Given denominator_class C5
    When an AttestationWindow is serialized
    Then coverage_ratio is present with value null
    And the record does not omit the field

  @ES-S-007 @ES-001
  # source: evidence-spec.md:288
  Scenario: ES-S-007 Cross-implementation canonicalization
    Given the published conformance vectors
    When the Python writer and the Go verifier each canonicalize them
    Then both produce byte-identical output
    And both compute identical digests

  @ES-S-008 @ES-005
  # source: evidence-spec.md:297
  Scenario: ES-S-008 Unknown envelope field rejected
    Given a record carrying an unrecognised field in its envelope
    When the verifier validates it
    Then verification fails with "unknown envelope field"

  @ES-S-009 @ES-005
  # source: evidence-spec.md:305
  Scenario: ES-S-009 Unknown body field preserved
    Given a record carrying an unrecognised field inside body
    When the verifier validates it
    Then verification succeeds
    And the unknown field is included in the digest computation
