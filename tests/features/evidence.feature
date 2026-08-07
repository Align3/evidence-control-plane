# GENERATED FILE -- DO NOT EDIT.
# Regenerate with: python tools/extract_features.py --docs docs --out tests/features
# Edit the scenario in its owning document under docs/ instead.

Feature: Agent evidence specification

  @ES-S-001 @ES-006
  # source: evidence-spec.md:268
  Scenario: ES-S-001 Fork detection
    Given a stream containing a record at sequence 42
    When a second record with the same stream_id and sequence 42 is submitted
    Then verification fails with "stream fork"
    And no attestation may be issued covering that stream

  @ES-S-002 @ES-011 @ES-012
  # source: evidence-spec.md:277
  Scenario: ES-S-002 Truncated enumeration blocks ratio
    Given a PopulationRecord with result_cap_hit true
    When an attestation window is generated
    Then coverage_ratio is null
    And the attestation states that enumeration was truncated

  @ES-S-003 @ES-014
  # source: evidence-spec.md:286
  Scenario: ES-S-003 Review after commitment is not effective oversight
    Given a HumanReview with action_state_at_review "committed"
    And decision "approve"
    When oversight effectiveness is evaluated
    Then the review is not counted as effective oversight
    And the attestation records it as "review after commitment"

  @ES-S-004 @ES-016
  # source: evidence-spec.md:296
  Scenario: ES-S-004 Offline gap emission
    Given hosted ingestion is unreachable
    When the SDK detects a collection gap
    Then a signed CoverageGap record is produced locally
    And it is accepted on reconnection with its original signature intact

  @ES-S-005 @ES-024
  # source: evidence-spec.md:305
  Scenario: ES-S-005 Rotation without continuity breaks the chain
    Given records signed with key K1
    When subsequent records are signed with K2 and no KeyContinuity assertion exists
    Then verification reports a chain break at the rotation point
    And the attestation window terminates there

  @ES-S-006 @ES-017
  # source: evidence-spec.md:314
  Scenario: ES-S-006 Null ratio is explicit, not omitted
    Given denominator_class C5
    When an AttestationWindow is serialized
    Then coverage_ratio is present with value null
    And the record does not omit the field

  @ES-S-007 @ES-001
  # source: evidence-spec.md:323
  Scenario: ES-S-007 Cross-implementation canonicalization
    Given the published conformance vectors
    When the Python writer and the Go verifier each canonicalize them
    Then both produce byte-identical output
    And both compute identical digests

  @ES-S-008 @ES-005
  # source: evidence-spec.md:332
  Scenario: ES-S-008 Unknown envelope field rejected
    Given a record carrying an unrecognised field in its envelope
    When the verifier validates it
    Then verification fails with "unknown envelope field"

  @ES-S-009 @ES-005
  # source: evidence-spec.md:340
  Scenario: ES-S-009 Unknown body field preserved
    Given a record carrying an unrecognised field inside body
    When the verifier validates it
    Then verification succeeds
    And the unknown field is included in the digest computation

  @ES-S-010 @ES-006a
  # source: evidence-spec.md:349
  Scenario: ES-S-010 Previous authentication is chain-linked
    Given two records linked after the first record is signed
    When the first record is replaced by an independently valid re-signature
    Then verification fails with "prev_digest mismatch" at sequence 2

  @ES-S-011 @ES-021a
  # source: evidence-spec.md:357
  Scenario: ES-S-011 Unknown signature member rejected
    Given a valid signed terminal record
    When an unknown member is added to its signature object
    Then verification fails with "unknown signature member"

  @ES-S-012 @ES-024a
  # source: evidence-spec.md:365
  Scenario: ES-S-012 Continuity proof is bound to its tenant and stream
    Given a valid key-continuity assertion bound to tenant A and stream X
    When it is replayed into tenant B on stream X
    Then verification fails with "continuity tenant_id does not match"
    And the rotated record is not accepted

  @ES-S-013 @ES-019 @ES-030 @DM-005 @DM-024 @TM-006
  # source: evidence-spec.md:374
  Scenario: ES-S-013 Collector cannot suppress measured skew
    Given an issuer-signed ingestion receipt whose measured clock_skew_ms is non-zero
    When clock_skew_ms is replaced with a collector-reported value of 0
    Then receipt verification fails
    And the customer-signed record bytes remain unchanged

  @ES-S-014 @ES-020 @TM-006
  # source: evidence-spec.md:383
  Scenario: ES-S-014 Measured skew withholds numerator eligibility
    Given a record without authoritative_time
    And its issuer-signed ingestion receipt exceeds the boundary clock-skew threshold
    When coverage eligibility is evaluated
    Then the record is excluded from the numerator
    And the affected interval is counted as unknown
