# GENERATED FILE -- DO NOT EDIT.
# Regenerate with: python tools/extract_features.py --docs docs --out tests/features
# Edit the scenario in its owning document under docs/ instead.

Feature: Agent evidence specification

  @ES-S-001 @ES-006
  # source: evidence-spec.md:355
  Scenario: ES-S-001 Fork detection
    Given a stream containing a record at sequence 42
    When a second record with the same stream_id and sequence 42 is submitted
    Then verification fails with "stream fork"
    And no attestation may be issued covering that stream

  @ES-S-002 @ES-011 @ES-012
  # source: evidence-spec.md:364
  Scenario: ES-S-002 Truncated enumeration blocks ratio
    Given a PopulationRecord with result_cap_hit true
    When an attestation window is generated
    Then coverage_ratio is null
    And the attestation states that enumeration was truncated

  @ES-S-003 @ES-014
  # source: evidence-spec.md:373
  Scenario: ES-S-003 Review after commitment is not effective oversight
    Given a HumanReview with action_state_at_review "committed"
    And decision "approve"
    When oversight effectiveness is evaluated
    Then the review is not counted as effective oversight
    And the attestation records it as "review after commitment"

  @ES-S-004 @ES-016
  # source: evidence-spec.md:383
  Scenario: ES-S-004 Offline gap emission
    Given hosted ingestion is unreachable
    When the SDK detects a collection gap
    Then a signed CoverageGap record is produced locally
    And it is accepted on reconnection with its original signature intact

  @ES-S-005 @ES-024
  # source: evidence-spec.md:392
  Scenario: ES-S-005 Rotation without continuity breaks the chain
    Given records signed with key K1
    When subsequent records are signed with K2 and no KeyContinuity assertion exists
    Then verification reports a chain break at the rotation point
    And the attestation window terminates there

  @ES-S-006 @ES-017
  # source: evidence-spec.md:401
  Scenario: ES-S-006 Null ratio is explicit, not omitted
    Given denominator_class C5
    When an AttestationWindow is serialized
    Then coverage_ratio is present with value null
    And the record does not omit the field

  @ES-S-007 @ES-001
  # source: evidence-spec.md:410
  Scenario: ES-S-007 Cross-implementation canonicalization
    Given the published conformance vectors
    When the Python writer and the Go verifier each canonicalize them
    Then both produce byte-identical output
    And both compute identical digests

  @ES-S-008 @ES-005
  # source: evidence-spec.md:419
  Scenario: ES-S-008 Unknown envelope field rejected
    Given a record carrying an unrecognised field in its envelope
    When the verifier validates it
    Then verification fails with "unknown envelope field"

  @ES-S-009 @ES-005
  # source: evidence-spec.md:427
  Scenario: ES-S-009 Unknown body field preserved
    Given a record carrying an unrecognised field inside body
    When the verifier validates it
    Then verification succeeds
    And the unknown field is included in the digest computation

  @ES-S-010 @ES-006a
  # source: evidence-spec.md:436
  Scenario: ES-S-010 Previous authentication is chain-linked
    Given two records linked after the first record is signed
    When the first record is replaced by an independently valid re-signature
    Then verification fails with "prev_digest mismatch" at sequence 2

  @ES-S-011 @ES-021a
  # source: evidence-spec.md:444
  Scenario: ES-S-011 Unknown signature member rejected
    Given a valid signed terminal record
    When an unknown member is added to its signature object
    Then verification fails with "unknown signature member"

  @ES-S-012 @ES-024a
  # source: evidence-spec.md:452
  Scenario: ES-S-012 Continuity proof is bound to its tenant and stream
    Given a valid key-continuity assertion bound to tenant A and stream X
    When it is replayed into tenant B on stream X
    Then verification fails with "continuity tenant_id does not match"
    And the rotated record is not accepted

  @ES-S-013 @ES-019 @ES-030 @DM-005 @DM-024 @TM-006
  # source: evidence-spec.md:461
  Scenario: ES-S-013 Collector cannot suppress measured skew
    Given an issuer-signed ingestion receipt whose measured clock_skew_ms is non-zero
    When clock_skew_ms is replaced with a collector-reported value of 0
    Then receipt verification fails
    And the customer-signed record bytes remain unchanged

  @ES-S-014 @ES-020 @TM-006
  # source: evidence-spec.md:470
  Scenario: ES-S-014 Measured skew withholds numerator eligibility
    Given a record without authoritative_time
    And its issuer-signed ingestion receipt exceeds the boundary clock-skew threshold
    When coverage eligibility is evaluated
    Then the record is excluded from the numerator
    And the affected interval is counted as unknown

  @ES-S-015 @ES-031
  # source: evidence-spec.md:480
  Scenario: ES-S-015 The schema-2 constitutive enumeration is closed
    Given a schema-2 QualificationRecord whose envelope omits boundary_ref
    And schema-2 PopulationRecord, AgentIdentity, ActionProposal, AuthorityDecision, HumanReview, ExecutionReceipt, ExternalConfirmation, FinalityRecord, OutcomeRecord, CoverageGap, AttestationWindow, and RevocationRecord each omit boundary_ref
    And a schema-2 QualificationRecord whose envelope carries boundary_ref as null
    When each is validated
    Then the QualificationRecord omitting the field is accepted
    And all twelve governed records are rejected with their record types identified
    And the QualificationRecord carrying null is rejected

  @ES-S-016 @ES-031
  # source: evidence-spec.md:492
  Scenario: ES-S-016 A boundary's self-reference is checked, not assumed
    Given a schema-2 AssuranceBoundary whose boundary_ref names version 2
    And whose body declares boundary_version 1
    When it is validated
    Then verification fails with "boundary_ref does not match the declared version"
    And the boundary is not recorded

  @ES-S-017 @ES-032 @AR-027
  # source: evidence-spec.md:502
  Scenario: ES-S-017 An unattested recording time withholds the boundary assertion
    Given an AssuranceBoundary recorded without an issuer-signed receipt
    When an attestation referencing that boundary version is generated
    Then A-02 is withheld
    And the effective interval is not computed from the stored recording time

  @ES-S-018 @ES-027 @ES-028 @ES-031
  # source: evidence-spec.md:511
  Scenario: ES-S-018 The schema-2 verifier retains schema-1 envelope support
    Given a schema-1 QualificationRecord carrying boundary_ref
    And the equivalent schema-2 QualificationRecord omitting boundary_ref
    When the current verifier validates both records under their declared versions
    Then both records are accepted
    And neither record is rewritten into the other version's canonical form

  @ES-S-019 @ES-033 @SE-002 @SE-003 @DM-008
  # source: evidence-spec.md:521
  Scenario: ES-S-019 Record origin fixes the signer namespace
    Given a PopulationRecord and ExternalConfirmation signed by an evidence-namespace key
    And equivalent records signed by an issuer-namespace key
    And a RevocationRecord signed by each namespace
    And an AttestationWindow with both required proofs and one with its issuer proof removed
    When Python, Go, and TypeScript verify each complete record under the same registered keyring
    Then both evidence-signed issuer observations fail with "key namespace mismatch"
    And both issuer-signed issuer observations verify
    And the issuer-signed RevocationRecord verifies and the evidence-signed one fails
    And only the complete two-proof AttestationWindow verifies

  @ES-S-020 @ES-011 @ES-012
  # source: evidence-spec.md:535
  Scenario: ES-S-020 Truncation is durably recorded without becoming a denominator
    Given a connector observation with result_cap_hit true and pagination_complete false
    When the population service records the enumeration
    Then the signed PopulationRecord preserves both truncation values
    And the record is durably appended before the task acknowledges it

  @ES-S-021 @ES-011 @ES-012
  # source: evidence-spec.md:544
  Scenario: ES-S-021 Coverage computation maps truncation to null, not zero
    Given a stored PopulationRecord with result_cap_hit true or pagination_complete false
    When coverage is computed for its window
    Then coverage_ratio is null
    And coverage_ratio is not zero

  @ES-S-022 @ES-034
  # source: evidence-spec.md:553
  Scenario: ES-S-022 A record's role in a bundle comes from the record
    Given a bundle carrying an attestation and a validly signed CoverageGap
    When the verifier parses the bundle
    Then the CoverageGap is classified as a gap
    And it is not classified as a population record
    And no position in the container can override its record_type

  @ES-S-023 @ES-034
  # source: evidence-spec.md:563
  Scenario: ES-S-023 A non-canonical bundle is refused
    Given an attestation bundle that is not RFC 8785 canonical
    When the verifier parses it
    Then parsing fails
    And the failure names the canonical form rather than a signature

  @ES-S-024 @ES-035
  # source: evidence-spec.md:572
  Scenario: ES-S-024 An unpublished schema version is refused
    Given an attestation whose schema_version is not in the ES-035 registry
    When the verifier validates it
    Then verification fails
    And the attestation is not verified under another version's rules

  @ES-S-025 @ES-036 @AR-003
  # source: evidence-spec.md:332
  Scenario: ES-S-025 Assertion routing agrees across implementations
    Given a signed bundle carrying an assertion_id outside the catalogue
    When the same bundle bytes are verified by the Python and Go entry points
    Then both refuse with assertion.outside_catalogue
