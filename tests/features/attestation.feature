# GENERATED FILE -- DO NOT EDIT.
# Regenerate with: python tools/extract_features.py --docs docs --out tests/features
# Edit the scenario in its owning document under docs/ instead.

Feature: Attestation and reliance framework

  @AR-S-001 @AR-003
  # source: attestation-reliance.md:203
  Scenario: AR-S-001 No assertion outside the catalogue
    Given an attestation generation request
    When the assertion set is assembled
    Then every assertion maps to a catalogue ID
    And any unmapped assertion causes generation to fail

  @AR-S-002 @AR-004
  # source: attestation-reliance.md:212
  Scenario: AR-S-002 No aggregate score
    When an attestation is rendered
    Then no single composite score, rating, or grade appears
    And each assertion carries its own scope and counts

  @AR-S-003 @AR-006
  # source: attestation-reliance.md:220
  Scenario: AR-S-003 Excluded scope disclosed
    Given a customer operating action families [X, Y, Z]
    And a boundary covering only [X]
    When an attestation is issued
    Then it states that other families exist and are out of scope

  @AR-S-004 @AR-009
  # source: attestation-reliance.md:229
  Scenario: AR-S-004 Expired verifies as expired
    Given an attestation whose validity_until has passed
    When the verifier validates it
    Then the result is "expired"
    And the result is not "valid"

  @AR-S-005 @AR-011
  # source: attestation-reliance.md:238
  Scenario: AR-S-005 Supersession preserves the original
    Given attestation A and superseding attestation A'
    When either is verified
    Then A remains independently verifiable
    And A' references A
    And A is reported as superseded, not invalid

  @AR-S-006 @AR-025
  # source: attestation-reliance.md:248
  Scenario: AR-S-006 Phase 0 artefact language check
    Given a phase 0 evidence pack
    When it is reviewed before release
    Then it contains none of: attestation, certification, assurance, verified, audited
    And it carries the full §9 header

  @AR-S-007 @AR-027 @QA-018
  # source: attestation-reliance.md:257
  Scenario: AR-S-007 A-02 is withheld where the boundary did not span the window
    Given the referenced assurance boundary version has effective interval B1 to B2 after applying its declared window, signed ingest time, and any next version
    And an attestation window from W1 to W2 where W1 < B1 or W2 > B2
    When the attestation is generated
    Then A-02 is withheld
    And the uncovered interval is reported with its bounds
    And no narrower restatement of A-02 is emitted in its place

  @AR-S-008 @AR-028 @QA-018
  # source: attestation-reliance.md:278
  Scenario: AR-S-008 A-09 is withheld where outcomes were not confirmed
    Given R actions claimed as confirmed against a named authoritative source
    And S of them have no OutcomeRecord whose authoritative_source matches that source
    When the attestation is generated
    Then A-09 is withheld unless R is restated as R - S
    And the named source is identified in the attestation
    And an unnamed or absent source withholds A-09 outright

  @AR-S-009 @AR-029
  # source: attestation-reliance.md:294
  Scenario: AR-S-009 An answer the verifier cannot authenticate establishes nothing
    Given a revocation endpoint that does not answer with an authenticated RevocationRecord
    When the verifier checks revocation for an attestation
    Then revocation_status is reported as "unchecked"
    And it is not reported as "valid"
    And it is not reported as "revoked"

  @AR-S-010 @AR-030
  # source: attestation-reliance.md:304
  Scenario: AR-S-010 Supersession is distinguished from revocation
    Given an authenticated RevocationRecord naming a superseding attestation
    When the verifier checks revocation
    Then revocation_status is reported as "superseded"
    And the superseding attestation is identified
    And an otherwise identical record with no superseding_ref reports "revoked"

  @AR-S-011 @AR-031
  # source: attestation-reliance.md:314
  Scenario: AR-S-011 A revocation before its effective date does not revoke
    Given an authenticated RevocationRecord whose effective_at is later than the evaluation instant
    When the verifier checks revocation
    Then revocation_status is reported as "valid"
    And the pending revocation and its effective_at are surfaced
    And the evaluation instant appears in the output
