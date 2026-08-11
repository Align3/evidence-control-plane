# GENERATED FILE -- DO NOT EDIT.
# Regenerate with: python tools/extract_features.py --docs docs --out tests/features
# Edit the scenario in its owning document under docs/ instead.

Feature: Security controls

  @SE-S-001 @SE-003
  # source: security.md:122
  Scenario: SE-S-001 Issuer cannot sign evidence records
    Given the issuer counter-signing key
    When an attempt is made to sign an evidence record with it
    Then the record is rejected at ingestion
    And the rejection reason is "key namespace mismatch"

  @SE-S-002 @SE-007
  # source: security.md:131
  Scenario: SE-S-002 Hosted custody disclosed
    Given a tenant using hosted KMS custody
    When an attestation is issued
    Then the attestation states that signing keys are held by the issuer
    And the assurance label reflects the reduced custody

  @SE-S-003 @SE-011
  # source: security.md:140
  Scenario: SE-S-003 Cross-tenant read not expressible
    Given a query attempting to read records across two tenants
    When it is executed under any application role
    Then it fails at the database layer
    And the failure does not depend on an application-layer filter

  @SE-S-004 @SE-017
  # source: security.md:149
  Scenario: SE-S-004 Evidence deletion blocked while attestation valid
    Given a valid attestation covering window W
    When deletion of evidence within W is requested
    Then deletion is refused
    And the refusal states that the covering attestation must be revoked first

  @SE-S-005 @SE-015
  # source: security.md:158
  Scenario: SE-S-005 Never-capture fields excluded regardless of config
    Given an action family configured for full cleartext parameter capture
    And a parameter matching a never-capture classification
    When the record is emitted
    Then that parameter appears only as a digest
    And the record notes a never-capture exclusion was applied

  @SE-S-006 @SE-018
  # source: security.md:168
  Scenario: SE-S-006 Unregistered collector rejected
    Given records signed by a collector identity not in the boundary
    When they are submitted to ingestion
    Then they are rejected
    And they do not enter the ledger in any state

  @SE-S-007 @SE-009
  # source: security.md:177
  Scenario: SE-S-007 Compromise does not retroactively validate
    Given a key compromise suspected from time T
    When revocation is processed
    Then all attestations covering windows after T are revoked
    And any superseding attestation covers only the period before T

  @SE-S-008 @SE-001 @SE-003
  # source: security.md:186
  Scenario: SE-S-008 Deployment location cannot change observation origin
    Given a P2 connector that can reach a customer evidence key but not an issuer key
    When it attempts to produce a PopulationRecord or ExternalConfirmation
    Then no issuer observation is emitted
    And the evidence key is not accepted as a fallback signer
