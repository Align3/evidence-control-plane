# GENERATED FILE -- DO NOT EDIT.
# Regenerate with: python tools/extract_features.py --docs docs --out tests/features
# Edit the scenario in its owning document under docs/ instead.

Feature: Architecture invariants

  @AC-S-001 @AC-001 @AC-010
  # source: architecture.md:171
  Scenario: AC-S-001 No queue in the write path
    Given a record submitted to ingestion
    When ingestion acknowledges it
    Then the record is durably committed to the ledger
    And no acknowledgment occurs before commit

  @AC-S-002 @AC-002
  # source: architecture.md:180
  Scenario: AC-S-002 Computation purity
    Given a ledger state L
    When reconciliation and coverage run
    Then the ledger state is unchanged
    And a second run produces identical output

  @AC-S-003 @AC-008
  # source: architecture.md:189
  Scenario: AC-S-003 Confirmation-only connector blocks coverage
    Given a connector reporting capabilities {enumeration: false, confirmation: true}
    When a window-level coverage claim is requested
    Then the coverage engine refuses
    And per-action reconciliation results remain available

  @AC-S-004 @AC-012
  # source: architecture.md:198
  Scenario: AC-S-004 Ledger immutability enforced at the database
    Given the application database role
    When an UPDATE or DELETE is attempted on the evidence table
    Then the database rejects it
    And the rejection is not dependent on application-layer checks

  @AC-S-005 @AC-007
  # source: architecture.md:207
  Scenario: AC-S-005 Mode addition requires no core change
    Given a running system in mode 2
    When a mode 1 checkpoint producer is added
    Then no ledger schema change is required
    And no coverage engine change is required

  @AC-S-006 @AC-015
  # source: architecture.md:216
  Scenario: AC-S-006 Projection rebuildable from canonical bytes
    Given a populated evidence ledger
    When the parsed projection is dropped and rebuilt
    Then every record reproduces identically
    And all digests and signatures still verify
