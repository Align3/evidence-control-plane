# GENERATED FILE -- DO NOT EDIT.
# Regenerate with: python tools/extract_features.py --docs docs --out tests/features
# Edit the scenario in its owning document under docs/ instead.

Feature: Coverage and assurance methodology

  @CM-S-001 @CM-009
  # source: coverage-methodology.md:236
  Scenario: CM-S-001 Coverage ratio withheld at insufficient denominator class
    Given an action family "ticket.resolve" with denominator source class C4
    When coverage is computed for window W
    Then no coverage ratio is emitted
    And the maximum claimable coverage level is "observed"
    And the attestation states that the population is not independently enumerable

  @CM-S-002 @CM-005 @CM-006
  # source: coverage-methodology.md:246
  Scenario: CM-S-002 Identity isolation failure forces C5
    Given a destination connector that can enumerate all records in window W
    And the agent acts under a credential also used by human operators
    When denominator qualification runs for action family "ticket.resolve"
    Then the denominator source is classified "C5"
    And enforced and reconciled coverage are unclaimable for that family
    And the qualification record states identity isolation as the disqualifying reason

  @CM-S-003 @CM-015
  # source: coverage-methodology.md:257
  Scenario: CM-S-003 Fail-open interval cannot claim enforced coverage
    Given a declared boundary for action family "refund.issue" at class C1
    And the checkpoint is unreachable from 10:00 to 10:07
    And 12 actions executed during that interval
    When an attestation window covering 09:00-11:00 is generated
    Then the window does not claim "enforced" for 10:00-10:07
    And a signed gap record for that interval is present
    And the 12 actions are classified unknown, or reconciled if destination-matched
    And no action in that interval is classified enforced

  @CM-S-004 @CM-008
  # source: coverage-methodology.md:270
  Scenario: CM-S-004 Admissibility caps evidence-supported level
    Given evidence sufficient to support "reconciled" for every action in window W
    And a denominator source of class C3
    When coverage is computed
    Then the claimed level is "enforced"
    And the attestation records that the level was capped by denominator class

  @CM-S-005 @CM-010
  # source: coverage-methodology.md:280
  Scenario: CM-S-005 Confirmation without enumeration blocks coverage
    Given a connector that can confirm individual actions
    And that cannot enumerate the population for a window
    When an attestation is requested for that action family
    Then per-action reconciliation results are available
    And no window-level coverage claim is emitted

  @CM-S-006 @CM-020
  # source: coverage-methodology.md:290
  Scenario: CM-S-006 Late evidence supersedes rather than amends
    Given attestation A issued for window W with 3 unmatched records
    When a destination confirmation matching one of them arrives after issuance
    Then attestation A is not modified
    And a superseding attestation A' is issued referencing A
    And relying parties of A are notified

  @CM-S-007 @CM-013
  # source: coverage-methodology.md:300
  Scenario: CM-S-007 Recomputation is deterministic
    Given an evidence ledger state L, qualification record Q, and boundary B
    When coverage is computed twice
    Then both computations return identical results
    And the ledger is unchanged

  @CM-S-008 @CM-017
  # source: coverage-methodology.md:309
  Scenario: CM-S-008 Chain break terminates the window
    Given a signed evidence chain for window W
    And a sequence gap at position n with no continuity proof
    When an attestation is generated for W
    Then the window terminates at position n
    And evidence after the break is assigned to a new window
    And the attestation does not claim coverage past the break

  @CM-S-009 @CM-004
  # source: coverage-methodology.md:320
  Scenario: CM-S-009 Denominator class cannot be upgraded retroactively
    Given window W was recorded under denominator class C4
    When the connector is later upgraded to support enumeration at class C1
    Then attestations for W remain capped at the C4 admissible level
    And only windows beginning after the qualification date may claim C1

  @CM-S-010 @CM-014 @CM-016
  # source: coverage-methodology.md:329
  Scenario: CM-S-010 Unknown is not absorbed
    Given a window in which the denominator source was unavailable for 90 minutes
    When the attestation is rendered
    Then the unknown interval appears adjacent to the coverage claim
    And it is expressed as a time range with cause and affected scope
    And it is not expressed as a reduction in the coverage percentage alone
