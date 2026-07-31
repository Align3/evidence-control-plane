# GENERATED FILE -- DO NOT EDIT.
# Regenerate with: python tools/extract_features.py --docs docs --out tests/features
# Edit the scenario in its owning document under docs/ instead.

Feature: Infrastructure and operations

  @IN-S-001 @IN-003
  # source: infrastructure.md:125
  Scenario: IN-S-001 No ack before durable commit
    Given ingestion receives a valid record
    When the process is killed immediately after acknowledgment
    Then the record is present after restart
    And the chain verifies without a gap at that position

  @IN-S-002 @IN-011
  # source: infrastructure.md:134
  Scenario: IN-S-002 Offline gap emission on buffer exhaustion
    Given ingestion is unreachable
    And the SDK local buffer reaches its configured bound
    When further actions occur
    Then a locally signed CoverageGap is emitted
    And it is accepted on reconnection with its original signature

  @IN-S-003 @IN-012
  # source: infrastructure.md:144
  Scenario: IN-S-003 Out-of-order reconnection reconciles by sequence
    Given buffered records for sequences 10 through 20
    When they are submitted in arbitrary order after reconnection
    Then the ledger reconstructs the chain by sequence
    And no gap is reported

  @IN-S-004 @IN-008
  # source: infrastructure.md:153
  Scenario: IN-S-004 Restore re-verifies before accepting writes
    Given a point-in-time restore has completed
    When the system starts
    Then chain verification runs across restored evidence
    And writes are refused until verification succeeds

  @IN-S-005 @IN-018
  # source: infrastructure.md:162
  Scenario: IN-S-005 Collector silence opens a provisional gap
    Given a collector with declared cadence of 60 seconds
    When no record is received for 300 seconds
    Then an alert fires
    And a provisional CoverageGap is opened for the silent interval
    And it is closed only by evidence or by an explanation record

  @IN-S-006 @IN-001
  # source: infrastructure.md:172
  Scenario: IN-S-006 Revocation endpoint availability under partial outage
    Given ingestion and computation are degraded
    When a relying party queries revocation status
    Then the endpoint responds within SLO
    And the response is authoritative
