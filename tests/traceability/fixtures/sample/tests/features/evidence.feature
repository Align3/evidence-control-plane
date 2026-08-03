# GENERATED FILE -- DO NOT EDIT.

Feature: Evidence fixture

  @ES-S-901 @ES-901
  Scenario: ES-S-901 Record is canonical
    Given a record
    When it is canonicalised
    Then the bytes are stable
