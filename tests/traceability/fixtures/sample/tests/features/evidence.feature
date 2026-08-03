# GENERATED FILE -- DO NOT EDIT.
# Regenerate with: python tools/extract_features.py --docs docs --out tests/features
# Edit the scenario in its owning document under docs/ instead.

Feature: Agent evidence specification

  @ES-S-901 @ES-901
  # source: evidence-spec.md:16
  Scenario: ES-S-901 Record is canonical
    Given a record
    When it is canonicalised
    Then the bytes are stable
