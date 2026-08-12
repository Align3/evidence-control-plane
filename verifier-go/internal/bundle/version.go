package bundle

import (
	"fmt"
	"time"
)

// SPEC GAP (recorded, not guessed).
//
// ES-027 says schema_version is semver and "verifiers MUST support every
// published version". CM-022/CM-023 say the same for methodology_version:
// "the verifier must support every published version", and that historical
// attestations remain verifiable under the version that produced them.
//
// Neither document publishes a list. coverage-methodology.md carries no
// methodology version number anywhere in its body — its only version marker is
// the prose "Draft v0.1" in the status line, which is not the same namespace as
// the "1.0.0" that appears in `methodology_version` in the vectors. So "every
// published version" is a set the corpus never enumerates, and a verifier
// cannot check membership of a set that is not written down.
//
// The sets below are taken from the one authoritative source that does state a
// value: the normative vector corpus (ES-029), where the AttestationWindow in
// `verify-customer-and-issuer-signatures` carries schema_version "1.0.0" and
// methodology_version "1.0.0". ES-031 additionally names schema_version
// "2.0.0" in prose as a version whose rules differ, so it is listed as known
// and explicitly not yet implemented here, which is a refusal rather than a
// silent verification under the wrong rules.
//
// Reported as a finding: the published-version registry needs to exist as data,
// in the corpus, or every independent verifier will invent its own.

var supportedSchemaVersions = map[string]bool{
	"1.0.0": true,
}

// knownUnimplementedSchemaVersions are versions the corpus names but this
// verifier does not implement. They are refused with a different message from
// an unrecognised version, because "I know about this and will not guess" and
// "I have never heard of this" are different statements to a relying party.
var knownUnimplementedSchemaVersions = map[string]bool{
	// ES-031 changes the constitutive-record enumeration at 2.0.0. EV-19 does
	// not implement schema-2 bundle rules; ES-S-018 belongs to that work.
	"2.0.0": true,
}

var supportedMethodologyVersions = map[string]bool{
	"1.0.0": true,
}

// checkVersions applies ES-027, ES-028 and CM-023 to the attestation.
func checkVersions(att *Record) []Finding {
	var out []Finding

	schema, ok := att.EnvelopeString("schema_version")
	if !ok || schema == "" {
		out = append(out, finding(CodeSchemaUnsupported,
			"attestation carries no schema_version"))
	} else if !supportedSchemaVersions[schema] {
		if knownUnimplementedSchemaVersions[schema] {
			out = append(out, finding(CodeSchemaUnsupported,
				"schema_version %s is published but not implemented by this verifier; "+
					"ES-028 requires a release that supports it rather than "+
					"verification under another version's rules", schema))
		} else {
			out = append(out, finding(CodeSchemaUnsupported,
				"schema_version %s is not a version this verifier supports (ES-027)",
				schema))
		}
	}

	methodology, ok := att.BodyString("methodology_version")
	if !ok || methodology == "" {
		out = append(out, finding(CodeMethodologyUnknown,
			"attestation carries no methodology_version (CM-022)"))
	} else if !supportedMethodologyVersions[methodology] {
		// CM-023 makes this a refusal rather than a fallback. A verifier that
		// silently applied its newest rules to an attestation computed under
		// older ones would be doing exactly what CM-023 forbids: applying a
		// methodology change retroactively.
		out = append(out, finding(CodeMethodologyUnknown,
			"methodology_version %s is not a version this verifier implements; "+
				"CM-023 requires the version that produced the attestation, "+
				"not the newest one", methodology))
	}

	return out
}

// validityPeriod reads and parses the AR-009 validity period.
func validityPeriod(att *Record) (time.Time, time.Time, error) {
	fromStr, ok := att.BodyString("validity_from")
	if !ok {
		return time.Time{}, time.Time{}, fmt.Errorf("attestation has no validity_from (AR-009)")
	}
	untilStr, ok := att.BodyString("validity_until")
	if !ok {
		return time.Time{}, time.Time{}, fmt.Errorf("attestation has no validity_until (AR-009)")
	}
	from, err := time.Parse(time.RFC3339, fromStr)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf(
			"validity_from %q is not RFC 3339: %w", fromStr, err)
	}
	until, err := time.Parse(time.RFC3339, untilStr)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf(
			"validity_until %q is not RFC 3339: %w", untilStr, err)
	}
	if until.Before(from) {
		return time.Time{}, time.Time{}, fmt.Errorf(
			"validity_until %s precedes validity_from %s", untilStr, fromStr)
	}
	return from, until, nil
}
