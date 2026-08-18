package bundle

import (
	"fmt"
	"time"

	"github.com/Align3/evidence-control-plane/verifier-go/internal/versions"
)

// checkVersions applies ES-027, ES-028 and CM-023 to every record before any
// version-dependent rule is used.
func checkVersions(b *Bundle) []Finding {
	var out []Finding

	for _, rec := range allRecords(b) {
		schema, ok := rec.EnvelopeString("schema_version")
		if !ok || schema == "" {
			out = append(out, finding(CodeSchemaUnsupported,
				"%s %s carries no schema_version",
				rec.Parsed.RecordType(), rec.Parsed.RecordID()))
			continue
		}
		switch versions.Schema(schema) {
		case versions.Published:
			// implemented
		case versions.Reserved:
			out = append(out, finding(CodeSchemaUnsupported,
				"%s %s carries reserved schema_version %s; "+
					"ES-028 requires a release that supports it rather than "+
					"verification under another version's rules",
				rec.Parsed.RecordType(), rec.Parsed.RecordID(), schema))
		default:
			out = append(out, finding(CodeSchemaUnsupported,
				"%s %s carries schema_version %s, which is not published (ES-035)",
				rec.Parsed.RecordType(), rec.Parsed.RecordID(), schema))
		}
	}

	att := b.Attestation
	methodology, ok := att.BodyString("methodology_version")
	if !ok || methodology == "" {
		out = append(out, finding(CodeMethodologyUnknown,
			"attestation carries no methodology_version (CM-022)"))
	} else if versions.Methodology(methodology) != versions.Published {
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
