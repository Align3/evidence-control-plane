package coverage

import (
	"encoding/json"
	"testing"
)

// The fixtures below are built here rather than read from tests/vectors/,
// because the corpus contains no coverage vector to read. The one published
// AttestationWindow (`verify-customer-and-issuer-signatures`) exists to fix
// two signatures and carries a degenerate body: window_start equal to
// window_end, empty counts, empty gaps, empty assertions. Its body members and
// their encodings are reused verbatim where it has them — notably
// `"coverage_ratio": "1.0"` as a decimal *string* — so that nothing here
// contradicts the corpus.

type obj = map[string]any

func attestationWindow(t *testing.T, bodyOverrides obj, drop ...string) obj {
	t.Helper()
	body := obj{
		"boundary_ref":           "boundary-1",
		"window_start":           "2026-08-01T09:00:00.000Z",
		"window_end":             "2026-08-01T11:00:00.000Z",
		"methodology_version":    "1.0.0",
		"denominator_class":      "C1",
		"population_record_refs": []any{},
		"coverage_level":         "observed",
		"verification_status":    "self_computed",
		"coverage_ratio":         nil,
		"counts":                 obj{},
		"gaps":                   []any{},
		"assertions":             []any{},
		"exclusions":             []any{},
		"relying_parties":        []any{},
		"validity_from":          "2026-08-01T12:00:00.000Z",
		"validity_until":         "2026-09-01T12:00:00.000Z",
		"liability_ref":          "terms-1",
		"issued_at":              "2026-08-01T12:00:00.000Z",
		"issuer":                 "issuer-1",
		"verifier_version":       "0.1.0",
	}
	for k, v := range bodyOverrides {
		body[k] = v
	}
	for _, k := range drop {
		delete(body, k)
	}
	return envelope("AttestationWindow", "01890f47-2f58-7cc0-98c4-000000000064", body)
}

func populationRecord(t *testing.T, id string, overrides obj) obj {
	t.Helper()
	body := obj{
		"action_family":       "ticket.resolve",
		"destination_system":  "destination-1",
		"window_start":        "2026-08-01T09:00:00.000Z",
		"window_end":          "2026-08-01T11:00:00.000Z",
		"enumeration_query":   obj{"scope": obj{"actor": "agent-1"}},
		"record_identifiers":  []any{"ticket-1"},
		"count":               1,
		"pagination_complete": true,
		"result_cap_hit":      false,
		"retrieved_at":        "2026-08-01T11:00:01.000Z",
		"authoritative_timestamps": obj{
			"min": "2026-08-01T10:30:00.000Z",
			"max": "2026-08-01T10:30:00.000Z",
		},
	}
	for k, v := range overrides {
		body[k] = v
	}
	return envelope("PopulationRecord", id, body)
}

func coverageGap(t *testing.T, id, start, end string) obj {
	t.Helper()
	body := obj{
		"gap_start":          start,
		"gap_end":            end,
		"affected_scope":     obj{"families": []any{"ticket.resolve"}},
		"cause":              "collector_unreachable",
		"detection_source":   "collector",
		"exposure":           "known",
		"actions_during_gap": nil,
	}
	return envelope("CoverageGap", id, body)
}

func envelope(recordType, id string, body obj) obj {
	return obj{
		"record_id":      id,
		"record_type":    recordType,
		"schema_version": "1.0.0",
		"tenant_id":      "tenant-1",
		"boundary_ref":   "boundary-1",
		"stream_id":      "stream-1",
		"sequence":       1,
		"prev_digest":    nil,
		"source":         obj{"collector": "fixture", "version": "0.1.0"},
		"clocks":         obj{"source_time": "2026-08-01T12:00:00.000Z"},
		"body":           body,
		"signature": obj{
			"alg":           "ed25519",
			"key_id":        "K1",
			"sig":           "YOwNB1XA4Lozm7eTg1Sr_6GH9vuylF3RAW9ZcOqUDs9cK0R7UgH-yevJN-J7N2zBSzv8y5n1xd7hZ92fcLO1Bg",
			"signed_digest": "sha256:af311d8f37db894adb77c8afd9189ab27455dac897dec0497fb213ca61d37622",
		},
	}
}

func bundleFrom(t *testing.T, records ...obj) *Bundle {
	t.Helper()
	data, err := json.Marshal(records)
	if err != nil {
		t.Fatalf("marshalling fixture: %v", err)
	}
	b, err := ParseBundle(data)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	return b
}

func recompute(t *testing.T, records ...obj) *Result {
	t.Helper()
	r, err := Recompute(bundleFrom(t, records...))
	if err != nil {
		t.Fatalf("Recompute: %v", err)
	}
	return r
}

// findingCodes returns the determinate failures, for comparison in tests.
func findingCodes(r *Result) []string {
	out := make([]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		out = append(out, f.Code)
	}
	return out
}

func hasFinding(r *Result, code string) bool {
	for _, f := range r.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}
