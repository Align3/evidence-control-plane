package coverage

import "testing"

func TestMalformedTruncationFlagCannotClearDenominator(t *testing.T) {
	id := "01890f47-2f58-7cc0-98c4-000000000211"
	window := attestationWindow(t, obj{
		"denominator_class":      "C1",
		"coverage_level":         "observed",
		"capped_by_class":        false,
		"coverage_ratio":         "1.0000",
		"population_record_refs": []any{id},
		"counts": obj{
			"matched":                    1,
			"unmatched_with_evidence":    0,
			"unmatched_without_evidence": 0,
			"duplicate":                  0,
			"ambiguous":                  0,
			"out_of_scope":               0,
		},
	})
	pop := populationRecord(t, id, obj{
		"count":               1,
		"pagination_complete": "false",
	})
	r := recompute(t, window, pop)
	if r.Reproduced() || !hasFinding(r, CodeBundleShape) {
		t.Fatalf("malformed pagination_complete cleared truncation: findings=%v unresolved=%v ratio=%s", findingCodes(r), r.Unresolved, r.Ratio)
	}
}

func TestDuplicatePopulationReferenceCannotDoubleTheDenominator(t *testing.T) {
	id := "01890f47-2f58-7cc0-98c4-000000000212"
	window := attestationWindow(t, obj{
		"denominator_class":      "C1",
		"coverage_level":         "observed",
		"capped_by_class":        false,
		"coverage_ratio":         "1.0000",
		"population_record_refs": []any{id, id},
		"counts": obj{
			"matched":                    2,
			"unmatched_with_evidence":    0,
			"unmatched_without_evidence": 0,
			"duplicate":                  0,
			"ambiguous":                  0,
			"out_of_scope":               0,
		},
	})
	pop := populationRecord(t, id, obj{"count": 1})
	r := recompute(t, window, pop)
	if !hasFinding(r, CodePopulationRefDuplicate) || r.Reproduced() {
		t.Fatalf("duplicate population reference was counted twice: findings=%v unresolved=%v", findingCodes(r), r.Unresolved)
	}
}
