package coverage

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"testing"
	"time"
)

// CM-013 — purity. Coverage computation is a pure function of the stored
// evidence ledger, the qualification record, and the declared boundary;
// recomputation from the same inputs yields an identical result, and no
// computation may mutate the ledger. CM-S-007 states it as a scenario.
//
// A single "compute twice, compare" example is a weak demonstration of that,
// because the ways a recomputation goes non-deterministic are mostly invisible
// on one input: Go randomises map iteration order per range statement, so a
// result assembled from a map is stable across two calls surprisingly often and
// unstable once the collection is large enough or the process is unlucky. The
// property is therefore exercised over generated bundles, over many iterations
// each, with the result rendered to a canonical string so that ordering
// differences show up as inequality rather than being smoothed away by a
// field-by-field comparison that happens to sort.

const determinismRepeats = 8

func TestCM_S_007_RecomputationIsDeterministic(t *testing.T) {
	for seed := int64(0); seed < 400; seed++ {
		seed := seed
		records := generateBundle(rand.New(rand.NewSource(seed)))
		data, err := json.Marshal(records)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		b, err := ParseBundle(data)
		if err != nil {
			// A generated bundle the record layer refuses is not a coverage
			// input at all; skip rather than assert anything about it.
			continue
		}
		var first string
		for i := 0; i < determinismRepeats; i++ {
			r, err := Recompute(b)
			if err != nil {
				if i == 0 {
					first = "error:" + err.Error()
					continue
				}
				if got := "error:" + err.Error(); got != first {
					t.Fatalf("seed %d: recomputation %d returned %s, first returned %s",
						seed, i, got, first)
				}
				continue
			}
			got := render(r)
			if i == 0 {
				first = got
				continue
			}
			if got != first {
				t.Fatalf("seed %d: recomputation %d differs from the first\n first: %s\n  got: %s",
					seed, i, first, got)
			}
		}
	}
}

// TestRecomputationIsIndependentOfBundleOrder is the same property from the
// other side. CM-013 makes the result a function of the ledger state, and the
// order records happen to sit in a bundle is not part of that state. A result
// that depends on it would make two relying parties given the same evidence
// reach different conclusions.
func TestRecomputationIsIndependentOfBundleOrder(t *testing.T) {
	for seed := int64(0); seed < 200; seed++ {
		rng := rand.New(rand.NewSource(seed))
		records := generateBundle(rng)
		b1, err := parseOrSkip(records)
		if err != nil {
			continue
		}
		shuffled := append([]obj(nil), records...)
		rng.Shuffle(len(shuffled), func(i, j int) {
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		})
		b2, err := parseOrSkip(shuffled)
		if err != nil {
			continue
		}
		r1, err1 := Recompute(b1)
		r2, err2 := Recompute(b2)
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("seed %d: reordering changed whether recomputation succeeded: %v / %v",
				seed, err1, err2)
		}
		if err1 != nil {
			continue
		}
		// Findings are reported in the order the checks run, which is fixed;
		// what must not vary is the set of them, nor any derived interval.
		if render(sorted(r1)) != render(sorted(r2)) {
			t.Fatalf("seed %d: reordering the bundle changed the result\n a: %s\n b: %s",
				seed, render(sorted(r1)), render(sorted(r2)))
		}
	}
}

func parseOrSkip(records []obj) (*Bundle, error) {
	data, err := json.Marshal(records)
	if err != nil {
		return nil, err
	}
	return ParseBundle(data)
}

func sorted(r *Result) *Result {
	out := *r
	codes := findingCodes(r)
	sort.Strings(codes)
	out.Findings = nil
	for _, c := range codes {
		out.Findings = append(out.Findings, &Error{Code: c})
	}
	return &out
}

// render writes a Result to a canonical string. Every collection is emitted in
// the order the Result carries it, deliberately: the point is to detect an
// ordering that varies, so re-sorting here would hide the defect under test.
func render(r *Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "window=%s class=%s claimed=%s admissible=%s capped=%v/%v eligible=%v ratio=%q",
		r.Window, r.DenominatorClass, r.ClaimedLevel, r.AdmissibleLevel,
		r.CappedByClass, r.CappedByClassDecided, r.RatioEligible, r.Ratio)
	b.WriteString(" covered=[")
	for _, iv := range r.Covered {
		b.WriteString(iv.String() + ",")
	}
	b.WriteString("] gaps=[")
	for _, iv := range r.Gaps {
		b.WriteString(iv.String() + ",")
	}
	b.WriteString("] assertions=[")
	for _, id := range r.Assertions.IDs {
		b.WriteString(id.String() + ",")
	}
	b.WriteString("] findings=[")
	for _, f := range r.Findings {
		b.WriteString(f.Code + ",")
	}
	b.WriteString("] unresolved=[")
	for _, u := range r.Unresolved {
		b.WriteString(u + ";")
	}
	b.WriteString("]")
	return b.String()
}

// generateBundle produces a bundle exercising every branch the recomputation
// has: each denominator class, each level, ratios both admissible and not,
// truncated and intact population records, gaps inside, straddling and outside
// the window, declared and undeclared, and assertion lists both catalogued and
// not.
func generateBundle(rng *rand.Rand) []obj {
	base := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	windowEnd := base.Add(time.Duration(30+rng.Intn(240)) * time.Minute)

	classes := []string{"C1", "C2", "C3", "C4", "C5"}
	levels := []string{"unknown", "observed", "intercepted", "enforced", "reconciled"}
	ratios := []any{nil, "1.0", "0.5", "0", "0.999", 1}

	class := classes[rng.Intn(len(classes))]
	window := obj{
		"denominator_class": class,
		"coverage_level":    levels[rng.Intn(len(levels))],
		"coverage_ratio":    ratios[rng.Intn(len(ratios))],
		"window_start":      base.Format("2006-01-02T15:04:05.000Z"),
		"window_end":        windowEnd.Format("2006-01-02T15:04:05.000Z"),
	}
	if rng.Intn(2) == 0 {
		window["capped_by_class"] = rng.Intn(2) == 0
	}

	records := []obj{}
	gapRefs := []any{}
	for i := 0; i < rng.Intn(5); i++ {
		id := fmt.Sprintf("01890f47-2f58-7cc0-98c4-0000000004%02d", i)
		offset := time.Duration(rng.Intn(360)-60) * time.Minute
		start := base.Add(offset)
		end := start.Add(time.Duration(1+rng.Intn(90)) * time.Minute)
		records = append(records, coverageGap(t0(), id,
			start.Format("2006-01-02T15:04:05.000Z"),
			end.Format("2006-01-02T15:04:05.000Z")))
		if rng.Intn(4) > 0 {
			gapRefs = append(gapRefs, id)
		}
	}
	window["gaps"] = gapRefs

	popRefs := []any{}
	for i := 0; i < rng.Intn(3); i++ {
		id := fmt.Sprintf("01890f47-2f58-7cc0-98c4-0000000005%02d", i)
		records = append(records, populationRecord(t0(), id, obj{
			"count":               rng.Intn(50),
			"result_cap_hit":      rng.Intn(3) == 0,
			"pagination_complete": rng.Intn(3) != 0,
		}))
		popRefs = append(popRefs, id)
	}
	if rng.Intn(6) == 0 {
		popRefs = append(popRefs, "absent-population")
	}
	window["population_record_refs"] = popRefs

	counts := obj{}
	for _, name := range []string{"matched", "unmatched_with_evidence",
		"unmatched_without_evidence", "duplicate", "ambiguous"} {
		counts[name] = rng.Intn(20)
	}
	window["counts"] = counts

	catalogued := []string{"A-01", "A-02", "A-03", "A-04", "A-05", "A-06", "A-07", "A-08", "A-09", "A-10"}
	assertions := []any{}
	for i := 0; i < rng.Intn(6); i++ {
		switch rng.Intn(4) {
		case 0:
			assertions = append(assertions, catalogued[rng.Intn(len(catalogued))])
		case 1:
			assertions = append(assertions, obj{
				"id": catalogued[rng.Intn(len(catalogued))], "count": rng.Intn(9)})
		case 2:
			assertions = append(assertions, obj{"scope": "window"})
		default:
			assertions = append(assertions, fmt.Sprintf("A-%02d", 11+rng.Intn(5)))
		}
	}
	window["assertions"] = assertions

	return append([]obj{attestationWindow(t0(), window)}, records...)
}

// t0 supplies the *testing.T the fixture helpers take. The helpers use it only
// for t.Helper(), and the generator runs outside any subtest, so a stub keeps
// the fixtures shared between the example tests and the property tests rather
// than duplicated.
func t0() *testing.T { return &testing.T{} }
