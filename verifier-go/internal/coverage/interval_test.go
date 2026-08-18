package coverage

import (
	"math/rand"
	"testing"
	"time"
)

func at(minutes int) time.Time {
	return time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC).Add(time.Duration(minutes) * time.Minute)
}

func iv(startMin, endMin int) Interval {
	return Interval{Start: at(startMin), End: at(endMin)}
}

// CM-014 as a property, over generated gap sets: covered and gap intervals
// partition the window exactly. This is the check QA-S-002 names and the one
// the working agreement calls out — an interval that is neither is the silent
// overclaim the product exists to prevent, and an interval that is both is the
// same defect with the opposite sign.
func TestGapConservationHoldsOverGeneratedGapSets(t *testing.T) {
	for seed := int64(0); seed < 2000; seed++ {
		rng := rand.New(rand.NewSource(seed))
		window := iv(0, 60+rng.Intn(300))
		gaps := []Interval{}
		for i := 0; i < rng.Intn(8); i++ {
			start := rng.Intn(400) - 40
			gap, inside := iv(start, start+1+rng.Intn(120)).Clip(window)
			if inside {
				gaps = append(gaps, gap)
			}
		}
		merged := mergeIntervals(gaps)
		covered := subtract(window, merged)
		if err := checkConservation(window, covered, merged); err != nil {
			t.Fatalf("seed %d: %v\n window %s\n gaps %v\n covered %v",
				seed, err, window, merged, covered)
		}
		// The partition is also checked by measure, independently of the
		// traversal above: durations must add up.
		var total time.Duration
		for _, x := range append(append([]Interval{}, covered...), merged...) {
			total += x.Duration()
		}
		if total != window.Duration() {
			t.Fatalf("seed %d: partition measures %s, window is %s", seed, total, window.Duration())
		}
	}
}

// checkConservation must actually refuse a non-partition, or the property above
// proves nothing. Both failure directions are exercised.
func TestConservationRefusesNonPartitions(t *testing.T) {
	window := iv(0, 120)

	// An interval belonging to neither set: the silent overclaim.
	if err := checkConservation(window, []Interval{iv(0, 30)}, []Interval{iv(60, 120)}); err == nil {
		t.Fatal("a window with 30-60 unaccounted for was accepted")
	} else if Code(err) != CodeGapConservation {
		t.Fatalf("wrong code %s", Code(err))
	}

	// An interval belonging to both: time counted as covered while declared
	// unknown.
	if err := checkConservation(window, []Interval{iv(0, 90)}, []Interval{iv(60, 120)}); err == nil {
		t.Fatal("overlapping covered and gap intervals were accepted")
	}

	// Reaching past the window's end.
	if err := checkConservation(window, []Interval{iv(0, 180)}, nil); err == nil {
		t.Fatal("an interval past window_end was accepted")
	}

	// Falling short of it.
	if err := checkConservation(window, []Interval{iv(0, 90)}, nil); err == nil {
		t.Fatal("a partition falling short of window_end was accepted")
	}
}

func TestMergeCoalescesOverlappingAndAbutting(t *testing.T) {
	got := mergeIntervals([]Interval{iv(30, 60), iv(0, 30), iv(50, 70), iv(90, 100)})
	want := []Interval{iv(0, 70), iv(90, 100)}
	if len(got) != len(want) {
		t.Fatalf("merge gave %v, want %v", got, want)
	}
	for i := range want {
		if !got[i].Start.Equal(want[i].Start) || !got[i].End.Equal(want[i].End) {
			t.Fatalf("merge gave %v, want %v", got, want)
		}
	}
}

func TestSubtractIsTheComplement(t *testing.T) {
	window := iv(0, 120)
	got := subtract(window, []Interval{iv(30, 45), iv(90, 120)})
	want := []Interval{iv(0, 30), iv(45, 90)}
	if len(got) != len(want) {
		t.Fatalf("subtract gave %v, want %v", got, want)
	}
	for i := range want {
		if !got[i].Start.Equal(want[i].Start) || !got[i].End.Equal(want[i].End) {
			t.Fatalf("subtract gave %v, want %v", got, want)
		}
	}
	if len(subtract(window, []Interval{iv(0, 120)})) != 0 {
		t.Fatal("a wholly unknown window left something covered")
	}
	if len(subtract(window, nil)) != 1 {
		t.Fatal("a window with no gaps is not one covered interval")
	}
}

// Half-open is what makes the partition well-defined at the joins.
func TestHalfOpenIntervalsDoNotOverlapAtTheirJoin(t *testing.T) {
	if iv(0, 30).Overlaps(iv(30, 60)) {
		t.Fatal("abutting half-open intervals reported as overlapping")
	}
	if !iv(0, 31).Overlaps(iv(30, 60)) {
		t.Fatal("genuinely overlapping intervals reported as disjoint")
	}
}
