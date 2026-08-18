package coverage

import (
	"sort"
	"time"
)

// Interval is a half-open time range [Start, End). Half-open is what makes
// CM-014's partition well-defined: with closed intervals an instant on a
// boundary belongs to two of them, so "covered and gap intervals partition the
// window exactly" has no truth value at the joins, which is precisely where a
// conservation bug hides.
type Interval struct {
	Start time.Time
	End   time.Time
}

// Duration of the interval.
func (i Interval) Duration() time.Duration { return i.End.Sub(i.Start) }

// Empty reports whether the interval covers no instant.
func (i Interval) Empty() bool { return !i.Start.Before(i.End) }

// Overlaps reports whether two half-open intervals share any instant.
func (i Interval) Overlaps(o Interval) bool {
	return i.Start.Before(o.End) && o.Start.Before(i.End)
}

// Clip returns the part of i inside w, and whether anything remains.
func (i Interval) Clip(w Interval) (Interval, bool) {
	start, end := i.Start, i.End
	if start.Before(w.Start) {
		start = w.Start
	}
	if end.After(w.End) {
		end = w.End
	}
	out := Interval{Start: start, End: end}
	return out, !out.Empty()
}

func (i Interval) String() string {
	return i.Start.Format(time.RFC3339Nano) + "/" + i.End.Format(time.RFC3339Nano)
}

// sortIntervals orders by start then end. Every list this package returns is
// sorted, because CM-013 makes recomputation a pure function whose result must
// be identical across runs — and a result assembled from a Go map or left in
// bundle order is not.
func sortIntervals(in []Interval) []Interval {
	out := make([]Interval, len(in))
	copy(out, in)
	sort.Slice(out, func(a, b int) bool {
		if !out[a].Start.Equal(out[b].Start) {
			return out[a].Start.Before(out[b].Start)
		}
		return out[a].End.Before(out[b].End)
	})
	return out
}

// mergeIntervals coalesces overlapping and abutting intervals into a minimal
// sorted disjoint set. Abutting ranges are merged too: [10:00,10:07) and
// [10:07,10:12) describe one unknown interval reported twice, and leaving them
// separate would make the covered complement depend on how the gap records
// happened to be split.
func mergeIntervals(in []Interval) []Interval {
	sorted := sortIntervals(in)
	out := make([]Interval, 0, len(sorted))
	for _, iv := range sorted {
		if iv.Empty() {
			continue
		}
		if n := len(out); n > 0 && !iv.Start.After(out[n-1].End) {
			if iv.End.After(out[n-1].End) {
				out[n-1].End = iv.End
			}
			continue
		}
		out = append(out, iv)
	}
	return out
}

// subtract returns w minus the union of cut, as a sorted disjoint set.
func subtract(w Interval, cut []Interval) []Interval {
	out := []Interval{}
	cursor := w.Start
	for _, c := range mergeIntervals(cut) {
		if !c.End.After(cursor) {
			continue
		}
		if !c.Start.Before(w.End) {
			break
		}
		if c.Start.After(cursor) {
			out = append(out, Interval{Start: cursor, End: c.Start})
		}
		if c.End.After(cursor) {
			cursor = c.End
		}
	}
	if cursor.Before(w.End) {
		out = append(out, Interval{Start: cursor, End: w.End})
	}
	return out
}

// checkConservation is CM-014 made executable, and it is the reason covered
// intervals are derived here rather than read from the attestation.
//
// The requirement is that covered intervals and gap intervals partition the
// window exactly. An interval that is neither is the silent overclaim this
// product exists to prevent (agent-working-agreement.md §4, QA-S-002), and an
// interval that is both is the same defect wearing the opposite sign — time
// counted as covered while also declared unknown.
//
// Deriving `covered` as the complement of the gaps makes the partition true by
// construction, which is exactly why it is then checked rather than assumed:
// the check is not of the attestation's arithmetic but of this function's, and
// a conservation bug in subtract() would otherwise be invisible precisely
// because the same code produced both sides.
func checkConservation(window Interval, covered, gaps []Interval) error {
	all := make([]Interval, 0, len(covered)+len(gaps))
	all = append(all, covered...)
	all = append(all, gaps...)
	all = sortIntervals(all)

	var total time.Duration
	cursor := window.Start
	for _, iv := range all {
		if iv.Empty() {
			return errf(CodeGapConservation,
				"empty interval %s in the partition of window %s", iv, window)
		}
		if iv.Start.Before(window.Start) || iv.End.After(window.End) {
			return errf(CodeGapConservation,
				"interval %s falls outside window %s (CM-014)", iv, window)
		}
		if iv.Start.Before(cursor) {
			return errf(CodeGapConservation,
				"interval %s overlaps the preceding interval; covered and gap "+
					"intervals must be disjoint (CM-014)", iv)
		}
		if iv.Start.After(cursor) {
			return errf(CodeGapConservation,
				"window %s has %s covered by neither an evidenced interval nor a "+
					"declared gap; an interval that is neither is a silent "+
					"overclaim (CM-014)", window, Interval{Start: cursor, End: iv.Start})
		}
		cursor = iv.End
		total += iv.Duration()
	}
	if !cursor.Equal(window.End) {
		return errf(CodeGapConservation,
			"window %s has %s covered by neither an evidenced interval nor a "+
				"declared gap (CM-014)", window, Interval{Start: cursor, End: window.End})
	}
	if total != window.Duration() {
		return errf(CodeGapConservation,
			"partition of window %s sums to %s, not %s (CM-014)",
			window, total, window.Duration())
	}
	return nil
}
