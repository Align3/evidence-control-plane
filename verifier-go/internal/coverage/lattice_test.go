package coverage

import "testing"

// The §6 admissibility lattice, transcribed from coverage-methodology.md rather
// than from any implementation of it, and asserted as a complete table so that
// a future edit to `admissible` has to change a test that names the document.
func TestAdmissibilityLatticeMatchesSection6(t *testing.T) {
	for _, tc := range []struct {
		class Class
		level Level
		ratio bool
	}{
		{C1, LevelReconciled, true},
		{C2, LevelReconciled, true},
		{C3, LevelEnforced, true},
		{C4, LevelObserved, false},
		{C5, LevelObserved, false},
	} {
		if got := AdmissibleLevel(tc.class); got != tc.level {
			t.Errorf("%s admits %q, §6 says %q", tc.class, got, tc.level)
		}
		if got := RatioEligible(tc.class); got != tc.ratio {
			t.Errorf("%s ratio eligibility %v, §6 says %v", tc.class, got, tc.ratio)
		}
	}
}

// CM-009 is the second column stated as a requirement: a ratio is emitted only
// at C1, C2 or C3.
func TestNoRatioBelowC3(t *testing.T) {
	for _, c := range []Class{C4, C5} {
		if RatioEligible(c) {
			t.Errorf("%s must emit no coverage ratio (CM-009, ES-017)", c)
		}
	}
}

// CM-008 is a minimum, and the operand order must not matter.
func TestMinLevelIsCommutativeAndBounded(t *testing.T) {
	levels := []Level{LevelUnknown, LevelObserved, LevelIntercepted, LevelEnforced, LevelReconciled}
	for _, a := range levels {
		for _, b := range levels {
			got := MinLevel(a, b)
			if got != MinLevel(b, a) {
				t.Fatalf("min(%s,%s) != min(%s,%s)", a, b, b, a)
			}
			if got > a || got > b {
				t.Fatalf("min(%s,%s) = %s, which exceeds an operand", a, b, got)
			}
		}
	}
}

// "Unknown / gap" ranks below observed, so a window carrying it can never
// breach a cap. It is included as a §5 level and excluded from the ladder's
// interpretation as a strength ordering above observed.
func TestUnknownRanksBelowObserved(t *testing.T) {
	if !(LevelUnknown < LevelObserved) {
		t.Fatal("unknown must claim strictly less than observed")
	}
	for _, c := range []Class{C1, C2, C3, C4, C5} {
		if LevelUnknown > AdmissibleLevel(c) {
			t.Fatalf("unknown breaches the %s cap", c)
		}
	}
}

func TestParsersAreClosed(t *testing.T) {
	for _, s := range []string{"C0", "C6", "c1", "", "C1 ", "class-1"} {
		if _, err := ParseClass(s); Code(err) != CodeClassUnknown {
			t.Errorf("ParseClass(%q) was not refused", s)
		}
	}
	for _, s := range []string{"", "Observed", "verified", "independently_reproduced", "gap"} {
		if _, err := ParseLevel(s); Code(err) != CodeLevelUnknown {
			t.Errorf("ParseLevel(%q) was not refused", s)
		}
	}
	for _, s := range []string{"C1", "C2", "C3", "C4", "C5"} {
		if _, err := ParseClass(s); err != nil {
			t.Errorf("ParseClass(%q): %v", s, err)
		}
	}
}

// The zero values are not declared classes or levels: CM-003 makes an
// undeclared class disqualifying, so a forgotten initialisation must not read
// as C1 or as observed.
func TestZeroValuesAreNotDeclarations(t *testing.T) {
	var c Class
	var l Level
	if c.String() != "invalid" || l.String() != "invalid" {
		t.Fatalf("zero values render as %q / %q", c, l)
	}
	if AdmissibleLevel(c) != levelInvalid {
		t.Fatal("an undeclared class admits a level")
	}
	if RatioEligible(c) {
		t.Fatal("an undeclared class is ratio-eligible")
	}
}

// TestRatioFixedScaleAndTruncation pins ES-017's encoding on fractions that do
// not terminate at four places.
//
// These are the cases a published vector would carry, and they are here instead
// because the corpus cannot yet accept them: tests/vectors requires every
// operation to have a Python runner and the file to match deterministic
// generation, so a Go-only vector cannot be published. That is QA-019 enforced
// mechanically rather than by convention. EV-41 is what makes them publishable.
//
// A vector at 1.0000 or 0.5000 would distinguish nothing: it cannot tell a
// conformant implementation from one that rounds half-up, and it cannot tell
// fixed scale from trailing-zero stripping.
func TestRatioFixedScaleAndTruncation(t *testing.T) {
	cases := []struct {
		name                            string
		matched, population, outOfScope int64
		want                            string
	}{
		{
			// 1 / (4 - 1) = 0.333...  Exercises the denominator exclusion and
			// the fixed scale together.
			name:    "one third, with an out-of-scope record excluded",
			matched: 1, population: 4, outOfScope: 1, want: "0.3333",
		},
		{
			// 2/3 = 0.6666...  This is the case that separates truncation from
			// rounding: half-up would give 0.6667 and would report more
			// coverage than was measured.
			name:    "two thirds truncates toward zero rather than rounding up",
			matched: 2, population: 3, outOfScope: 0, want: "0.6666",
		},
		{
			name:    "one seventh",
			matched: 1, population: 7, outOfScope: 0, want: "0.1428",
		},
		{
			// Trailing zeros are never stripped: "1" and "1.0" are refused
			// spellings of this value.
			name:    "full coverage keeps its four decimal places",
			matched: 3, population: 3, outOfScope: 0, want: "1.0000",
		},
		{
			name:    "zero matched is not an absent ratio",
			matched: 0, population: 5, outOfScope: 0, want: "0.0000",
		},
		{
			// Every action out of scope leaves an empty in-scope denominator,
			// which ES-017 sends to null rather than to 0.0000.
			name:    "out-of-scope records do not inflate the denominator",
			matched: 1, population: 2, outOfScope: 1, want: "1.0000",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := RatioFor(tc.matched, tc.population, tc.outOfScope)
			if err != nil {
				t.Fatalf("RatioFor: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			if len(got) != 6 || got[1] != '.' {
				t.Fatalf("%q is not a fixed four-decimal string (ES-017)", got)
			}
		})
	}
}

// TestRatioRefusalsAreNotSilentZeros: the degenerate cases must refuse rather
// than produce a number that reads as a measurement.
func TestRatioRefusalsAreNotSilentZeros(t *testing.T) {
	cases := []struct {
		name                            string
		matched, population, outOfScope int64
		wantCode                        string
	}{
		{"empty in-scope denominator", 0, 2, 2, CodeRatioMustBeNull},
		{"out-of-scope exceeds the population", 0, 1, 2, CodeRatioMismatch},
		{"matched exceeds the in-scope denominator", 3, 3, 1, CodeRatioMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := RatioFor(tc.matched, tc.population, tc.outOfScope)
			if err == nil {
				t.Fatalf("got %q; this case has no ratio to state", got)
			}
			if Code(err) != tc.wantCode {
				t.Fatalf("code = %s, want %s", Code(err), tc.wantCode)
			}
		})
	}
}
