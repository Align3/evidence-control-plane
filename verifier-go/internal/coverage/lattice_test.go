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
