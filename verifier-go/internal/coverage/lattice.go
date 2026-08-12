// Package coverage recomputes an attestation's coverage claim from the bundle,
// independently of the Python engine (AC-011, AG-017). Nothing here is ported;
// the admissibility lattice below is transcribed from coverage-methodology.md
// §6 rather than from any implementation of it.
package coverage

import "fmt"

// Stable dotted error codes. `coverage` is a new family — no published vector
// exercises any rule in this package (see the note on Recompute).
const (
	CodeClassUnknown           = "coverage.denominator_class_unknown"
	CodeLevelUnknown           = "coverage.level_unknown"
	CodeLevelExceedsAdmissible = "coverage.level_exceeds_class_admissible"
	CodeCappedFlagMisreported  = "coverage.capped_by_class_misreported"
	CodeRatioMissing           = "coverage.ratio_missing"
	CodeRatioMustBeNull        = "coverage.ratio_must_be_null"
	CodeRatioNotString         = "coverage.ratio_not_string"
	CodeRatioMalformed         = "coverage.ratio_malformed"
	CodeCountsInvalid          = "coverage.counts_invalid"
	CodeCountsExceedPopulation = "coverage.counts_exceed_population"
	CodeWindowInvalid          = "coverage.window_interval_invalid"
	CodeGapInvalid             = "coverage.gap_interval_invalid"
	CodeGapOutsideWindow       = "coverage.gap_outside_window"
	CodeGapConservation        = "coverage.gap_conservation_violated"
	CodeBundleShape            = "coverage.bundle_shape_invalid"
)

// Error carries a stable code.
type Error struct {
	Code string
	Msg  string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func errf(code, format string, args ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Code extracts the dotted code from an error this package produced.
func Code(err error) string {
	if e, ok := err.(*Error); ok {
		return e.Code
	}
	return ""
}

// Class is the coverage-methodology.md §3 denominator taxonomy. It is a closed
// five-member enumeration: CM-003 makes an undeclared class disqualifying, so
// there is no "unclassified" inhabitant and no default.
type Class int

const (
	classInvalid Class = iota // zero value; never a declared class
	C1
	C2
	C3
	C4
	C5
)

var classNames = map[Class]string{C1: "C1", C2: "C2", C3: "C3", C4: "C4", C5: "C5"}

func (c Class) String() string {
	if n, ok := classNames[c]; ok {
		return n
	}
	return "invalid"
}

// ParseClass admits exactly C1..C5.
func ParseClass(s string) (Class, error) {
	for c, name := range classNames {
		if name == s {
			return c, nil
		}
	}
	return classInvalid, errf(CodeClassUnknown,
		"denominator_class %q is not one of C1..C5 (coverage-methodology.md §3, CM-003)", s)
}

// Level is a coverage-methodology.md §5 coverage level.
//
// The rungs are ordered so that CM-008's minimum is an ordinary comparison.
// "Unknown / gap" is included and ranked below observed: §5 lists it as a level
// whose claim is that coverage could not be established, so a window carrying
// it claims strictly less than observed and can never breach an admissibility
// cap. CM-014 separately requires the unknown *extent* to be reported as
// intervals, which is what Result.Gaps carries — the level and the intervals
// are different statements and neither substitutes for the other.
type Level int

const (
	levelInvalid Level = iota // zero value; never a declared level
	LevelUnknown
	LevelObserved
	LevelIntercepted
	LevelEnforced
	LevelReconciled
)

var levelNames = map[Level]string{
	LevelUnknown:     "unknown",
	LevelObserved:    "observed",
	LevelIntercepted: "intercepted",
	LevelEnforced:    "enforced",
	LevelReconciled:  "reconciled",
}

func (l Level) String() string {
	if n, ok := levelNames[l]; ok {
		return n
	}
	return "invalid"
}

// ParseLevel admits exactly the §5 levels.
func ParseLevel(s string) (Level, error) {
	for l, name := range levelNames {
		if name == s {
			return l, nil
		}
	}
	return levelInvalid, errf(CodeLevelUnknown,
		"coverage_level %q is not one of the coverage-methodology.md §5 levels", s)
}

// admissible is the §6 admissibility lattice: the maximum coverage level a
// denominator class permits a window to claim, regardless of how complete our
// own records look. This is CM-008's second operand and it is recomputed here
// from the class alone — never read from the record.
var admissible = map[Class]Level{
	C1: LevelReconciled,
	C2: LevelReconciled,
	C3: LevelEnforced,
	C4: LevelObserved,
	C5: LevelObserved,
}

// AdmissibleLevel returns the §6 cap for a class.
func AdmissibleLevel(c Class) Level { return admissible[c] }

// ratioEligible is the second column of the §6 table, restated by CM-009: a
// coverage ratio is emitted only at C1, C2 or C3. At C4 and C5 the population
// is not independently enumerable and no ratio exists to emit.
var ratioEligible = map[Class]bool{C1: true, C2: true, C3: true, C4: false, C5: false}

// RatioEligible reports whether the class admits a numeric coverage ratio at
// all (CM-009, ES-017).
func RatioEligible(c Class) bool { return ratioEligible[c] }

// MinLevel is CM-008 itself: the claimed level is the minimum of the level the
// evidence supports and the level the denominator class admits.
func MinLevel(evidenceSupported, classAdmissible Level) Level {
	if evidenceSupported < classAdmissible {
		return evidenceSupported
	}
	return classAdmissible
}
