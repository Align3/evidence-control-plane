package coverage

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Align3/evidence-control-plane/verifier-go/internal/attestation"
	"github.com/Align3/evidence-control-plane/verifier-go/internal/evidence"
)

// Negative-first (AG-007). Every affirmative case in this file is preceded by
// the withholding case it is the counterpart of: the dangerous defect here is
// a false claim, not a crash.

// --- CM-008: the lattice caps the claim ------------------------------------

// TestClaimAboveClassAdmissibleIsRefused is the CM-008 overclaim direction, at
// every class where a ceiling exists to breach.
func TestClaimAboveClassAdmissibleIsRefused(t *testing.T) {
	for _, tc := range []struct {
		class, level string
	}{
		{"C3", "reconciled"},
		{"C4", "intercepted"},
		{"C4", "enforced"},
		{"C4", "reconciled"},
		{"C5", "intercepted"},
		{"C5", "reconciled"},
	} {
		t.Run(tc.class+"_claims_"+tc.level, func(t *testing.T) {
			r := recompute(t, attestationWindow(t, obj{
				"denominator_class": tc.class,
				"coverage_level":    tc.level,
			}))
			if !hasFinding(r, CodeLevelExceedsAdmissible) {
				t.Fatalf("class %s claiming %q was not refused; findings %v",
					tc.class, tc.level, findingCodes(r))
			}
			if r.Valid() {
				t.Fatal("result reports valid despite an inadmissible claim")
			}
		})
	}
}

// TestCappedFlagIsRecomputedNotTrusted: a record claiming the cap bound when
// its own claim sits below the ceiling is refused. The flag is the issuer's
// account of whether the issuer's cap applied, so it is recomputed.
func TestCappedFlagIsRecomputedNotTrusted(t *testing.T) {
	r := recompute(t, attestationWindow(t, obj{
		"denominator_class": "C1", // admits reconciled
		"coverage_level":    "observed",
		"capped_by_class":   true, // but the cap cannot have bound
	}))
	if !hasFinding(r, CodeCappedFlagMisreported) {
		t.Fatalf("misreported capped_by_class was not refused; findings %v", findingCodes(r))
	}
}

func TestCappedFlagFalseBelowCeilingIsAccepted(t *testing.T) {
	r := recompute(t, attestationWindow(t, obj{
		"denominator_class": "C1",
		"coverage_level":    "observed",
		"capped_by_class":   false,
	}))
	if hasFinding(r, CodeCappedFlagMisreported) {
		t.Fatalf("correct capped_by_class was refused: %v", findingCodes(r))
	}
	if !r.CappedByClassDecided || r.CappedByClass {
		t.Fatal("cap should be recomputed as not binding below the ceiling")
	}
}

// TestCappedFlagAtCeilingIsUndecidable records the honest limit: at the
// ceiling, evidence at, above, or below it all produce the same claimed level,
// and the evidence-supported operand is not derivable from the bundle.
func TestCappedFlagAtCeilingIsUndecidable(t *testing.T) {
	r := recompute(t, attestationWindow(t, obj{
		"denominator_class": "C3",
		"coverage_level":    "enforced",
		"capped_by_class":   true,
	}))
	if hasFinding(r, CodeCappedFlagMisreported) {
		t.Fatalf("a flag that cannot be recomputed must not be refused: %v", findingCodes(r))
	}
	if r.CappedByClassDecided {
		t.Fatal("capped_by_class was reported as decided at the ceiling")
	}
	if r.Reproduced() {
		t.Fatal("a result with an uncheckable member must not report as fully reproduced")
	}
}

// TestCM_S_004 is coverage-methodology.md CM-S-004: evidence sufficient for
// reconciled, denominator class C3, claimed level enforced.
func TestCM_S_004_AdmissibilityCapsEvidenceSupportedLevel(t *testing.T) {
	if got := AdmissibleLevel(C3); got != LevelEnforced {
		t.Fatalf("C3 admits %q, want enforced", got)
	}
	if got := MinLevel(LevelReconciled, AdmissibleLevel(C3)); got != LevelEnforced {
		t.Fatalf("min(reconciled, enforced) = %q, want enforced", got)
	}
	r := recompute(t, attestationWindow(t, obj{
		"denominator_class": "C3",
		"coverage_level":    "enforced",
	}))
	if !r.Valid() {
		t.Fatalf("the CM-S-004 claim was refused: %v", findingCodes(r))
	}
}

func TestUnknownClassAndLevelAreRefused(t *testing.T) {
	_, err := Recompute(bundleFrom(t, attestationWindow(t, obj{"denominator_class": "C6"})))
	if Code(err) != CodeClassUnknown {
		t.Fatalf("unknown class gave %v, want %s", err, CodeClassUnknown)
	}
	r := recompute(t, attestationWindow(t, obj{"coverage_level": "fully-assured"}))
	if !hasFinding(r, CodeLevelUnknown) {
		t.Fatalf("unknown level was not refused: %v", findingCodes(r))
	}
}

// --- ES-017: the null ratio ------------------------------------------------

// TestES017_NumericRatioAtIneligibleClassIsRefused is the rule in its refusal
// direction: a bundle claiming a ratio at C4 or C5 fails verification.
func TestES017_NumericRatioAtIneligibleClassIsRefused(t *testing.T) {
	for _, class := range []string{"C4", "C5"} {
		for _, ratio := range []any{"1.0", "0.0", "0.87"} {
			r := recompute(t, attestationWindow(t, obj{
				"denominator_class": class,
				"coverage_level":    "observed",
				"coverage_ratio":    ratio,
			}))
			if !hasFinding(r, CodeRatioMustBeNull) {
				t.Fatalf("class %s with ratio %v was not refused: %v",
					class, ratio, findingCodes(r))
			}
		}
	}
}

// TestES017_ZeroIsNotNull is the specific confusion ES-017 names: serialising
// zero is non-conformant, because zero coverage and an unenumerable population
// are different claims about the world.
func TestES017_ZeroIsNotNull(t *testing.T) {
	r := recompute(t, attestationWindow(t, obj{
		"denominator_class": "C4",
		"coverage_level":    "observed",
		"coverage_ratio":    "0.0",
	}))
	if !hasFinding(r, CodeRatioMustBeNull) {
		t.Fatalf("zero at C4 was accepted as if it were the null: %v", findingCodes(r))
	}
}

// TestES_S_006_NullRatioIsExplicitNotOmitted. The omission half is enforced one
// layer down, by the §5.13 body-member check, so this asserts the refusal
// arrives rather than which component produced it.
func TestES_S_006_NullRatioIsExplicitNotOmitted(t *testing.T) {
	r := recompute(t, attestationWindow(t, obj{
		"denominator_class": "C5",
		"coverage_level":    "observed",
		"coverage_ratio":    nil,
	}))
	if !r.Valid() {
		t.Fatalf("an explicit null at C5 was refused: %v", findingCodes(r))
	}

	data, err := json.Marshal([]obj{attestationWindow(t, nil, "coverage_ratio")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseBundle(data); err == nil {
		t.Fatal("an AttestationWindow omitting coverage_ratio was accepted (ES-002b, ES-017)")
	}
}

// TestES_S_021_TruncationMapsToNullNotZero. Truncation is read from the
// referenced PopulationRecord, so the refusal does not depend on the
// attestation admitting to it.
func TestES_S_021_TruncationMapsToNullNotZero(t *testing.T) {
	for _, truncation := range []obj{
		{"result_cap_hit": true},
		{"pagination_complete": false},
		{"result_cap_hit": true, "pagination_complete": false},
	} {
		window := attestationWindow(t, obj{
			"denominator_class":      "C1",
			"coverage_level":         "observed",
			"coverage_ratio":         "1.0",
			"population_record_refs": []any{"01890f47-2f58-7cc0-98c4-000000000211"},
		})
		pop := populationRecord(t, "01890f47-2f58-7cc0-98c4-000000000211", truncation)
		r := recompute(t, window, pop)
		if !hasFinding(r, CodeRatioMustBeNull) {
			t.Fatalf("truncation %v did not force a null ratio: %v",
				truncation, findingCodes(r))
		}
	}
}

// TestUnresolvedPopulationCannotClearTruncation: a bundle that omits the
// PopulationRecord it references cannot rule out ES-011 truncation, so the
// ratio is unverifiable rather than fine (CM-021 adversary assumption).
func TestUnresolvedPopulationCannotClearTruncation(t *testing.T) {
	r := recompute(t, attestationWindow(t, obj{
		"denominator_class":      "C1",
		"coverage_ratio":         "1.0",
		"population_record_refs": []any{"missing-population"},
	}))
	if r.Reproduced() {
		t.Fatal("a ratio was reproduced without the PopulationRecord backing it")
	}
	if len(r.Unresolved) == 0 {
		t.Fatal("the missing population record was not recorded as unresolved")
	}
}

func TestRatioEncoding(t *testing.T) {
	// ES-002 forbids representing a quantity as a JSON number.
	r := recompute(t, attestationWindow(t, obj{
		"denominator_class": "C1",
		"coverage_ratio":    1,
	}))
	if !hasFinding(r, CodeRatioNotString) {
		t.Fatalf("a numeric ratio was accepted: %v", findingCodes(r))
	}
	// ES-017 fixes the scale at exactly four decimal places with no
	// trailing-zero stripping, so "1", "1.0" and "1.000" are refused spellings
	// of a conformant value rather than alternative encodings of it. A free
	// scale would let two implementations compute the same ratio and serialize
	// it differently, and QA-008 compares golden bundles byte-for-byte.
	for _, bad := range []string{
		"", "1.5", "2.0", "-0.5", ".5", "1.", "0,5", "abc", "1e0",
		"0", "1", "0.0", "1.0", "0.875", "1.000", "0.50000",
	} {
		r := recompute(t, attestationWindow(t, obj{
			"denominator_class": "C1",
			"coverage_ratio":    bad,
		}))
		if !hasFinding(r, CodeRatioMalformed) {
			t.Fatalf("ratio %q was accepted: %v", bad, findingCodes(r))
		}
	}
	for _, good := range []string{"0.0000", "1.0000", "0.8750", "0.3333", "0.6666"} {
		r := recompute(t, attestationWindow(t, obj{
			"denominator_class": "C1",
			"coverage_ratio":    good,
		}))
		if hasFinding(r, CodeRatioMalformed) {
			t.Fatalf("ratio %q was refused: %v", good, findingCodes(r))
		}
	}
}

// --- CM-014: gap conservation ---------------------------------------------

// TestGapsAndCoveredPartitionTheWindow is CM-014 / QA-S-002. The gap is
// re-derived from the signed CoverageGap record, and the covered set is the
// complement — neither is read from the attestation.
func TestGapsAndCoveredPartitionTheWindow(t *testing.T) {
	gap := coverageGap(t, "01890f47-2f58-7cc0-98c4-000000000301",
		"2026-08-01T10:00:00.000Z", "2026-08-01T10:07:00.000Z")
	window := attestationWindow(t, obj{
		"gaps": []any{"01890f47-2f58-7cc0-98c4-000000000301"},
	})
	r := recompute(t, window, gap)
	if !r.Valid() {
		t.Fatalf("a conserved partition was refused: %v", findingCodes(r))
	}
	if len(r.Gaps) != 1 || r.Gaps[0].Duration().Minutes() != 7 {
		t.Fatalf("gaps = %v, want one 7-minute interval", r.Gaps)
	}
	if len(r.Covered) != 2 {
		t.Fatalf("covered = %v, want the two intervals either side of the gap", r.Covered)
	}
	var total float64
	for _, iv := range append(append([]Interval{}, r.Covered...), r.Gaps...) {
		total += iv.Duration().Minutes()
	}
	if total != r.Window.Duration().Minutes() {
		t.Fatalf("partition sums to %v minutes, window is %v", total, r.Window.Duration().Minutes())
	}
}

// TestGapOmittedFromClaimIsRefused is the overclaim CM-014 exists to stop: the
// bundle holds a signed gap record and the attestation does not list it.
func TestGapOmittedFromClaimIsRefused(t *testing.T) {
	gap := coverageGap(t, "01890f47-2f58-7cc0-98c4-000000000301",
		"2026-08-01T10:00:00.000Z", "2026-08-01T10:07:00.000Z")
	window := attestationWindow(t, obj{"gaps": []any{}})
	r := recompute(t, window, gap)
	if !hasFinding(r, CodeGapOmittedFromClaim) {
		t.Fatalf("an undeclared signed gap was not refused: %v", findingCodes(r))
	}
	// The interval is still counted as unknown: the refusal does not also
	// silently absorb the gap into the covered set.
	if len(r.Gaps) != 1 {
		t.Fatalf("the undeclared gap was dropped from the recomputation: %v", r.Gaps)
	}
}

func TestGapOutsideWindowIsRefused(t *testing.T) {
	gap := coverageGap(t, "01890f47-2f58-7cc0-98c4-000000000302",
		"2026-08-01T12:00:00.000Z", "2026-08-01T12:30:00.000Z")
	r := recompute(t, attestationWindow(t, obj{"gaps": []any{"01890f47-2f58-7cc0-98c4-000000000302"}}), gap)
	if !hasFinding(r, CodeGapOutsideWindow) {
		t.Fatalf("a gap outside the window was accepted: %v", findingCodes(r))
	}
}

func TestGapPartlyOutsideWindowIsClipped(t *testing.T) {
	gap := coverageGap(t, "01890f47-2f58-7cc0-98c4-000000000303",
		"2026-08-01T08:00:00.000Z", "2026-08-01T09:30:00.000Z")
	r := recompute(t, attestationWindow(t, obj{"gaps": []any{"01890f47-2f58-7cc0-98c4-000000000303"}}), gap)
	if !r.Valid() {
		t.Fatalf("a partly overlapping gap was refused: %v", findingCodes(r))
	}
	if len(r.Gaps) != 1 || !r.Gaps[0].Start.Equal(r.Window.Start) {
		t.Fatalf("gap was not clipped to the window: %v", r.Gaps)
	}
	if r.Gaps[0].Duration().Minutes() != 30 {
		t.Fatalf("clipped gap is %v, want 30 minutes", r.Gaps[0].Duration())
	}
}

func TestOverlappingGapsAreMergedNotDoubleCounted(t *testing.T) {
	a := coverageGap(t, "01890f47-2f58-7cc0-98c4-000000000304",
		"2026-08-01T10:00:00.000Z", "2026-08-01T10:20:00.000Z")
	b := coverageGap(t, "01890f47-2f58-7cc0-98c4-000000000305",
		"2026-08-01T10:10:00.000Z", "2026-08-01T10:30:00.000Z")
	window := attestationWindow(t, obj{"gaps": []any{
		"01890f47-2f58-7cc0-98c4-000000000304",
		"01890f47-2f58-7cc0-98c4-000000000305",
	}})
	r := recompute(t, window, a, b)
	if !r.Valid() {
		t.Fatalf("overlapping gaps were refused: %v", findingCodes(r))
	}
	if len(r.Gaps) != 1 || r.Gaps[0].Duration().Minutes() != 30 {
		t.Fatalf("gaps = %v, want one merged 30-minute interval", r.Gaps)
	}
}

func TestWholeWindowUnknownLeavesNothingCovered(t *testing.T) {
	gap := coverageGap(t, "01890f47-2f58-7cc0-98c4-000000000306",
		"2026-08-01T09:00:00.000Z", "2026-08-01T11:00:00.000Z")
	r := recompute(t, attestationWindow(t, obj{"gaps": []any{"01890f47-2f58-7cc0-98c4-000000000306"}}), gap)
	if !r.Valid() {
		t.Fatalf("a wholly unknown window was refused: %v", findingCodes(r))
	}
	if len(r.Covered) != 0 {
		t.Fatalf("covered = %v, want nothing", r.Covered)
	}
}

func TestInvertedWindowIsRefused(t *testing.T) {
	_, err := Recompute(bundleFrom(t, attestationWindow(t, obj{
		"window_start": "2026-08-01T11:00:00.000Z",
		"window_end":   "2026-08-01T09:00:00.000Z",
	})))
	if Code(err) != CodeWindowInvalid {
		t.Fatalf("inverted window gave %v, want %s", err, CodeWindowInvalid)
	}
	// An instantaneous window has no interval for CM-014 to partition.
	_, err = Recompute(bundleFrom(t, attestationWindow(t, obj{
		"window_start": "2026-08-01T09:00:00.000Z",
		"window_end":   "2026-08-01T09:00:00.000Z",
	})))
	if Code(err) != CodeWindowInvalid {
		t.Fatalf("instantaneous window gave %v, want %s", err, CodeWindowInvalid)
	}
}

// --- CM-012: counts -------------------------------------------------------

func TestCountsCannotExceedTheEnumeratedPopulation(t *testing.T) {
	window := attestationWindow(t, obj{
		"population_record_refs": []any{"01890f47-2f58-7cc0-98c4-000000000211"},
		"counts": obj{
			"matched":                    9,
			"unmatched_with_evidence":    1,
			"unmatched_without_evidence": 0,
			"duplicate":                  0,
			"ambiguous":                  0,
		},
	})
	pop := populationRecord(t, "01890f47-2f58-7cc0-98c4-000000000211", obj{"count": 4})
	r := recompute(t, window, pop)
	if !hasFinding(r, CodeCountsExceedPopulation) {
		t.Fatalf("counts exceeding the denominator were accepted: %v", findingCodes(r))
	}
}

func TestNegativeCountIsRefused(t *testing.T) {
	r := recompute(t, attestationWindow(t, obj{"counts": obj{"matched": -1}}))
	if !hasFinding(r, CodeCountsInvalid) {
		t.Fatalf("a negative count was accepted: %v", findingCodes(r))
	}
}

// --- AR-003: the closed assertion catalogue --------------------------------

// TestAR_S_001_OffCatalogueAssertionFailsVerification.
func TestAR_S_001_OffCatalogueAssertionFailsVerification(t *testing.T) {
	for _, bad := range []any{"A-11", "A-00", "a-01", "OVERALL-SCORE"} {
		r := recompute(t, attestationWindow(t, obj{"assertions": []any{obj{"assertion_id": bad}}}))
		if !hasFinding(r, attestation.CodeAssertionOffCatalogue) {
			t.Fatalf("off-catalogue assertion %v was accepted: %v", bad, findingCodes(r))
		}
	}
	empty := recompute(t, attestationWindow(t, obj{
		"assertions": []any{obj{"assertion_id": ""}},
	}))
	if !hasFinding(empty, attestation.CodeAssertionInvalid) {
		t.Fatalf("empty assertion_id was not refused: %v", findingCodes(empty))
	}
}

func TestCataloguedAssertionsAreAccepted(t *testing.T) {
	r := recompute(t, attestationWindow(t, obj{
		"assertions": []any{obj{"assertion_id": "A-01"}, obj{"assertion_id": "A-06", "scope": "window", "count": 12}},
	}))
	if len(r.Findings) != 0 {
		t.Fatalf("catalogued assertions were refused: %v", findingCodes(r))
	}
	if !r.Assertions.Has(attestation.A01) || !r.Assertions.Has(attestation.A06) {
		t.Fatalf("assertions not read back: %v", r.Assertions.IDs)
	}
	var payloadUnresolved int
	for _, unresolved := range r.Unresolved {
		if strings.Contains(unresolved, "assertion payload") {
			payloadUnresolved++
		}
	}
	if payloadUnresolved != 2 {
		t.Fatalf("catalogued payloads were promoted to verified: %v", r.Unresolved)
	}
}

func TestDuplicateAssertionIsRefused(t *testing.T) {
	r := recompute(t, attestationWindow(t, obj{"assertions": []any{obj{"assertion_id": "A-04"}, obj{"assertion_id": "A-04"}}}))
	if !hasFinding(r, attestation.CodeAssertionDuplicated) {
		t.Fatalf("a duplicated assertion was accepted: %v", findingCodes(r))
	}
}

func TestUndeterminedAssertionShapeIsNotAPass(t *testing.T) {
	r := recompute(t, attestationWindow(t, obj{"assertions": []any{obj{"scope": "window"}}}))
	if r.Reproduced() {
		t.Fatal("an assertion whose encoding is undetermined was reported as reproduced")
	}
	if !hasFinding(r, attestation.CodeAssertionInvalid) {
		t.Fatal("an assertion without assertion_id was not refused as malformed")
	}
}

// --- bundle shape ----------------------------------------------------------

func TestBundleMustCarryExactlyOneAttestationWindow(t *testing.T) {
	none, _ := json.Marshal([]obj{populationRecord(t, "01890f47-2f58-7cc0-98c4-000000000211", nil)})
	if _, err := ParseBundle(none); Code(err) != CodeBundleShape {
		t.Fatalf("a bundle with no AttestationWindow gave %v", err)
	}
	two, _ := json.Marshal([]obj{attestationWindow(t, nil), attestationWindow(t, nil)})
	if _, err := ParseBundle(two); Code(err) != CodeBundleShape {
		t.Fatalf("a bundle with two AttestationWindows gave %v", err)
	}
}

// TestRecomputeDoesNotMutateTheBundle is the second half of CM-013: no
// computation may mutate the ledger.
func TestRecomputeDoesNotMutateTheBundle(t *testing.T) {
	gap := coverageGap(t, "01890f47-2f58-7cc0-98c4-000000000307",
		"2026-08-01T10:00:00.000Z", "2026-08-01T10:07:00.000Z")
	records := []obj{
		attestationWindow(t, obj{"gaps": []any{"01890f47-2f58-7cc0-98c4-000000000307"}}),
		gap,
		populationRecord(t, "01890f47-2f58-7cc0-98c4-000000000211", nil),
	}
	b := bundleFrom(t, records...)
	before := digestsOf(t, b)
	if _, err := Recompute(b); err != nil {
		t.Fatal(err)
	}
	if _, err := Recompute(b); err != nil {
		t.Fatal(err)
	}
	after := digestsOf(t, b)
	for i := range before {
		if before[i] != after[i] {
			t.Fatalf("record %d changed under recomputation: %s -> %s", i, before[i], after[i])
		}
	}
}

func digestsOf(t *testing.T, b *Bundle) []string {
	t.Helper()
	all := []*evidence.Record{b.Window}
	all = append(all, b.Populations...)
	all = append(all, b.Gaps...)
	all = append(all, b.Other...)
	out := make([]string, 0, len(all))
	for _, rec := range all {
		d, err := rec.CompleteDigest()
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, d)
	}
	return out
}

// --- adversarial: inputs constructed to make this verifier report a pass -----
//
// AG-012 requires actively trying to make the implementation emit a false
// claim rather than confirming that tests pass. Each case below was built by
// asking what a bundle assembler who benefits from a favourable number would
// send (CM-021), and each failed against an earlier revision of this package.

// A claimed ratio the evidence does not support must be refused.
//
// This case has been strengthened by ES-017. When the ratio had no definition
// anywhere in the corpus, a bundle claiming "1.0" over a population it had
// matched nothing in verified as fully reproduced — every rule that existed
// was satisfied, and the number itself was never checked because no
// requirement said what it meant. The best this package could then do was
// decline to report it as reproduced. ES-017 now states the formula, so the
// same bundle is a determinate refusal rather than an unresolved one, which is
// the difference between "I could not check this" and "this is false".
func TestRatioValueIsNotReportedAsReproduced(t *testing.T) {
	window := attestationWindow(t, obj{
		"denominator_class":      "C1",
		"coverage_level":         "reconciled",
		"coverage_ratio":         "1.0000",
		"population_record_refs": []any{"01890f47-2f58-7cc0-98c4-000000000211"},
		"counts": obj{
			"matched": 0, "unmatched_without_evidence": 40, "out_of_scope": 0,
		},
	})
	pop := populationRecord(t, "01890f47-2f58-7cc0-98c4-000000000211", obj{"count": 40})
	r := recompute(t, window, pop)
	if r.Valid() {
		t.Fatal("a ratio of 1.0000 over 0 matched actions was not refused")
	}
	if !hasFinding(r, CodeRatioMismatch) {
		t.Fatalf("codes = %v, want %s", findingCodes(r), CodeRatioMismatch)
	}
	if r.Reproduced() {
		t.Fatal("a ratio of 1.0000 over 0 matched actions was reported as reproduced")
	}
}

func TestUnrecognisedCountsMemberIsNotSummed(t *testing.T) {
	window := attestationWindow(t, obj{
		"population_record_refs": []any{"01890f47-2f58-7cc0-98c4-000000000211"},
		"counts": obj{
			"matched":            1,
			"reviewed_last_week": 9999,
		},
	})
	pop := populationRecord(t, "01890f47-2f58-7cc0-98c4-000000000211", obj{"count": 4})
	r := recompute(t, window, pop)
	if hasFinding(r, CodeCountsExceedPopulation) {
		t.Fatalf("an unrecognised member was summed into the CM-012 total: %v", findingCodes(r))
	}
	if r.Reproduced() {
		t.Fatal("an uncounted member was not reported as unchecked")
	}
}

// out_of_scope is a CM-012 bucket that §5.13's counts enumeration omits. It is
// counted when present, because an out-of-scope record was still enumerated
// and still occupies the denominator.
func TestOutOfScopeCountsTowardTheDenominator(t *testing.T) {
	window := attestationWindow(t, obj{
		"population_record_refs": []any{"01890f47-2f58-7cc0-98c4-000000000211"},
		"counts":                 obj{"matched": 3, "out_of_scope": 5},
	})
	pop := populationRecord(t, "01890f47-2f58-7cc0-98c4-000000000211", obj{"count": 4})
	r := recompute(t, window, pop)
	if !hasFinding(r, CodeCountsExceedPopulation) {
		t.Fatalf("out_of_scope was excluded from the denominator: %v", findingCodes(r))
	}
}

// A CoverageGap from another tenant or another boundary version says nothing
// about this window. Counting one lets unknown time be manufactured from
// unrelated evidence — and, worse, lets a gaps[] entry be satisfied by a
// record that does not govern the window it is declared in.
func TestGapFromAnotherTenantOrBoundaryIsRefused(t *testing.T) {
	for _, mutate := range []func(obj){
		func(g obj) { g["tenant_id"] = "tenant-2" },
		func(g obj) { g["boundary_ref"] = "boundary-2" },
	} {
		gap := coverageGap(t, "01890f47-2f58-7cc0-98c4-000000000401",
			"2026-08-01T10:00:00.000Z", "2026-08-01T10:07:00.000Z")
		mutate(gap)
		window := attestationWindow(t, obj{
			"gaps": []any{"01890f47-2f58-7cc0-98c4-000000000401"},
		})
		r := recompute(t, window, gap)
		if !hasFinding(r, CodeGapInvalid) {
			t.Fatalf("a foreign CoverageGap was counted: %v", findingCodes(r))
		}
		if len(r.Gaps) != 0 {
			t.Fatalf("a foreign gap reached the partition: %v", r.Gaps)
		}
	}
}

// The withholding limit, stated as a test so it is not mistaken for a gap in
// the checking. SE-004 and evidence-spec.md §7 are explicit that the model
// prevents forgery, not withholding: a gap record simply left out of the
// bundle cannot be detected from the bundle. This asserts what the verifier
// does claim in that case — nothing about the omitted interval — rather than
// pretending to catch it.
func TestOmittedGapRecordIsOutsideWhatABundleCanShow(t *testing.T) {
	r := recompute(t, attestationWindow(t, obj{"gaps": []any{}}))
	if !r.Valid() {
		t.Fatalf("a bundle with no gap records was refused: %v", findingCodes(r))
	}
	if len(r.Covered) != 1 || !r.Covered[0].Start.Equal(r.Window.Start) {
		t.Fatalf("covered = %v, want the whole window", r.Covered)
	}
}
