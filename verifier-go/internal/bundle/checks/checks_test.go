package checks

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Align3/evidence-control-plane/verifier-go/internal/bundle"
	"github.com/Align3/evidence-control-plane/verifier-go/internal/coverage"
	"github.com/Align3/evidence-control-plane/verifier-go/internal/revocation"
	"github.com/Align3/evidence-control-plane/verifier-go/internal/testfixture"
)

// These tests exercise the adapter, which is the one place a correct
// recomputation and a correct bundle path can still combine into a wrong
// answer: a finding dropped in translation, or an unresolved item quietly
// promoted to a pass, would leave both halves individually right and the
// verifier wrong.

func build(t *testing.T, overrides map[string]any) (*bundle.Bundle, testfixture.Keys) {
	t.Helper()
	keys, err := testfixture.NewKeys()
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	body := testfixture.AttestationBody()
	for k, v := range overrides {
		body[k] = v
	}
	class, _ := body["denominator_class"].(string)
	env := testfixture.NewEnvelope("AttestationWindow",
		"01890f47-2f58-7cc0-98c4-000000000064", "tenant-1", "attestation-1", body)
	attWire, err := env.SignAttestation(keys)
	if err != nil {
		t.Fatalf("sign attestation: %v", err)
	}
	qualEnv := testfixture.NewEnvelope("QualificationRecord",
		"01890f47-2f58-7cc0-98c4-000000000101", "tenant-1", "qualifications-1",
		testfixture.QualificationBody(class, "2026-01-01T00:00:00Z"))
	qualWire, err := qualEnv.Sign(testfixture.EvidenceKeyID, keys.Evidence)
	if err != nil {
		t.Fatalf("sign qualification: %v", err)
	}
	container, err := testfixture.Bundle(attWire, qualWire)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	parsed, err := bundle.Parse(container)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return parsed, keys
}

type okFetcher struct{}

func (okFetcher) Fetch(context.Context, string) (int, []byte, error) { return 404, nil, nil }

func verify(t *testing.T, b *bundle.Bundle, keys testfixture.Keys) bundle.Result {
	t.Helper()
	return bundle.Verify(context.Background(), b, bundle.Options{
		Keys:   keys.Keyring,
		Checks: All(),
		Now:    func() time.Time { return time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC) },
		Revocation: revocation.Checker{
			Fetcher: okFetcher{}, IssuerKeys: keys.Keyring,
		},
	})
}

// TestES017RefusalReachesTheVerdict is the end-to-end proof that the seam
// carries a refusal. A numeric ratio at C4 is refused by the recomputation;
// this asserts it is still refused after crossing into the bundle verdict.
func TestES017RefusalReachesTheVerdict(t *testing.T) {
	b, keys := build(t, map[string]any{
		"denominator_class": "C4",
		"coverage_ratio":    "0.97",
		"coverage_level":    "observed",
	})
	res := verify(t, b, keys)
	if res.Verdict != bundle.Invalid {
		t.Fatalf("verdict = %s; a numeric ratio at C4 must refuse (ES-017)", res.Verdict)
	}
	var found bool
	for _, f := range res.Findings {
		if strings.Contains(f.Code, "ratio") {
			found = true
			// The rendered finding must not repeat its own code.
			if strings.HasPrefix(f.Message, f.Code+": ") {
				t.Fatalf("finding message repeats its code: %s", f)
			}
		}
	}
	if !found {
		t.Fatalf("no ratio finding crossed the seam: %v", res.Findings)
	}
}

// TestCM008RefusalReachesTheVerdict: a level above the class ceiling.
func TestCM008RefusalReachesTheVerdict(t *testing.T) {
	b, keys := build(t, map[string]any{
		"denominator_class": "C4",
		"coverage_level":    "enforced",
	})
	res := verify(t, b, keys)
	if res.Verdict != bundle.Invalid {
		t.Fatalf("verdict = %s; CM-008 caps the claim at the class ceiling", res.Verdict)
	}
}

// TestAR003RefusalReachesTheVerdict: an assertion outside the closed catalogue.
func TestAR003RefusalReachesTheVerdict(t *testing.T) {
	b, keys := build(t, map[string]any{"assertions": []any{"A-99"}})
	res := verify(t, b, keys)
	if res.Verdict != bundle.Invalid {
		t.Fatalf("verdict = %s; AR-003 closes the catalogue", res.Verdict)
	}
}

// TestUnresolvedIsNotPromotedToAPass is the failure mode the adapter exists to
// avoid. The recomputation reports items it could not decide; if the adapter
// dropped them, a bundle whose coverage claim was never checked would come out
// the far side as "valid".
func TestUnresolvedIsNotPromotedToAPass(t *testing.T) {
	b, keys := build(t, nil)
	res := verify(t, b, keys)
	if len(res.Unresolved) == 0 {
		t.Skip("the recomputation resolved everything for this fixture; " +
			"nothing to carry across the seam")
	}
	if res.Verdict == bundle.Valid {
		t.Fatalf("verdict = valid with %d unresolved items: %v",
			len(res.Unresolved), res.Unresolved)
	}
	var attributed bool
	for _, u := range res.Unresolved {
		if strings.HasPrefix(u, "coverage: ") {
			attributed = true
		}
	}
	if !attributed {
		t.Fatalf("no unresolved item is attributed to the coverage check: %v",
			res.Unresolved)
	}
}

// TestSupportingRecordsCrossTheSeam guards the conversion between the two
// bundle containers: a population or gap record that failed to cross would
// leave the recomputation working from a bundle emptier than the one the
// relying party was given.
func TestSupportingRecordsCrossTheSeam(t *testing.T) {
	keys, err := testfixture.NewKeys()
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	gapBody := map[string]any{
		"gap_start":          "2026-08-05T00:00:00Z",
		"gap_end":            "2026-08-06T00:00:00Z",
		"affected_scope":     map[string]any{"families": []any{"refund.issue"}},
		"cause":              "collector_unreachable",
		"detection_source":   "collector",
		"exposure":           "known",
		"actions_during_gap": nil,
	}
	gapEnv := testfixture.NewEnvelope("CoverageGap",
		"01890f47-2f58-7cc0-98c4-000000000201", "tenant-1", "gaps-1", gapBody)
	gapWire, err := gapEnv.Sign(testfixture.EvidenceKeyID, keys.Evidence)
	if err != nil {
		t.Fatalf("sign gap: %v", err)
	}
	body := testfixture.AttestationBody()
	env := testfixture.NewEnvelope("AttestationWindow",
		"01890f47-2f58-7cc0-98c4-000000000064", "tenant-1", "attestation-1", body)
	attWire, err := env.SignAttestation(keys)
	if err != nil {
		t.Fatalf("sign attestation: %v", err)
	}
	container, err := testfixture.Bundle(attWire, gapWire)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	parsed, err := bundle.Parse(container)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	converted := toCoverageBundle(parsed)
	if len(converted.Gaps) != 1 {
		t.Fatalf("gap records did not cross the seam: %d carried", len(converted.Gaps))
	}
	if converted.Window == nil ||
		converted.Window.RecordType() != "AttestationWindow" {
		t.Fatal("the attestation did not cross the seam")
	}
	// A signed gap the attestation omits from gaps[] is the overclaim this
	// pairing exists to catch; assert only that the check now sees it.
	res := bundle.Verify(context.Background(), parsed, bundle.Options{
		Keys:   keys.Keyring,
		Checks: All(),
		Now:    func() time.Time { return time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC) },
	})
	if res.Verdict == bundle.Valid {
		t.Fatalf("a bundle with an unlisted signed gap verified as valid: %v", res)
	}
}

// TestBothPackagesClassifyRecordsIdentically guards the one thing that can go
// wrong while both halves stay individually correct.
//
// ES-034 settled the container on the array, and both packages now parse it —
// internal/bundle for the shipped path, coverage.ParseBundle for that
// package's own fixtures. Two parsers of one format can still drift, and if
// they do, the coverage suite stops being evidence about the shipped path.
// This asserts the same bytes land in the same buckets and reach the same
// conclusion either way.
func TestBothPackagesClassifyRecordsIdentically(t *testing.T) {
	keys, err := testfixture.NewKeys()
	if err != nil {
		t.Fatalf("keys: %v", err)
	}

	attWire, err := testfixture.NewEnvelope("AttestationWindow",
		"01890f47-2f58-7cc0-98c4-000000000064", "tenant-1", "attestation-1",
		testfixture.AttestationBody()).SignAttestation(keys)
	if err != nil {
		t.Fatalf("sign attestation: %v", err)
	}
	gapWire, err := testfixture.NewEnvelope("CoverageGap",
		"01890f47-2f58-7cc0-98c4-000000000201", "tenant-1", "gaps-1",
		map[string]any{
			"gap_start": "2026-08-05T00:00:00Z", "gap_end": "2026-08-06T00:00:00Z",
			"affected_scope": map[string]any{}, "cause": "collector_unreachable",
			"detection_source": "collector", "exposure": "known",
			"actions_during_gap": nil,
		}).Sign(testfixture.EvidenceKeyID, keys.Evidence)
	if err != nil {
		t.Fatalf("sign gap: %v", err)
	}
	qualWire, err := testfixture.NewEnvelope("QualificationRecord",
		"01890f47-2f58-7cc0-98c4-000000000101", "tenant-1", "qualifications-1",
		testfixture.QualificationBody("C1", "2026-01-01T00:00:00Z"),
	).Sign(testfixture.EvidenceKeyID, keys.Evidence)
	if err != nil {
		t.Fatalf("sign qualification: %v", err)
	}

	container, err := testfixture.Bundle(attWire, gapWire, qualWire)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}

	parsed, err := bundle.Parse(container)
	if err != nil {
		t.Fatalf("internal/bundle refused the container: %v", err)
	}
	viaBundle := toCoverageBundle(parsed)

	viaCoverage, err := coverage.ParseBundle(container)
	if err != nil {
		t.Fatalf("coverage.ParseBundle refused the same bytes: %v", err)
	}

	if viaBundle.Window.RecordID() != viaCoverage.Window.RecordID() {
		t.Fatalf("attestation differs: %s vs %s",
			viaBundle.Window.RecordID(), viaCoverage.Window.RecordID())
	}
	if len(viaBundle.Gaps) != len(viaCoverage.Gaps) {
		t.Fatalf("gap counts differ: %d vs %d",
			len(viaBundle.Gaps), len(viaCoverage.Gaps))
	}
	if len(viaBundle.Populations) != len(viaCoverage.Populations) {
		t.Fatalf("population counts differ: %d vs %d",
			len(viaBundle.Populations), len(viaCoverage.Populations))
	}
	if len(viaBundle.Other) != len(viaCoverage.Other) {
		t.Fatalf("other counts differ: %d vs %d",
			len(viaBundle.Other), len(viaCoverage.Other))
	}

	fromBundle, err := coverage.Recompute(viaBundle)
	if err != nil {
		t.Fatalf("recompute via bundle: %v", err)
	}
	fromCoverage, err := coverage.Recompute(viaCoverage)
	if err != nil {
		t.Fatalf("recompute via coverage: %v", err)
	}
	if len(fromBundle.Findings) != len(fromCoverage.Findings) ||
		len(fromBundle.Unresolved) != len(fromCoverage.Unresolved) {
		t.Fatalf("the two parses reach different conclusions:\n"+
			"  bundle    %d findings, %d unresolved\n"+
			"  coverage  %d findings, %d unresolved",
			len(fromBundle.Findings), len(fromBundle.Unresolved),
			len(fromCoverage.Findings), len(fromCoverage.Unresolved))
	}
}

// TestC4CountConservationCannotMakeAClaimValid guards the independently
// enumerable boundary: a signed count at C4 is still not an independently
// established denominator.
func TestC4CountConservationCannotMakeAClaimValid(t *testing.T) {
	b, keys := buildComplete(t, map[string]any{
		"denominator_class": "C4",
		"coverage_level":    "unknown",
		"capped_by_class":   false,
		"coverage_ratio":    nil,
		"counts":            testfixture.CountsBody(3, 1, 1, 0, 0, 1),
	}, 6)
	res := verify(t, b, keys)
	if res.Verdict != bundle.Indeterminate {
		t.Fatalf("verdict = %s, want indeterminate\n  findings   %v\n  unresolved %v",
			res.Verdict, res.Findings, res.Unresolved)
	}
	if len(res.Unresolved) == 0 {
		t.Fatal("C4 count conservation was silently treated as independently established")
	}
}

// TestCountsMustAccountForThePopulationExactly is what the §5.13 correction
// bought. While out_of_scope had nowhere to be reported, a conformant
// attestation could sum to less than its population and the check could only
// ever be an inequality. With all six buckets enumerated the enumeration is
// closed and admits no residual, so a shortfall is actions in the population
// the attestation classified as nothing at all.
func TestCountsMustAccountForThePopulationExactly(t *testing.T) {
	b, keys := buildComplete(t, map[string]any{
		"denominator_class": "C4",
		"coverage_level":    "unknown",
		"capped_by_class":   false,
		"coverage_ratio":    nil,
		"counts":            testfixture.CountsBody(3, 1, 1, 0, 0, 0),
	}, 6)
	res := verify(t, b, keys)
	if res.Verdict != bundle.Invalid {
		t.Fatalf("verdict = %s; five of six actions accounted for is a "+
			"silent shortfall, not a pass", res.Verdict)
	}
}

// TestAtTheCeilingCappedByClassIsUnresolvable pins the honest limit of ES-018's
// one-directional check.
func TestAtTheCeilingCappedByClassIsUnresolvable(t *testing.T) {
	b, keys := buildComplete(t, map[string]any{
		"denominator_class": "C4",
		"coverage_level":    "observed", // exactly the C4 ceiling
		"capped_by_class":   false,
		"coverage_ratio":    nil,
		"counts":            testfixture.CountsBody(3, 1, 1, 0, 0, 1),
	}, 6)
	res := verify(t, b, keys)
	if res.Verdict == bundle.Valid {
		t.Fatal("a claim at the class ceiling verified as valid, but whether " +
			"the cap bound is not derivable from the bundle")
	}
	var found bool
	for _, u := range res.Unresolved {
		if strings.Contains(u, "capped_by_class") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the ceiling case was not reported as unresolved: %v", res.Unresolved)
	}
}

// TestCappedByClassStrictComparison is ES-018's strict inequality: below the
// ceiling the cap did not bind, whatever the record asserts.
func TestCappedByClassStrictComparison(t *testing.T) {
	b, keys := buildComplete(t, map[string]any{
		"denominator_class": "C4",
		"coverage_level":    "unknown",
		"capped_by_class":   true, // a stronger class would change nothing
		"coverage_ratio":    nil,
		"counts":            testfixture.CountsBody(3, 1, 1, 0, 0, 1),
	}, 6)
	res := verify(t, b, keys)
	if res.Verdict != bundle.Invalid {
		t.Fatalf("verdict = %s; capped_by_class is true only where the class "+
			"is strictly below what the evidence supports", res.Verdict)
	}
}

// buildComplete assembles a bundle carrying everything a full recomputation
// needs: attestation, boundary, qualification and an enumerated population.
func buildComplete(
	t *testing.T, overrides map[string]any, population int64,
) (*bundle.Bundle, testfixture.Keys) {
	t.Helper()
	keys, err := testfixture.NewKeys()
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	const (
		qualID = "01890f47-2f58-7cc0-98c4-000000000101"
		popID  = "01890f47-2f58-7cc0-98c4-000000000401"
	)
	body := testfixture.AttestationBody()
	for k, v := range overrides {
		body[k] = v
	}
	body["population_record_refs"] = []any{popID}
	class, _ := body["denominator_class"].(string)

	attWire, err := testfixture.NewEnvelope("AttestationWindow",
		"01890f47-2f58-7cc0-98c4-000000000064", "tenant-1", "attestation-1",
		body).SignAttestation(keys)
	if err != nil {
		t.Fatalf("sign attestation: %v", err)
	}
	qualWire, err := testfixture.NewEnvelope("QualificationRecord", qualID,
		"tenant-1", "qualifications-1",
		testfixture.QualificationBody(class, "2026-01-01T00:00:00Z"),
	).Sign(testfixture.EvidenceKeyID, keys.Evidence)
	if err != nil {
		t.Fatalf("sign qualification: %v", err)
	}
	boundaryWire, err := testfixture.NewEnvelope("AssuranceBoundary",
		"01890f47-2f58-7cc0-98c4-000000000201", "tenant-1", "boundary-stream-1",
		testfixture.BoundaryBody(qualID),
	).Sign(testfixture.EvidenceKeyID, keys.Evidence)
	if err != nil {
		t.Fatalf("sign boundary: %v", err)
	}
	popWire, err := testfixture.NewEnvelope("PopulationRecord", popID,
		"tenant-1", "populations-1", testfixture.PopulationBody(population),
	).Sign(testfixture.IssuerKeyID, keys.Issuer)
	if err != nil {
		t.Fatalf("sign population: %v", err)
	}

	container, err := testfixture.Bundle(attWire, boundaryWire, qualWire, popWire)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	parsed, err := bundle.Parse(container)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return parsed, keys
}

// TestValidIsReachableWithANumericRatio closes the last of the three gaps.
//
// The earlier TestValidIsReachable had to use C4, where ES-017 makes a null
// ratio mandatory and there is therefore nothing to recompute. A ratio-eligible
// class with an actual number is the case that was blocked: until ES-017 stated
// the formula, no verifier could reproduce the value, so any bundle carrying
// one reported indeterminate however correct it was.
//
// 2 matched over an in-scope denominator of 3 — population 4 less one
// out-of-scope — is 0.6666, truncated rather than rounded.
func TestValidIsReachableWithANumericRatio(t *testing.T) {
	b, keys := buildComplete(t, map[string]any{
		"denominator_class": "C1",
		"coverage_level":    "observed", // below C1's reconciled ceiling
		"capped_by_class":   false,
		"coverage_ratio":    "0.6666",
		"counts":            testfixture.CountsBody(2, 1, 0, 0, 0, 1),
	}, 4)
	res := verify(t, b, keys)
	if res.Verdict != bundle.Valid {
		t.Fatalf("verdict = %s, want valid\n  findings   %v\n  unresolved %v",
			res.Verdict, res.Findings, res.Unresolved)
	}
	if len(res.Unresolved) != 0 {
		t.Fatalf("valid was reached with unresolved items: %v", res.Unresolved)
	}
}

// TestOverstatedRatioIsRefused is the overclaim direction, which is the whole
// reason the formula had to be stated. The bundle below is internally
// consistent and correctly signed; only the number is wrong.
func TestOverstatedRatioIsRefused(t *testing.T) {
	b, keys := buildComplete(t, map[string]any{
		"denominator_class": "C1",
		"coverage_level":    "observed",
		"capped_by_class":   false,
		"coverage_ratio":    "1.0000", // 2 of 3 in-scope actions were matched
		"counts":            testfixture.CountsBody(2, 1, 0, 0, 0, 1),
	}, 4)
	res := verify(t, b, keys)
	if res.Verdict != bundle.Invalid {
		t.Fatalf("verdict = %s; a claimed 1.0000 over 2 matched of 3 must refuse",
			res.Verdict)
	}
}

// TestRatioRoundedUpIsRefused: 0.6667 is what half-up rounding produces, and
// it reports more coverage than was measured.
func TestRatioRoundedUpIsRefused(t *testing.T) {
	b, keys := buildComplete(t, map[string]any{
		"denominator_class": "C1",
		"coverage_level":    "observed",
		"capped_by_class":   false,
		"coverage_ratio":    "0.6667",
		"counts":            testfixture.CountsBody(2, 1, 0, 0, 0, 1),
	}, 4)
	res := verify(t, b, keys)
	if res.Verdict != bundle.Invalid {
		t.Fatalf("verdict = %s; ES-017 truncates toward zero", res.Verdict)
	}
}

// TestUnmatchedWithEvidenceIsNotPartialCredit: CM-011's no-imputation rule
// applies to the ratio exactly as it does elsewhere. Counting
// unmatched_with_evidence toward the numerator would give 3/3 here.
func TestUnmatchedWithEvidenceIsNotPartialCredit(t *testing.T) {
	b, keys := buildComplete(t, map[string]any{
		"denominator_class": "C1",
		"coverage_level":    "observed",
		"capped_by_class":   false,
		"coverage_ratio":    "1.0000",
		"counts":            testfixture.CountsBody(2, 1, 0, 0, 0, 1),
	}, 4)
	res := verify(t, b, keys)
	if res.Verdict != bundle.Invalid {
		t.Fatalf("verdict = %s; unmatched_with_evidence is evidence of a gap, "+
			"not partial coverage (CM-011)", res.Verdict)
	}
}
