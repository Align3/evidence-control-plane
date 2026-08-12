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
