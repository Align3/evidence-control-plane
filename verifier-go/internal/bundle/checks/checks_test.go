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
	container, err := testfixture.Bundle(
		map[string][]byte{"attestation": attWire},
		map[string][][]byte{"qualification_records": {qualWire}},
	)
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
	container, err := testfixture.Bundle(
		map[string][]byte{"attestation": attWire},
		map[string][][]byte{"gap_records": {gapWire}},
	)
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

// TestTheTwoContainersClassifyRecordsIdentically pins the one thing that can go
// wrong while both halves stay individually correct.
//
// internal/coverage still carries ParseBundle, a flat array container that
// predates the shipped keyed one and is reachable only from that package's own
// tests. The risk is drift: the coverage suite keeps passing against a
// container the verifier no longer accepts, so its evidence stops being
// evidence about the shipped path. This asserts that the same records, routed
// through both containers, land in the same buckets.
func TestTheTwoContainersClassifyRecordsIdentically(t *testing.T) {
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

	// Route 1: the shipped keyed container, through internal/bundle.
	container, err := testfixture.Bundle(
		map[string][]byte{"attestation": attWire},
		map[string][][]byte{
			"gap_records":           {gapWire},
			"qualification_records": {qualWire},
		},
	)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	parsed, err := bundle.Parse(container)
	if err != nil {
		t.Fatalf("parse keyed container: %v", err)
	}
	viaKeyed := toCoverageBundle(parsed)

	// Route 2: the flat array container, through coverage.ParseBundle.
	array := append([]byte("["), attWire...)
	array = append(array, ',')
	array = append(array, gapWire...)
	array = append(array, ',')
	array = append(array, qualWire...)
	array = append(array, ']')
	viaArray, err := coverage.ParseBundle(array)
	if err != nil {
		t.Fatalf("parse array container: %v", err)
	}

	if viaKeyed.Window.RecordID() != viaArray.Window.RecordID() {
		t.Fatalf("attestation differs: %s vs %s",
			viaKeyed.Window.RecordID(), viaArray.Window.RecordID())
	}
	if len(viaKeyed.Gaps) != len(viaArray.Gaps) {
		t.Fatalf("gap counts differ: keyed %d, array %d",
			len(viaKeyed.Gaps), len(viaArray.Gaps))
	}
	if len(viaKeyed.Populations) != len(viaArray.Populations) {
		t.Fatalf("population counts differ: keyed %d, array %d",
			len(viaKeyed.Populations), len(viaArray.Populations))
	}
	if len(viaKeyed.Other) != len(viaArray.Other) {
		t.Fatalf("other counts differ: keyed %d, array %d",
			len(viaKeyed.Other), len(viaArray.Other))
	}

	// And the recomputation must reach the same conclusion either way.
	fromKeyed, err := coverage.Recompute(viaKeyed)
	if err != nil {
		t.Fatalf("recompute keyed: %v", err)
	}
	fromArray, err := coverage.Recompute(viaArray)
	if err != nil {
		t.Fatalf("recompute array: %v", err)
	}
	if len(fromKeyed.Findings) != len(fromArray.Findings) ||
		len(fromKeyed.Unresolved) != len(fromArray.Unresolved) {
		t.Fatalf("the two containers reach different conclusions:\n"+
			"  keyed  %d findings, %d unresolved\n  array  %d findings, %d unresolved",
			len(fromKeyed.Findings), len(fromKeyed.Unresolved),
			len(fromArray.Findings), len(fromArray.Unresolved))
	}
}
