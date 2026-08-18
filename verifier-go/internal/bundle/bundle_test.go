package bundle

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Align3/evidence-control-plane/verifier-go/internal/revocation"
	"github.com/Align3/evidence-control-plane/verifier-go/internal/testfixture"
)

const (
	attestationID = "01890f47-2f58-7cc0-98c4-000000000064"
	tenant        = "tenant-1"
)

// during is a clock inside the fixture validity period
// (2026-09-01 .. 2026-12-01).
func during() time.Time { return time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC) }

type builder struct {
	t             *testing.T
	keys          testfixture.Keys
	attestation   map[string]any
	envelope      testfixture.Envelope
	qualification []map[string]any
	qualSigner    string
	qualTenant    string
	withBoundary  bool
	// declareQualifications puts the qualification record ids into the
	// boundary's qualification_refs (ES-009). Turning it off models a
	// qualification the boundary never declared.
	declareQualifications bool
	// secondQualification mutates the second qualification envelope, so a test
	// can place it at another sequence or point it at another predecessor.
	secondQualification func(testfixture.Envelope)
}

func newBuilder(t *testing.T) *builder {
	t.Helper()
	k, err := testfixture.NewKeys()
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	body := testfixture.AttestationBody()
	return &builder{
		t:           t,
		keys:        k,
		attestation: body,
		envelope: testfixture.NewEnvelope("AttestationWindow", attestationID,
			tenant, "attestation-1", body),
		// The default qualification entitles C1 from before the window starts:
		// the shape a bundle has to have before any of the negatives below
		// mean anything.
		qualification: []map[string]any{
			testfixture.QualificationBody("C1", "2026-07-01T00:00:00Z"),
		},
		qualSigner: "evidence",
		qualTenant: tenant,
		// A bundle that does not carry its boundary has an unchecked scope, so
		// the default fixture carries one: otherwise no test could reach a
		// verdict of Valid and the positive path would go undemonstrated.
		withBoundary:          true,
		declareQualifications: true,
	}
}

// qualificationID is the record id of the i-th qualification record, which the
// boundary must declare under ES-009.
func qualificationID(i int) string {
	return "01890f47-2f58-7cc0-98c4-00000000010" + string(rune('0'+i))
}

// build assembles and returns the canonical ES-034 bundle bytes.
func (b *builder) build() []byte {
	b.t.Helper()
	b.envelope["body"] = b.attestation
	attWire, err := b.envelope.SignAttestation(b.keys)
	if err != nil {
		b.t.Fatalf("sign attestation: %v", err)
	}
	records := [][]byte{attWire}
	refs := make([]string, 0, len(b.qualification))
	for i, qb := range b.qualification {
		refs = append(refs, qualificationID(i))
		env := testfixture.NewEnvelope("QualificationRecord",
			qualificationID(i), b.qualTenant, "qualifications-1", qb)
		if i == 1 && b.secondQualification != nil {
			b.secondQualification(env)
		}
		var wire []byte
		if b.qualSigner == "issuer" {
			wire, err = env.Sign(testfixture.IssuerKeyID, b.keys.Issuer)
		} else {
			wire, err = env.Sign(testfixture.EvidenceKeyID, b.keys.Evidence)
		}
		if err != nil {
			b.t.Fatalf("sign qualification: %v", err)
		}
		records = append(records, wire)
	}
	if b.withBoundary {
		declared := refs
		if !b.declareQualifications {
			declared = nil
		}
		boundaryEnv := testfixture.NewEnvelope("AssuranceBoundary",
			"01890f47-2f58-7cc0-98c4-000000000201", tenant, "boundary-stream-1",
			testfixture.BoundaryBody(declared...))
		boundaryWire, err := boundaryEnv.Sign(testfixture.EvidenceKeyID, b.keys.Evidence)
		if err != nil {
			b.t.Fatalf("sign boundary: %v", err)
		}
		records = append(records, boundaryWire)
	}
	out, err := testfixture.Bundle(records...)
	if err != nil {
		b.t.Fatalf("assemble bundle: %v", err)
	}
	return out
}

// verify parses and verifies with the given options, failing the test if the
// bundle does not even parse.
func (b *builder) verify(opts Options) Result {
	b.t.Helper()
	parsed, err := Parse(b.build())
	if err != nil {
		b.t.Fatalf("parse bundle: %v", err)
	}
	if opts.Keys == nil {
		opts.Keys = b.keys.Keyring
	}
	if opts.Now == nil {
		opts.Now = during
	}
	return Verify(context.Background(), parsed, opts)
}

func hasCode(res Result, code string) bool {
	for _, f := range res.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

func codes(res Result) []string {
	out := make([]string, 0, len(res.Findings))
	for _, f := range res.Findings {
		out = append(out, f.Code)
	}
	return out
}

// ---------------------------------------------------------------------------
// The bundle container itself.
// ---------------------------------------------------------------------------

func TestNonCanonicalBundleIsRefused(t *testing.T) {
	b := newBuilder(t)
	canonical := b.build()
	pretty := new(bytes.Buffer)
	if err := json.Indent(pretty, canonical, "", "  "); err != nil {
		t.Fatalf("indent: %v", err)
	}
	if _, err := Parse(pretty.Bytes()); err == nil {
		t.Fatal("a pretty-printed bundle parsed; the records inside it cannot " +
			"then be checked against the bytes that were signed")
	} else if !strings.Contains(err.Error(), CodeBundleNonCanonical) {
		t.Fatalf("error = %v, want %s", err, CodeBundleNonCanonical)
	}
}

// TestKeyedContainerIsRefused: ES-034 is an array. A keyed object is the shape
// this verifier used to accept, and accepting both would reintroduce the
// role-stated-separately-from-the-record failure that disqualified it.
func TestKeyedContainerIsRefused(t *testing.T) {
	raw := []byte(`{"attestation":{},"coverage_summary":{"ratio":1}}`)
	if _, err := Parse(raw); err == nil {
		t.Fatal("a keyed container parsed; ES-034 defines an array")
	}
}

func TestBundleWithoutAttestationIsRefused(t *testing.T) {
	if _, err := Parse([]byte(`[]`)); err == nil {
		t.Fatal("an empty bundle parsed")
	}
}

// TestTwoAttestationsRefused: a bundle carrying two conclusions has no single
// status to report, and choosing one would make the verdict depend on
// container order.
func TestTwoAttestationsRefused(t *testing.T) {
	b := newBuilder(t)
	b.envelope["body"] = b.attestation
	wire, err := b.envelope.SignAttestation(b.keys)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	container, err := testfixture.Bundle(wire, wire)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if _, err := Parse(container); err == nil {
		t.Fatal("a bundle with two AttestationWindows parsed")
	}
}

// TestRecordsCannotBeMisfiled is the property the array container exists for.
// Under the keyed container a signed CoverageGap placed in population_records
// reached the coverage engine as a population, vanishing from the gap set
// CM-014 conservation is checked against — a gap-hiding path built entirely
// out of validly signed records. Routing from the record's own record_type
// makes that unexpressible, and this pins it.
func TestRecordsCannotBeMisfiled(t *testing.T) {
	b := newBuilder(t)
	b.envelope["body"] = b.attestation
	attWire, err := b.envelope.SignAttestation(b.keys)
	if err != nil {
		t.Fatalf("sign attestation: %v", err)
	}
	gapWire, err := testfixture.NewEnvelope("CoverageGap",
		"01890f47-2f58-7cc0-98c4-000000000301", tenant, "gaps-1",
		map[string]any{
			"gap_start": "2026-08-05T00:00:00Z", "gap_end": "2026-08-06T00:00:00Z",
			"affected_scope": map[string]any{}, "cause": "collector_unreachable",
			"detection_source": "collector", "exposure": "known",
			"actions_during_gap": nil,
		}).Sign(testfixture.EvidenceKeyID, b.keys.Evidence)
	if err != nil {
		t.Fatalf("sign gap: %v", err)
	}
	container, err := testfixture.Bundle(attWire, gapWire)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	parsed, err := Parse(container)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(parsed.Gaps) != 1 {
		t.Fatalf("the gap was not routed to Gaps: %d", len(parsed.Gaps))
	}
	if len(parsed.Populations) != 0 {
		t.Fatalf("a CoverageGap reached the population bucket: %d",
			len(parsed.Populations))
	}
}

// ---------------------------------------------------------------------------
// Signatures — the composition path, not the primitive.
// ---------------------------------------------------------------------------

// TestAttestationWithoutIssuerCounterSignature is the adversarial shape
// testing-qa §10 names: a stricter primitive exists, and the question is
// whether a new entry point can be made to bypass it.
func TestAttestationWithoutIssuerCounterSignature(t *testing.T) {
	b := newBuilder(t)
	b.envelope["body"] = b.attestation
	wire, err := b.envelope.Sign(testfixture.EvidenceKeyID, b.keys.Evidence)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	container, err := testfixture.Bundle(wire)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	parsed, err := Parse(container)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	res := Verify(context.Background(), parsed, Options{Keys: b.keys.Keyring, Now: during})
	if res.Verdict != Invalid {
		t.Fatalf("verdict = %s; an attestation with no ES-023 counter-signature "+
			"must not verify", res.Verdict)
	}
	if !hasCode(res, CodeSignatureInvalid) {
		t.Fatalf("codes = %v, want %s", codes(res), CodeSignatureInvalid)
	}
}

func TestTamperedAttestationIsRefused(t *testing.T) {
	b := newBuilder(t)
	wire := b.build()
	// Flip the claimed class after signing.
	tampered := strings.Replace(string(wire), `"denominator_class":"C1"`,
		`"denominator_class":"C2"`, 1)
	if tampered == string(wire) {
		t.Fatal("fixture shape changed; the tamper did not apply")
	}
	parsed, err := Parse([]byte(tampered))
	if err != nil {
		// Refusing at parse is also a refusal, and an acceptable one.
		return
	}
	res := Verify(context.Background(), parsed, Options{Keys: b.keys.Keyring, Now: during})
	if res.Verdict != Invalid {
		t.Fatalf("verdict = %s; a tampered attestation must not verify", res.Verdict)
	}
}

// TestQualificationSignedByIssuerKeyIsRefused: ES-033 puts QualificationRecord
// in the customer-declaration category. An issuer-signed one would mean we
// qualified the customer ourselves and then attested to it.
func TestQualificationSignedByIssuerKeyIsRefused(t *testing.T) {
	b := newBuilder(t)
	b.qualSigner = "issuer"
	res := b.verify(Options{})
	if res.Verdict != Invalid {
		t.Fatalf("verdict = %s, want invalid", res.Verdict)
	}
	if !hasCode(res, CodeSignatureInvalid) {
		t.Fatalf("codes = %v, want %s", codes(res), CodeSignatureInvalid)
	}
}

// TestQualificationFromAnotherTenantIsRefused: one tenant's qualification must
// not entitle another tenant's claim.
func TestQualificationFromAnotherTenantIsRefused(t *testing.T) {
	b := newBuilder(t)
	b.qualTenant = "tenant-2"
	res := b.verify(Options{})
	if res.Verdict != Invalid {
		t.Fatalf("verdict = %s, want invalid", res.Verdict)
	}
	if !hasCode(res, CodeTenantMismatch) {
		t.Fatalf("codes = %v, want %s", codes(res), CodeTenantMismatch)
	}
}

// ---------------------------------------------------------------------------
// TM-013 / TM-S-005 — qualification dates.
// ---------------------------------------------------------------------------

// TestTMS005QualificationPostdatesWindow is the acceptance scenario, at the
// dates the scenario states: a C1 qualification dated 2026-09-01 and a window
// starting 2026-08-01.
func TestTMS005QualificationPostdatesWindow(t *testing.T) {
	b := newBuilder(t)
	b.attestation["window_start"] = "2026-08-01T00:00:00Z"
	b.attestation["denominator_class"] = "C1"
	b.qualification = []map[string]any{
		testfixture.QualificationBody("C1", "2026-09-01T00:00:00Z"),
	}
	res := b.verify(Options{})

	if res.Verdict != Invalid {
		t.Fatalf("verdict = %s; TM-S-005 requires verification to fail", res.Verdict)
	}
	if !hasCode(res, CodeQualificationPostdates) {
		t.Fatalf("codes = %v, want %s", codes(res), CodeQualificationPostdates)
	}
	// The scenario pins the wording, not only the outcome.
	var found bool
	for _, f := range res.Findings {
		if strings.Contains(f.Message, "qualification postdates window") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no finding said \"qualification postdates window\": %v", res.Findings)
	}
}

// TestQualificationExactlyAtWindowStartIsAccepted pins the boundary of the
// comparison. CM-004 permits a class for windows beginning *after* the
// qualification date, so equality is admissible and only a strictly later
// qualification is not.
func TestQualificationExactlyAtWindowStartIsAccepted(t *testing.T) {
	b := newBuilder(t)
	b.attestation["window_start"] = "2026-08-01T00:00:00Z"
	b.qualification = []map[string]any{
		testfixture.QualificationBody("C1", "2026-08-01T00:00:00Z"),
	}
	res := b.verify(Options{})
	if hasCode(res, CodeQualificationPostdates) {
		t.Fatalf("a qualification dated exactly at window_start was refused: %v",
			res.Findings)
	}
}

// TestOneSecondAfterWindowStartIsRefused is the other side of that boundary.
func TestOneSecondAfterWindowStartIsRefused(t *testing.T) {
	b := newBuilder(t)
	b.attestation["window_start"] = "2026-08-01T00:00:00Z"
	b.qualification = []map[string]any{
		testfixture.QualificationBody("C1", "2026-08-01T00:00:01Z"),
	}
	res := b.verify(Options{})
	if !hasCode(res, CodeQualificationPostdates) {
		t.Fatalf("codes = %v, want %s", codes(res), CodeQualificationPostdates)
	}
}

func TestNoQualificationRecordIsRefused(t *testing.T) {
	b := newBuilder(t)
	b.qualification = nil
	res := b.verify(Options{})
	if res.Verdict != Invalid {
		t.Fatalf("verdict = %s; a class nobody can check is not a class this "+
			"verifier accepts", res.Verdict)
	}
	if !hasCode(res, CodeQualificationMissing) {
		t.Fatalf("codes = %v, want %s", codes(res), CodeQualificationMissing)
	}
}

// TestQualificationForAnotherClassDoesNotEntitle: a C4 qualification is not
// evidence about a C1 claim, and this check must not quietly treat "some
// qualification exists" as entitlement.
func TestQualificationForAnotherClassDoesNotEntitle(t *testing.T) {
	b := newBuilder(t)
	b.attestation["denominator_class"] = "C1"
	b.qualification = []map[string]any{
		testfixture.QualificationBody("C4", "2026-01-01T00:00:00Z"),
	}
	res := b.verify(Options{})
	if !hasCode(res, CodeQualificationMissing) {
		t.Fatalf("codes = %v, want %s", codes(res), CodeQualificationMissing)
	}
}

// TestRetroactiveUpgradeWithBothRecords is CM-S-009's actual shape: the
// customer legitimately holds C1 now, and re-attests an older window with it.
// Both qualification records are present and both are validly signed.
func TestRetroactiveUpgradeWithBothRecords(t *testing.T) {
	b := newBuilder(t)
	b.attestation["window_start"] = "2026-08-01T00:00:00Z"
	b.attestation["denominator_class"] = "C1"
	b.qualification = []map[string]any{
		testfixture.QualificationBody("C4", "2026-01-01T00:00:00Z"),
		testfixture.QualificationBody("C1", "2026-09-01T00:00:00Z"),
	}
	res := b.verify(Options{})
	if res.Verdict != Invalid {
		t.Fatalf("verdict = %s; the C1 qualification postdates the window", res.Verdict)
	}
	if !hasCode(res, CodeQualificationPostdates) {
		t.Fatalf("codes = %v, want %s", codes(res), CodeQualificationPostdates)
	}
}

// TestSameWindowAtTheClassItActuallyHeld is the positive half of CM-S-009: the
// identical window, attested at the class that was qualified in time, verifies.
func TestSameWindowAtTheClassItActuallyHeld(t *testing.T) {
	b := newBuilder(t)
	b.attestation["window_start"] = "2026-08-01T00:00:00Z"
	b.attestation["denominator_class"] = "C4"
	b.qualification = []map[string]any{
		testfixture.QualificationBody("C4", "2026-01-01T00:00:00Z"),
		testfixture.QualificationBody("C1", "2026-09-01T00:00:00Z"),
	}
	res := b.verify(Options{})
	if hasCode(res, CodeQualificationPostdates) || hasCode(res, CodeQualificationMissing) {
		t.Fatalf("the class the customer actually held was refused: %v", res.Findings)
	}
}

func TestUnparseableQualificationDateIsRefused(t *testing.T) {
	b := newBuilder(t)
	b.qualification = []map[string]any{
		testfixture.QualificationBody("C1", "sometime in July"),
	}
	res := b.verify(Options{})
	if !hasCode(res, CodeQualificationUnparsed) {
		t.Fatalf("codes = %v, want %s", codes(res), CodeQualificationUnparsed)
	}
	if res.Verdict != Invalid {
		t.Fatalf("verdict = %s; an uncheckable date is not a satisfied check", res.Verdict)
	}
}

// ---------------------------------------------------------------------------
// Versions.
// ---------------------------------------------------------------------------

func TestVersionRefusals(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*builder)
		wantErr string
	}{
		{
			name:    "unknown schema version",
			mutate:  func(b *builder) { b.envelope["schema_version"] = "9.9.9" },
			wantErr: CodeSchemaUnsupported,
		},
		{
			name:    "published but unimplemented schema version",
			mutate:  func(b *builder) { b.envelope["schema_version"] = "2.0.0" },
			wantErr: CodeSchemaUnsupported,
		},
		{
			name: "unknown methodology version",
			mutate: func(b *builder) {
				b.attestation["methodology_version"] = "2.0.0"
			},
			wantErr: CodeMethodologyUnknown,
		},
		{
			name: "empty methodology version",
			mutate: func(b *builder) {
				b.attestation["methodology_version"] = ""
			},
			wantErr: CodeMethodologyUnknown,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := newBuilder(t)
			tc.mutate(b)
			res := b.verify(Options{})
			if res.Verdict != Invalid {
				t.Fatalf("verdict = %s, want invalid", res.Verdict)
			}
			if !hasCode(res, tc.wantErr) {
				t.Fatalf("codes = %v, want %s", codes(res), tc.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// AR-009 / AR-S-004 — validity period.
// ---------------------------------------------------------------------------

// TestARS004ExpiredVerifiesAsExpired is the acceptance scenario. The two
// assertions are separate on purpose: "the result is expired" and "the result
// is not valid" are different claims, and a verifier that reported
// valid-with-a-warning would satisfy neither.
func TestARS004ExpiredVerifiesAsExpired(t *testing.T) {
	b := newBuilder(t)
	after := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	res := b.verify(Options{Now: func() time.Time { return after }})

	if res.Verdict != Expired {
		t.Fatalf("verdict = %s, want expired (findings: %v)", res.Verdict, res.Findings)
	}
	if res.Verdict == Valid {
		t.Fatal("an expired attestation reported valid")
	}
	if res.Verdict.String() != "expired" {
		t.Fatalf("verdict renders as %q", res.Verdict.String())
	}
}

// TestExpiryIsReportedEvenWithNoRevocationEndpoint guards the ordering inside
// decide. AR-S-004 runs offline, so if unchecked revocation outranked expiry
// the scenario would report "unchecked_revocation" and AR-009 would go
// unenforced.
func TestExpiryIsReportedEvenWithNoRevocationEndpoint(t *testing.T) {
	b := newBuilder(t)
	after := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	res := b.verify(Options{
		Now:        func() time.Time { return after },
		Revocation: revocation.Checker{Offline: true},
	})
	if res.Verdict != Expired {
		t.Fatalf("verdict = %s, want expired", res.Verdict)
	}
	if res.Revocation.Status() != revocation.Unchecked {
		t.Fatalf("revocation = %s", res.Revocation.Status())
	}
}

func TestNotYetValid(t *testing.T) {
	b := newBuilder(t)
	before := time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)
	res := b.verify(Options{Now: func() time.Time { return before }})
	if res.Verdict != NotYetValid {
		t.Fatalf("verdict = %s, want not_yet_valid", res.Verdict)
	}
}

func TestInvertedValidityPeriodIsRefused(t *testing.T) {
	b := newBuilder(t)
	b.attestation["validity_from"] = "2026-12-01T00:00:00Z"
	b.attestation["validity_until"] = "2026-09-01T00:00:00Z"
	res := b.verify(Options{})
	if res.Verdict != Invalid {
		t.Fatalf("verdict = %s, want invalid", res.Verdict)
	}
	if !hasCode(res, CodeValidityUnparseable) {
		t.Fatalf("codes = %v", codes(res))
	}
}

func TestUnparseableValidityIsRefusedNotIgnored(t *testing.T) {
	b := newBuilder(t)
	b.attestation["validity_until"] = "whenever"
	res := b.verify(Options{})
	if res.Verdict != Invalid {
		t.Fatalf("verdict = %s; an unenforceable validity period is not an "+
			"unbounded one", res.Verdict)
	}
}

// ---------------------------------------------------------------------------
// TM-014 / TM-S-004 — revocation, through the bundle.
// ---------------------------------------------------------------------------

// TestTMS004OfflineReportsUncheckedRevocation is the acceptance scenario:
// signatures verify, revocation is unchecked, and the verdict is not valid.
func TestTMS004OfflineReportsUncheckedRevocation(t *testing.T) {
	b := newBuilder(t)
	res := b.verify(Options{Revocation: revocation.Checker{Offline: true}})

	if len(res.Findings) != 0 {
		t.Fatalf("signature and structural verification did not succeed: %v", res.Findings)
	}
	if res.EvidenceKeyID == "" || res.IssuerKeyID == "" {
		t.Fatalf("both ES-023 signatures should be reported, got %q/%q",
			res.EvidenceKeyID, res.IssuerKeyID)
	}
	if res.Revocation.Status() != revocation.Unchecked {
		t.Fatalf("revocation_status = %s, want unchecked", res.Revocation.Status())
	}
	if res.Verdict == Valid {
		t.Fatal("an offline verifier reported the attestation valid")
	}
	if res.Verdict != UncheckedRevocation {
		t.Fatalf("verdict = %s, want unchecked_revocation", res.Verdict)
	}
}

// TestNoRevocationCheckerConfiguredIsNotValid: the zero-valued Options must
// behave the same way as an explicit offline run. This is the mistake the
// package is shaped to make impossible — a caller who forgets to configure
// revocation must not thereby get a stronger verdict.
func TestNoRevocationCheckerConfiguredIsNotValid(t *testing.T) {
	b := newBuilder(t)
	res := b.verify(Options{})
	if res.Verdict == Valid {
		t.Fatal("a verifier with no revocation checker configured reported valid")
	}
	if res.Verdict != UncheckedRevocation {
		t.Fatalf("verdict = %s, want unchecked_revocation", res.Verdict)
	}
}

type stubFetcher struct {
	status int
	body   []byte
	err    error
}

func (s stubFetcher) Fetch(context.Context, string) (int, []byte, error) {
	return s.status, s.body, s.err
}

func TestValidRequiresAnAffirmativeRevocationAnswer(t *testing.T) {
	b := newBuilder(t)
	res := b.verify(Options{
		Revocation: revocation.Checker{
			Fetcher:    stubFetcher{status: 404},
			IssuerKeys: b.keys.Keyring,
		},
	})
	if res.Verdict != Valid {
		t.Fatalf("verdict = %s, want valid (findings %v, revocation %s/%s)",
			res.Verdict, res.Findings, res.Revocation.Status(), res.Revocation.Reason())
	}
}

func TestRevokedAndSupersededPropagateToTheVerdict(t *testing.T) {
	for _, tc := range []struct {
		name           string
		supersedingRef string
		want           Verdict
	}{
		{"revoked", "", Revoked},
		{"superseded", "attestation-2", Superseded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newBuilder(t)
			env := testfixture.NewEnvelope("RevocationRecord",
				"01890f47-2f58-7cc0-98c4-0000000000aa", tenant, "revocations-1",
				testfixture.RevocationBody(attestationID, "defect",
					"2026-09-15T00:00:00Z", tc.supersedingRef))
			wire, err := env.Sign(testfixture.IssuerKeyID, b.keys.Issuer)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			res := b.verify(Options{
				Revocation: revocation.Checker{
					Fetcher:    stubFetcher{status: 200, body: wire},
					IssuerKeys: b.keys.Keyring,
					Now:        during,
				},
			})
			if res.Verdict != tc.want {
				t.Fatalf("verdict = %s, want %s (%s)",
					res.Verdict, tc.want, res.Revocation.Detail())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The integration seam.
// ---------------------------------------------------------------------------

type stubCheck struct {
	name       string
	findings   []Finding
	unresolved []string
	ran        *bool
}

func (s stubCheck) Name() string { return s.name }
func (s stubCheck) Check(*Bundle) CheckResult {
	if s.ran != nil {
		*s.ran = true
	}
	return CheckResult{Findings: s.findings, Unresolved: s.unresolved}
}

// TestRegisteredCheckCanRefuse is the contract the coverage and assertion
// packages rely on: a finding from a plugged-in check refuses the bundle, and
// cannot be downgraded by anything else in the pipeline.
func TestRegisteredCheckCanRefuse(t *testing.T) {
	b := newBuilder(t)
	ran := false
	res := b.verify(Options{
		Revocation: revocation.Checker{
			Fetcher:    stubFetcher{status: 404},
			IssuerKeys: b.keys.Keyring,
		},
		Checks: []Check{stubCheck{
			name:     "coverage",
			findings: []Finding{{Code: "coverage.ratio_not_null_at_c4", Message: "ES-017"}},
			ran:      &ran,
		}},
	})
	if !ran {
		t.Fatal("the registered check never ran")
	}
	if res.Verdict != Invalid {
		t.Fatalf("verdict = %s; a refusing check must refuse the bundle", res.Verdict)
	}
	if !hasCode(res, "coverage.ratio_not_null_at_c4") {
		t.Fatalf("codes = %v", codes(res))
	}
}

// TestChecksAreNamedInTheResult: the output has to be able to say what was
// checked. A verdict that does not name its checks lets an unregistered
// coverage check read as a passed one.
func TestChecksAreNamedInTheResult(t *testing.T) {
	b := newBuilder(t)
	res := b.verify(Options{
		Revocation: revocation.Checker{
			Fetcher: stubFetcher{status: 404}, IssuerKeys: b.keys.Keyring,
		},
		Checks: []Check{
			stubCheck{name: "coverage"},
			stubCheck{name: "assertions"},
		},
	})
	if len(res.ChecksRun) != 2 || res.ChecksRun[0] != "coverage" ||
		res.ChecksRun[1] != "assertions" {
		t.Fatalf("ChecksRun = %v", res.ChecksRun)
	}
	// The ES-009 standing limitation is disclosed on every run; what must not
	// appear is the "no checks registered" note, since two were.
	for _, note := range res.Notes {
		if strings.Contains(note, "no coverage") {
			t.Fatalf("checks were registered but the result says otherwise: %v", res.Notes)
		}
	}
}

func TestNoChecksRegisteredIsDisclosed(t *testing.T) {
	b := newBuilder(t)
	res := b.verify(Options{
		Revocation: revocation.Checker{
			Fetcher: stubFetcher{status: 404}, IssuerKeys: b.keys.Keyring,
		},
	})
	if len(res.Notes) == 0 {
		t.Fatal("a verdict reached with no coverage or assertion checks " +
			"registered must say so (AG-015)")
	}
}

// ---------------------------------------------------------------------------
// Type-level guarantees.
// ---------------------------------------------------------------------------

func TestZeroVerdictIsIndeterminate(t *testing.T) {
	var v Verdict
	if v != Indeterminate || v.String() != "indeterminate" {
		t.Fatalf("zero Verdict is %s", v)
	}
	var r Result
	if r.Verdict == Valid {
		t.Fatal("a zero Result reads as valid")
	}
	if got := Verdict(99).String(); got != "indeterminate" {
		t.Fatalf("out-of-range Verdict renders as %q", got)
	}
}

// TestNoFindingSetEverProducesValid states the invariant across the whole
// verdict machine rather than per case: if anything refused, the verdict is
// invalid, whatever else is true about the dates or the revocation status.
func TestNoFindingSetEverProducesValid(t *testing.T) {
	b := newBuilder(t)
	clocks := []time.Time{
		time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC), // before validity
		during(), // inside
		time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), // after
	}
	for _, now := range clocks {
		res := b.verify(Options{
			Now: func() time.Time { return now },
			Revocation: revocation.Checker{
				Fetcher: stubFetcher{status: 404}, IssuerKeys: b.keys.Keyring,
			},
			Checks: []Check{stubCheck{
				name:     "coverage",
				findings: []Finding{{Code: "coverage.gap_not_conserved", Message: "CM-014"}},
			}},
		})
		if res.Verdict != Invalid {
			t.Fatalf("at %s: verdict = %s with findings %v",
				now, res.Verdict, res.Findings)
		}
	}
}

// TestUnresolvedBlocksValidWithoutRefusing is the integration contract with the
// coverage recomputation. A claim the check could not decide is not a violation
// — nothing is refused — but it is also not a verification, so the verdict must
// not be "valid". Both halves matter: refusing would be an AG-002-shaped
// overreach, and passing would be the overclaim the product exists to prevent.
func TestUnresolvedBlocksValidWithoutRefusing(t *testing.T) {
	b := newBuilder(t)
	res := b.verify(Options{
		Revocation: revocation.Checker{
			Fetcher: stubFetcher{status: 404}, IssuerKeys: b.keys.Keyring,
		},
		Checks: []Check{stubCheck{
			name:       "coverage",
			unresolved: []string{"coverage_ratio: the specification does not define it"},
		}},
	})
	if len(res.Findings) != 0 {
		t.Fatalf("an unresolved item refused the bundle: %v", res.Findings)
	}
	if res.Verdict == Valid {
		t.Fatal("a claim nobody could check was reported as valid")
	}
	if res.Verdict != Indeterminate {
		t.Fatalf("verdict = %s, want indeterminate", res.Verdict)
	}
	// It must be attributed, or an operator cannot tell which check gave up.
	var attributed bool
	for _, u := range res.Unresolved {
		if strings.HasPrefix(u, "coverage: ") {
			attributed = true
		}
	}
	if !attributed {
		t.Fatalf("the check's unresolved item was not attributed to it: %v",
			res.Unresolved)
	}
}

// TestUnresolvedDoesNotMaskADeterminateNegative: expiry and revocation are
// conclusions, and an unresolved coverage item must not soften them into
// "indeterminate".
func TestUnresolvedDoesNotMaskADeterminateNegative(t *testing.T) {
	b := newBuilder(t)
	after := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	res := b.verify(Options{
		Now: func() time.Time { return after },
		Revocation: revocation.Checker{
			Fetcher: stubFetcher{status: 404}, IssuerKeys: b.keys.Keyring,
		},
		Checks: []Check{stubCheck{name: "coverage", unresolved: []string{"undecidable"}}},
	})
	if res.Verdict != Expired {
		t.Fatalf("verdict = %s, want expired", res.Verdict)
	}
}

// ---------------------------------------------------------------------------
// Boundary binding — the records must describe one boundary.
// ---------------------------------------------------------------------------

// TestAttestationNamingAnotherBoundaryIsRefused: every signature verifies and
// the records still do not belong together.
func TestAttestationNamingAnotherBoundaryIsRefused(t *testing.T) {
	b := newBuilder(t)
	b.attestation["boundary_ref"] = "boundary-2"
	res := b.verify(Options{})
	if res.Verdict != Invalid {
		t.Fatalf("verdict = %s; an attestation verified against a boundary it "+
			"does not name is a claim about a different scope", res.Verdict)
	}
	if !hasCode(res, CodeBoundaryMismatch) {
		t.Fatalf("codes = %v, want %s", codes(res), CodeBoundaryMismatch)
	}
}

// TestQualificationNotDeclaredByBoundaryIsRefused: a validly signed
// qualification the boundary never declared cannot entitle a class under it.
func TestQualificationNotDeclaredByBoundaryIsRefused(t *testing.T) {
	b := newBuilder(t)
	b.declareQualifications = false
	res := b.verify(Options{})
	if res.Verdict != Invalid {
		t.Fatalf("verdict = %s, want invalid", res.Verdict)
	}
	if !hasCode(res, CodeQualificationUndeclared) {
		t.Fatalf("codes = %v, want %s", codes(res), CodeQualificationUndeclared)
	}
}

// TestMissingBoundaryIsDisclosedNotAssumed: omitting the boundary is legitimate
// under ES-026, so it must not refuse — but the scope then went unchecked, and
// the verdict must not be "valid".
func TestMissingBoundaryIsDisclosedNotAssumed(t *testing.T) {
	b := newBuilder(t)
	b.withBoundary = false
	res := b.verify(Options{
		Revocation: revocation.Checker{
			Fetcher: stubFetcher{status: 404}, IssuerKeys: b.keys.Keyring,
		},
	})
	if len(res.Findings) != 0 {
		t.Fatalf("selective disclosure was refused: %v", res.Findings)
	}
	if res.Verdict == Valid {
		t.Fatal("a bundle whose scope was never checked reported valid")
	}
	if res.Verdict != Indeterminate {
		t.Fatalf("verdict = %s, want indeterminate", res.Verdict)
	}
}

// TestStandingLimitationsDoNotBlockAValidVerdict is the other half of that
// distinction. The ES-009 family-encoding gap is true of every bundle; if it
// blocked the verdict, "valid" would be unreachable for all inputs and the
// scale would stop distinguishing a good bundle from a bad one.
func TestStandingLimitationsDoNotBlockAValidVerdict(t *testing.T) {
	b := newBuilder(t)
	res := b.verify(Options{
		Revocation: revocation.Checker{
			Fetcher: stubFetcher{status: 404}, IssuerKeys: b.keys.Keyring,
		},
	})
	if res.Verdict != Valid {
		t.Fatalf("verdict = %s, want valid (findings %v, unresolved %v)",
			res.Verdict, res.Findings, res.Unresolved)
	}
	if len(res.Notes) == 0 {
		t.Fatal("the standing ES-009 limitation must still be disclosed")
	}
}

// ---------------------------------------------------------------------------
// Chain links.
// ---------------------------------------------------------------------------

// TestBrokenChainLinkIsRefused: two records at consecutive sequences in one
// stream, where the second does not link to the first. ES-006a digests the
// complete record, so this is also what catches a validly re-signed
// predecessor.
func TestBrokenChainLinkIsRefused(t *testing.T) {
	b := newBuilder(t)
	b.qualification = []map[string]any{
		testfixture.QualificationBody("C1", "2026-07-01T00:00:00Z"),
		testfixture.QualificationBody("C1", "2026-07-02T00:00:00Z"),
	}
	// The second qualification sits at sequence 2 in the same stream, but
	// points its prev_digest at something that is not its predecessor.
	b.secondQualification = func(env testfixture.Envelope) {
		env["sequence"] = int64(2)
		env["prev_digest"] = "sha256:" +
			"0000000000000000000000000000000000000000000000000000000000000000"
	}
	res := b.verify(Options{})
	if res.Verdict != Invalid {
		t.Fatalf("verdict = %s, want invalid", res.Verdict)
	}
	if !hasCode(res, CodeChainBroken) {
		t.Fatalf("codes = %v, want %s", codes(res), CodeChainBroken)
	}
}

// TestChainForkIsRefused: two records claiming one position in one stream.
func TestChainForkIsRefused(t *testing.T) {
	b := newBuilder(t)
	b.qualification = []map[string]any{
		testfixture.QualificationBody("C1", "2026-07-01T00:00:00Z"),
		testfixture.QualificationBody("C1", "2026-07-02T00:00:00Z"),
	}
	// Both left at sequence 1 in the same stream.
	res := b.verify(Options{})
	if res.Verdict != Invalid {
		t.Fatalf("verdict = %s, want invalid", res.Verdict)
	}
	if !hasCode(res, CodeChainFork) {
		t.Fatalf("codes = %v, want %s", codes(res), CodeChainFork)
	}
}

// TestNonContiguousSliceIsDisclosedNotRefused: ES-026 makes selective
// disclosure mandatory, so a bundle carrying sequences 1 and 3 must not be
// refused for the missing 2 — but the link across the hole is not checkable
// from what the bundle carries, and that must be said.
func TestNonContiguousSliceIsDisclosedNotRefused(t *testing.T) {
	b := newBuilder(t)
	b.qualification = []map[string]any{
		testfixture.QualificationBody("C1", "2026-07-01T00:00:00Z"),
		testfixture.QualificationBody("C1", "2026-07-02T00:00:00Z"),
	}
	b.secondQualification = func(env testfixture.Envelope) {
		env["sequence"] = int64(3)
		env["prev_digest"] = "sha256:" +
			"0000000000000000000000000000000000000000000000000000000000000000"
	}
	res := b.verify(Options{})
	if hasCode(res, CodeChainBroken) || hasCode(res, CodeChainFork) {
		t.Fatalf("a selectively disclosed slice was refused: %v", res.Findings)
	}
	var disclosed bool
	for _, u := range res.Unresolved {
		if strings.Contains(u, "jumps from sequence 1 to 3") {
			disclosed = true
		}
	}
	if !disclosed {
		t.Fatalf("the unverified chain hole was not disclosed: %v", res.Unresolved)
	}
}

// TestUnorderedBundleIsRefused is ES-034's ordering rule.
//
// The rule exists because canonicalizing the container is not enough on its
// own: RFC 8785 sorts the members of an object and does not reorder the
// elements of an array, so before this rule the same record set emitted in two
// orders produced two canonical, conformant bundles with different digests.
// QA-008 fails CI on any bundle diff, so that gate would have reported
// divergence between implementations agreeing about everything substantive.
func TestUnorderedBundleIsRefused(t *testing.T) {
	b := newBuilder(t)
	b.envelope["body"] = b.attestation
	att, err := b.envelope.SignAttestation(b.keys)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	qual, err := testfixture.NewEnvelope("QualificationRecord", qualificationID(0),
		tenant, "qualifications-1",
		testfixture.QualificationBody("C1", "2026-07-01T00:00:00Z"),
	).Sign(testfixture.EvidenceKeyID, b.keys.Evidence)
	if err != nil {
		t.Fatalf("sign qual: %v", err)
	}

	sorted, err := testfixture.Bundle(att, qual)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if _, err := Parse(sorted); err != nil {
		t.Fatalf("the sorted bundle was refused: %v", err)
	}

	// The same records in the other order. Still canonical, still every
	// signature valid, and no longer a conformant bundle.
	reversed, err := testfixture.BundleInOrder(att, qual)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if bytes.Equal(sorted, reversed) {
		t.Skip("the fixture happens to be in sorted order already")
	}
	_, err = Parse(reversed)
	if err == nil {
		t.Fatal("an unordered bundle parsed; the same record set then has two " +
			"bundles with two digests and QA-008 cannot hold")
	}
	if !strings.Contains(err.Error(), CodeBundleUnordered) {
		t.Fatalf("error = %v, want %s", err, CodeBundleUnordered)
	}
}

// TestOneRecordSetHasOneBundle is the property the ordering rule buys, stated
// directly: assembling the same records in any order yields identical bytes.
func TestOneRecordSetHasOneBundle(t *testing.T) {
	b := newBuilder(t)
	b.envelope["body"] = b.attestation
	att, err := b.envelope.SignAttestation(b.keys)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	qual, err := testfixture.NewEnvelope("QualificationRecord", qualificationID(0),
		tenant, "qualifications-1",
		testfixture.QualificationBody("C1", "2026-07-01T00:00:00Z"),
	).Sign(testfixture.EvidenceKeyID, b.keys.Evidence)
	if err != nil {
		t.Fatalf("sign qual: %v", err)
	}
	one, _ := testfixture.Bundle(att, qual)
	two, _ := testfixture.Bundle(qual, att)
	if !bytes.Equal(one, two) {
		t.Fatalf("two assembly orders produced different bundles:\n  %s\n  %s",
			one, two)
	}
}

// TestDuplicateRecordIsRefused: two byte-identical elements are one record
// presented twice, and would make counts and chain links depend on how many
// copies a producer happened to include.
func TestDuplicateRecordIsRefused(t *testing.T) {
	b := newBuilder(t)
	b.envelope["body"] = b.attestation
	att, err := b.envelope.SignAttestation(b.keys)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	qual, err := testfixture.NewEnvelope("QualificationRecord", qualificationID(0),
		tenant, "qualifications-1",
		testfixture.QualificationBody("C1", "2026-07-01T00:00:00Z"),
	).Sign(testfixture.EvidenceKeyID, b.keys.Evidence)
	if err != nil {
		t.Fatalf("sign qual: %v", err)
	}
	container, err := testfixture.Bundle(att, qual, qual)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if _, err := Parse(container); err == nil {
		t.Fatal("a bundle carrying the same record twice parsed")
	}
}
