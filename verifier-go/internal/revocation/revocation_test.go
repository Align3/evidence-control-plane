package revocation

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Align3/evidence-control-plane/verifier-go/internal/evidence"
	"github.com/Align3/evidence-control-plane/verifier-go/internal/testfixture"
)

const attestationRef = "01890f47-2f58-7cc0-98c4-000000000064"

func keys(t *testing.T) testfixture.Keys {
	t.Helper()
	k, err := testfixture.NewKeys()
	if err != nil {
		t.Fatalf("fixture keys: %v", err)
	}
	return k
}

// revocationWire builds a signed RevocationRecord. ES-033 puts RevocationRecord
// in the issuer-observation category, so the fixture signs with the issuer key
// unless a test is specifically probing the wrong one.
func revocationWire(t *testing.T, k testfixture.Keys, ref, reason, effectiveAt,
	supersedingRef string) []byte {
	t.Helper()
	env := testfixture.NewEnvelope("RevocationRecord", "01890f47-2f58-7cc0-98c4-0000000000aa",
		"tenant-1", "revocations-1",
		testfixture.RevocationBody(ref, reason, effectiveAt, supersedingRef))
	wire, err := env.Sign(testfixture.IssuerKeyID, k.Issuer)
	if err != nil {
		t.Fatalf("sign revocation: %v", err)
	}
	return wire
}

// stubFetcher returns whatever a test tells it to, including failures a real
// network produces but a happy-path test never exercises.
type stubFetcher struct {
	status int
	body   []byte
	err    error
}

func (s stubFetcher) Fetch(context.Context, string) (int, []byte, error) {
	return s.status, s.body, s.err
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// ---------------------------------------------------------------------------
// Negative first (AG-007). Every one of these is a way the check can fail, and
// the requirement is that not one of them is allowed to look like good news.
// ---------------------------------------------------------------------------

// TestNoFailurePathReportsValid is the requirement itself, stated once over
// every failure the machine can encounter. If a future change adds a code path
// that swallows an error, this is the test that should stop it — which is why
// it asserts over a table rather than in one scenario.
func TestNoFailurePathReportsValid(t *testing.T) {
	k := keys(t)
	cases := []struct {
		name    string
		checker Checker
		reason  string
	}{
		{
			name:    "offline by configuration",
			checker: Checker{Offline: true, Fetcher: stubFetcher{status: 404}, IssuerKeys: k.Keyring},
			reason:  ReasonOffline,
		},
		{
			name:    "no endpoint configured",
			checker: Checker{IssuerKeys: k.Keyring},
			reason:  ReasonNoEndpoint,
		},
		{
			name: "connection refused",
			checker: Checker{
				Fetcher:    stubFetcher{err: errors.New("connection refused")},
				IssuerKeys: k.Keyring,
			},
			reason: ReasonTransport,
		},
		{
			name: "DNS failure",
			checker: Checker{
				Fetcher:    stubFetcher{err: &net.DNSError{Err: "no such host"}},
				IssuerKeys: k.Keyring,
			},
			reason: ReasonTransport,
		},
		{
			name: "timeout",
			checker: Checker{
				Fetcher:    stubFetcher{err: timeoutError{}},
				IssuerKeys: k.Keyring,
			},
			reason: ReasonTimeout,
		},
		{
			name: "context deadline exceeded",
			checker: Checker{
				Fetcher:    stubFetcher{err: context.DeadlineExceeded},
				IssuerKeys: k.Keyring,
			},
			reason: ReasonTimeout,
		},
		{
			name: "server error",
			checker: Checker{
				Fetcher:    stubFetcher{status: 500},
				IssuerKeys: k.Keyring,
			},
			reason: ReasonHTTPStatus,
		},
		{
			name: "forbidden",
			checker: Checker{
				Fetcher:    stubFetcher{status: 403},
				IssuerKeys: k.Keyring,
			},
			reason: ReasonHTTPStatus,
		},
		{
			name: "captive portal returns 200 with HTML",
			checker: Checker{
				Fetcher:    stubFetcher{status: 200, body: []byte("<html>sign in</html>")},
				IssuerKeys: k.Keyring,
			},
			reason: ReasonUnauthenticated,
		},
		{
			name: "empty 200",
			checker: Checker{
				Fetcher:    stubFetcher{status: 200, body: nil},
				IssuerKeys: k.Keyring,
			},
			reason: ReasonMalformed,
		},
		{
			name: "200 with an unsigned RevocationRecord",
			checker: Checker{
				Fetcher: stubFetcher{status: 200, body: []byte(
					`{"body":{},"record_type":"RevocationRecord"}`)},
				IssuerKeys: k.Keyring,
			},
			reason: ReasonUnauthenticated,
		},
		{
			name: "no issuer keys to authenticate with",
			checker: Checker{
				Fetcher: stubFetcher{status: 200, body: revocationWire(t, k, attestationRef,
					"defect", "2026-09-02T00:00:00Z", "")},
				IssuerKeys: nil,
			},
			reason: ReasonUnauthenticated,
		},
		{
			name: "empty attestation reference",
			checker: Checker{
				Fetcher:    stubFetcher{status: 404},
				IssuerKeys: k.Keyring,
			},
			reason: ReasonWrongSubject,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ref := attestationRef
			if tc.reason == ReasonWrongSubject {
				ref = ""
			}
			got := tc.checker.Check(context.Background(), ref)
			if got.Status() == Valid {
				t.Fatalf("a %s reported revocation_status=valid; TM-014 forbids it", tc.name)
			}
			if got.Status() != Unchecked {
				t.Fatalf("status = %s, want unchecked", got.Status())
			}
			if got.Reason() != tc.reason {
				t.Fatalf("reason = %s, want %s (detail: %s)",
					got.Reason(), tc.reason, got.Detail())
			}
			if got.Checked() {
				t.Fatal("Checked() reported true for an unchecked result")
			}
		})
	}
}

// TestZeroValuesAreUnchecked pins the type-level guarantee. A struct nobody
// filled in, and a Status nobody assigned, must both mean "I did not check".
func TestZeroValuesAreUnchecked(t *testing.T) {
	var s Status
	if s != Unchecked || s.String() != "unchecked" {
		t.Fatalf("zero Status is %s; it must be unchecked", s)
	}
	var r Result
	if r.Status() != Unchecked || r.Checked() {
		t.Fatal("zero Result is not unchecked")
	}
	// An out-of-range value must not render as anything affirmative either.
	if got := Status(99).String(); got != "unchecked" {
		t.Fatalf("out-of-range Status renders as %q", got)
	}
}

// TestEvidenceKeySignedRevocationIsUnchecked probes the composition path
// testing-qa §10 warns about: a correct primitive reached through an entry
// point that forgot to apply it. ES-033 puts RevocationRecord in the issuer
// category, so a customer-signed one is the customer answering a question only
// the issuer may answer — here, whether their own attestation still stands.
func TestEvidenceKeySignedRevocationIsUnchecked(t *testing.T) {
	k := keys(t)
	env := testfixture.NewEnvelope("RevocationRecord", "01890f47-2f58-7cc0-98c4-0000000000ab",
		"tenant-1", "revocations-1",
		testfixture.RevocationBody(attestationRef, "defect", "2026-09-02T00:00:00Z", ""))
	wire, err := env.Sign(testfixture.EvidenceKeyID, k.Evidence)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	c := Checker{Fetcher: stubFetcher{status: 200, body: wire}, IssuerKeys: k.Keyring}
	got := c.Check(context.Background(), attestationRef)
	if got.Status() != Unchecked || got.Reason() != ReasonUnauthenticated {
		t.Fatalf("evidence-signed revocation gave %s/%s; want unchecked/%s",
			got.Status(), got.Reason(), ReasonUnauthenticated)
	}
}

// TestRevocationForAnotherAttestationIsUnchecked: an authenticated record about
// a different subject is not evidence about this one in either direction.
func TestRevocationForAnotherAttestationIsUnchecked(t *testing.T) {
	k := keys(t)
	wire := revocationWire(t, k, "some-other-attestation", "defect", "2026-09-02T00:00:00Z", "")
	c := Checker{Fetcher: stubFetcher{status: 200, body: wire}, IssuerKeys: k.Keyring}
	got := c.Check(context.Background(), attestationRef)
	if got.Status() != Unchecked || got.Reason() != ReasonWrongSubject {
		t.Fatalf("got %s/%s, want unchecked/%s", got.Status(), got.Reason(), ReasonWrongSubject)
	}
}

func TestUnparseableEffectiveAtIsUnchecked(t *testing.T) {
	k := keys(t)
	wire := revocationWire(t, k, attestationRef, "defect", "last Tuesday", "")
	c := Checker{Fetcher: stubFetcher{status: 200, body: wire}, IssuerKeys: k.Keyring}
	got := c.Check(context.Background(), attestationRef)
	if got.Status() != Unchecked || got.Reason() != ReasonBodyShape {
		t.Fatalf("got %s/%s, want unchecked/%s", got.Status(), got.Reason(), ReasonBodyShape)
	}
}

// TestRealNetworkFailuresAreUnchecked exercises the actual HTTP transport
// rather than a stub, because a stub cannot demonstrate that the deployed
// client times out at all. A verifier that hangs never reports unchecked; it
// reports nothing, and an operator eventually kills it and reruns it with the
// check disabled.
func TestRealNetworkFailuresAreUnchecked(t *testing.T) {
	k := keys(t)

	t.Run("server never answers", func(t *testing.T) {
		blocked := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-blocked
		}))
		// Order matters: Close waits for outstanding handlers, so the handler
		// has to be released first or the test deadlocks instead of failing.
		defer srv.Close()
		defer close(blocked)
		c := Checker{
			Fetcher:    NewHTTPFetcher(srv.URL, 100*time.Millisecond),
			IssuerKeys: k.Keyring,
		}
		got := c.Check(context.Background(), attestationRef)
		if got.Status() != Unchecked {
			t.Fatalf("a hung endpoint gave %s", got.Status())
		}
		if got.Reason() != ReasonTimeout {
			t.Fatalf("reason = %s, want %s (%s)", got.Reason(), ReasonTimeout, got.Detail())
		}
	})

	t.Run("nothing is listening", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		url := srv.URL
		srv.Close() // the port is now closed
		c := Checker{Fetcher: NewHTTPFetcher(url, time.Second), IssuerKeys: k.Keyring}
		got := c.Check(context.Background(), attestationRef)
		if got.Status() != Unchecked {
			t.Fatalf("a closed port gave %s", got.Status())
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(500 * time.Millisecond)
		}))
		defer srv.Close()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		c := Checker{Fetcher: NewHTTPFetcher(srv.URL, time.Minute), IssuerKeys: k.Keyring}
		got := c.Check(ctx, attestationRef)
		if got.Status() != Unchecked {
			t.Fatalf("a cancelled context gave %s", got.Status())
		}
	})
}

// ---------------------------------------------------------------------------
// The three checked states.
// ---------------------------------------------------------------------------

func TestIssuerSaysNothingPublished(t *testing.T) {
	k := keys(t)
	c := Checker{Fetcher: stubFetcher{status: 404}, IssuerKeys: k.Keyring}
	got := c.Check(context.Background(), attestationRef)
	if got.Status() != Valid {
		t.Fatalf("status = %s, want valid", got.Status())
	}
	if got.Reason() != ReasonNonePublished || !got.Checked() {
		t.Fatalf("reason = %s, checked = %v", got.Reason(), got.Checked())
	}
}

func TestRevoked(t *testing.T) {
	k := keys(t)
	wire := revocationWire(t, k, attestationRef, "computation defect", "2026-09-02T00:00:00Z", "")
	c := Checker{
		Fetcher:    stubFetcher{status: 200, body: wire},
		IssuerKeys: k.Keyring,
		Now:        func() time.Time { return time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC) },
	}
	got := c.Check(context.Background(), attestationRef)
	if got.Status() != Revoked {
		t.Fatalf("status = %s, want revoked (%s)", got.Status(), got.Detail())
	}
	if got.SupersededBy != "" {
		t.Fatalf("a plain revocation reported SupersededBy=%q", got.SupersededBy)
	}
}

func TestSuperseded(t *testing.T) {
	k := keys(t)
	wire := revocationWire(t, k, attestationRef, "late evidence",
		"2026-09-02T00:00:00Z", "attestation-2")
	c := Checker{
		Fetcher:    stubFetcher{status: 200, body: wire},
		IssuerKeys: k.Keyring,
		Now:        func() time.Time { return time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC) },
	}
	got := c.Check(context.Background(), attestationRef)
	if got.Status() != Superseded {
		t.Fatalf("status = %s, want superseded (%s)", got.Status(), got.Detail())
	}
	if got.SupersededBy != "attestation-2" {
		t.Fatalf("SupersededBy = %q", got.SupersededBy)
	}
}

// TestRevocationNotYetEffective: the issuer answered, so this is checked, and
// the answer is that the revocation has not taken effect. The pending state
// travels on the Result instead of being discarded.
func TestRevocationNotYetEffective(t *testing.T) {
	k := keys(t)
	wire := revocationWire(t, k, attestationRef, "defect", "2026-12-01T00:00:00Z", "")
	c := Checker{
		Fetcher:    stubFetcher{status: 200, body: wire},
		IssuerKeys: k.Keyring,
		Now:        func() time.Time { return time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC) },
	}
	got := c.Check(context.Background(), attestationRef)
	if got.Status() != Valid || got.Reason() != ReasonNotYetEffective {
		t.Fatalf("got %s/%s, want valid/%s", got.Status(), got.Reason(), ReasonNotYetEffective)
	}
	if got.EffectiveAt != "2026-12-01T00:00:00Z" {
		t.Fatalf("EffectiveAt = %q; the pending revocation must stay visible", got.EffectiveAt)
	}
}

// TestEndToEndOverRealHTTP proves the wiring, not just the classifier.
func TestEndToEndOverRealHTTP(t *testing.T) {
	k := keys(t)
	wire := revocationWire(t, k, attestationRef, "computation defect", "2026-09-02T00:00:00Z", "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/revocations/"+attestationRef {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(wire)
	}))
	defer srv.Close()

	c := Checker{
		Fetcher:    NewHTTPFetcher(srv.URL, 5*time.Second),
		IssuerKeys: k.Keyring,
		Now:        func() time.Time { return time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC) },
	}
	if got := c.Check(context.Background(), attestationRef); got.Status() != Revoked {
		t.Fatalf("status = %s, want revoked (%s)", got.Status(), got.Detail())
	}
	// An attestation the issuer has nothing on gets a 404 from the same server.
	if got := c.Check(context.Background(), "unknown-attestation"); got.Status() != Valid {
		t.Fatalf("status = %s, want valid", got.Status())
	}
}

// TestFixtureRevocationVerifiesAsAnEvidenceRecord guards the fixture itself.
// If these fixtures ever stop being canonical or stop verifying, the tests
// above would start passing for the wrong reason.
func TestFixtureRevocationVerifiesAsAnEvidenceRecord(t *testing.T) {
	k := keys(t)
	wire := revocationWire(t, k, attestationRef, "defect", "2026-09-02T00:00:00Z", "")
	v, err := evidence.VerifyCanonicalEvidenceRecord(wire, k.Keyring)
	if err != nil {
		t.Fatalf("fixture RevocationRecord does not verify: %v", err)
	}
	if v.RecordType != "RevocationRecord" || v.KeyID != testfixture.IssuerKeyID {
		t.Fatalf("unexpected verification %+v", v)
	}
}
