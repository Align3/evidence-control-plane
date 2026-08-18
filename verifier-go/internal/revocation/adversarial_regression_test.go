package revocation

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/Align3/evidence-control-plane/verifier-go/internal/testfixture"
)

func TestMalformedFutureRevocationCannotReportValid(t *testing.T) {
	k := keys(t)
	body := testfixture.RevocationBody(
		attestationRef, "key compromise", "2026-08-15T00:00:00Z", "")
	body["superseding_ref"] = int64(7)
	env := testfixture.NewEnvelope("RevocationRecord",
		"01890f47-2f58-7cc0-98c4-0000000000aa", "tenant-1", "revocations-1", body)
	wire, err := env.Sign(testfixture.IssuerKeyID, k.Issuer)
	if err != nil {
		t.Fatalf("sign malformed revocation: %v", err)
	}
	checker := Checker{
		Fetcher: stubFetcher{status: http.StatusOK, body: wire}, IssuerKeys: k.Keyring,
		Now: func() time.Time { return time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC) },
	}
	got := checker.Check(context.Background(), attestationRef)
	if got.Status() != Unchecked || got.Reason() != ReasonBodyShape {
		t.Fatalf("malformed future revocation = %s/%s, want unchecked/body-shape", got.Status(), got.Reason())
	}
}

func TestUnpublishedRevocationSchemaCannotBeActedOn(t *testing.T) {
	k := keys(t)
	env := testfixture.NewEnvelope("RevocationRecord",
		"01890f47-2f58-7cc0-98c4-0000000000ab", "tenant-1", "revocations-1",
		testfixture.RevocationBody(attestationRef, "key compromise", "2026-08-01T00:00:00Z", ""))
	env["schema_version"] = "9.9.9"
	wire, err := env.Sign(testfixture.IssuerKeyID, k.Issuer)
	if err != nil {
		t.Fatalf("sign unpublished-version revocation: %v", err)
	}
	got := (Checker{
		Fetcher: stubFetcher{status: http.StatusOK, body: wire}, IssuerKeys: k.Keyring,
		Now: func() time.Time { return time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC) },
	}).Check(context.Background(), attestationRef)
	if got.Status() != Unchecked || got.Reason() != ReasonMalformed {
		t.Fatalf("unpublished schema = %s/%s, want unchecked/malformed", got.Status(), got.Reason())
	}
}
