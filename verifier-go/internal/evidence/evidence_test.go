package evidence

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Align3/evidence-control-plane/verifier-go/internal/jcs"
)

// baseRecord is a minimal conformant record: the closed §3 envelope, and the
// body §5.4 defines for the type it declares. Tests mutate one thing at a time
// so a refusal can only be attributed to that change.
func baseRecord() map[string]any {
	return map[string]any{
		"record_id":      "01890f47-2f58-7cc0-98c4-000000000001",
		"record_type":    "AgentIdentity",
		"schema_version": "1.0.0",
		"tenant_id":      "tenant-1",
		"boundary_ref":   "boundary-1",
		"stream_id":      "stream-1",
		"sequence":       1,
		"prev_digest":    nil,
		"source":         map[string]any{"collector_id": "collector-1", "version": "1.0.0"},
		"clocks":         map[string]any{"source_time": "2026-08-01T12:00:00.000Z"},
		"body": map[string]any{
			"agent_id":         "agent-1",
			"deployment":       "prod",
			"runtime":          "go-1.23",
			"tenant_scope":     "tenant-1",
			"service_identity": "collector@example.invalid",
			"model_versions":   []any{"model-1"},
			"tool_versions":    []any{"tool-1"},
			"credential_ref":   "service_identity",
		},
		"signature": map[string]any{},
	}
}

func parse(t *testing.T, rec map[string]any) (*Record, error) {
	t.Helper()
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	return ParseRecord(b)
}

// TestES005Asymmetry is the trap: the envelope is closed and the body is open,
// and an implementation that treats them alike is wrong in one direction or the
// other. A tolerated unknown envelope member is an extension point the spec
// deliberately withholds; a rejected unknown body member breaks forward
// compatibility.
func TestES005Asymmetry(t *testing.T) {
	rec := baseRecord()
	rec["surprise"] = "value"
	_, err := parse(t, rec)
	if err == nil {
		t.Fatal("unknown envelope member must fail verification (ES-005)")
	}
	if Code(err) != CodeUnknownEnvelopeMember {
		t.Fatalf("expected %s, got %s", CodeUnknownEnvelopeMember, Code(err))
	}

	rec = baseRecord()
	rec["body"].(map[string]any)["future_field"] = "kept"
	r, err := parse(t, rec)
	if err != nil {
		t.Fatalf("unknown body member must be tolerated (ES-005): %v", err)
	}
	// ...and it must reach the digest, not merely survive parsing.
	canonical, err := r.CompleteBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(canonical), "future_field") {
		t.Fatal("unknown body member must be preserved for digest computation (ES-005)")
	}
}

func TestMissingEnvelopeMemberRefused(t *testing.T) {
	for _, missing := range []string{"record_id", "sequence", "clocks", "signature", "prev_digest"} {
		t.Run(missing, func(t *testing.T) {
			rec := baseRecord()
			delete(rec, missing)
			if _, err := parse(t, rec); err == nil {
				t.Fatalf("missing %q must be refused", missing)
			}
		})
	}
}

// TestHostedClockFieldsRefused covers ES-019 in both spellings. A collector
// supplying either is asserting an observation only the hosted service can
// make, which is the whole reason EV-27 moved them out of the record.
func TestHostedClockFieldsRefused(t *testing.T) {
	for _, field := range []string{"ingest_time", "clock_skew_ms"} {
		t.Run(field, func(t *testing.T) {
			rec := baseRecord()
			rec["clocks"].(map[string]any)[field] = "2026-08-01T12:00:01.000Z"
			_, err := parse(t, rec)
			if err == nil || Code(err) != CodeHostedClockFieldForbid {
				t.Fatalf("expected %s, got %v", CodeHostedClockFieldForbid, err)
			}
		})
	}
}

// TestSignatureInclusiveDigestDiffers pins ES-006a. If these two ever coincide,
// prev_digest stops committing to the previous record's authentication and a
// re-signature becomes invisible to the chain.
func TestSignatureInclusiveDigestDiffers(t *testing.T) {
	rec := baseRecord()
	rec["signature"] = map[string]any{
		"alg": "ed25519", "key_id": "K1", "sig": "AA", "signed_digest": "sha256:" + strings.Repeat("0", 64),
	}
	r, err := parse(t, rec)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := r.SignedDigest()
	if err != nil {
		t.Fatal(err)
	}
	complete, err := r.CompleteDigest()
	if err != nil {
		t.Fatal(err)
	}
	if signed == complete {
		t.Fatal("ES-006a requires the signature-inclusive and signature-excluded digests to differ")
	}
}

// TestMeasureClockSkewTruncatesTowardZero is the ES-030 rounding trap. Flooring
// and truncating agree on every positive skew, so an implementation exercised
// only on late arrivals looks correct while being wrong for early clocks.
func TestMeasureClockSkewTruncatesTowardZero(t *testing.T) {
	cases := []struct {
		name, source, ingest string
		want                 int64
	}{
		{"exact", "2026-08-01T12:00:00.000Z", "2026-08-01T12:00:01.500Z", 1500},
		{"negative whole", "2026-08-01T12:00:02.000Z", "2026-08-01T12:00:00.000Z", -2000},
		{"negative sub-ms truncates to zero", "2026-08-01T12:00:00.0005Z", "2026-08-01T12:00:00.000Z", 0},
		{"negative truncates toward zero not down", "2026-08-01T12:00:01.0005Z", "2026-08-01T12:00:00.000Z", -1000},
		{"positive sub-ms truncates down", "2026-08-01T12:00:00.0005Z", "2026-08-01T12:00:01.000Z", 999},
		{"offset is honoured", "2026-08-01T13:00:00.000+01:00", "2026-08-01T12:00:00.500Z", 500},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := MeasureClockSkewMS(tc.source, tc.ingest)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("skew %d != %d", got, tc.want)
			}
		})
	}
}

func TestMeasureClockSkewRejectsNaiveTimestamp(t *testing.T) {
	// ES-002 requires an explicit offset. Guessing UTC for a naive timestamp
	// would silently shift every measurement by the collector's real offset.
	if _, err := MeasureClockSkewMS("2026-08-01T12:00:00.000", "2026-08-01T12:00:01.000Z"); err == nil {
		t.Fatal("a timestamp without an explicit offset must be refused")
	}
}

func TestParseDigestShape(t *testing.T) {
	good := "sha256:" + strings.Repeat("ab", 32)
	if _, _, err := ParseDigest(good); err != nil {
		t.Fatalf("valid digest refused: %v", err)
	}
	for _, bad := range []string{
		"sha256:" + strings.Repeat("AB", 32), // uppercase
		"sha512:" + strings.Repeat("ab", 32), // wrong algorithm
		"sha256:abc",                         // wrong length
		strings.Repeat("ab", 32),             // missing prefix
	} {
		if _, _, err := ParseDigest(bad); err == nil {
			t.Fatalf("malformed digest %q was accepted (ES-003)", bad)
		}
	}
}

func TestCodeExtractsFromEachErrorType(t *testing.T) {
	if got := Code(&Error{Code: "a.b"}); got != "a.b" {
		t.Fatalf("evidence error: %s", got)
	}
	if got := Code(&jcs.Error{Code: "c.d"}); got != "c.d" {
		t.Fatalf("jcs error: %s", got)
	}
	if got := Code(&StreamError{Code: "e.f"}); got != "e.f" {
		t.Fatalf("stream error: %s", got)
	}
}
