package conformance

import (
	"encoding/json"
	"testing"

	"github.com/Align3/evidence-control-plane/verifier-go/internal/evidence"
)

// TestBothFailuresReported covers the refusal-precedence rule added to ES-006a.
//
// reject-validly-resigned-predecessor is a stream in which the predecessor was
// re-signed under a different key. Two integrity failures are independently
// determinable at sequence 2: the link no longer matches (ES-006a), and the
// signing key changed with no continuity assertion (ES-024). Reporting only one
// would tell a relying party half of what went wrong, and which half would
// depend on an implementation's check order rather than on the evidence.
//
// The vector's normative error_code is the first in chain-traversal order, so
// the corpus expectation is unchanged; the second code is additional detail.
func TestBothFailuresReported(t *testing.T) {
	vf := loadVectors(t)
	var target map[string]any
	for _, v := range vf.Vectors {
		if v["id"] == "reject-validly-resigned-predecessor" {
			target = v
		}
	}
	if target == nil {
		t.Skip("vector reject-validly-resigned-predecessor is not in the corpus")
	}

	rawRecords, _ := target["records"].([]any)
	records := make([]*evidence.Record, 0, len(rawRecords))
	for i, raw := range rawRecords {
		b, err := json.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		rec, err := evidence.ParseRecord(b)
		if err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
		records = append(records, rec)
	}

	_, err := evidence.VerifyStream(records, keyring(t, target["public_keys"]))
	if err == nil {
		t.Fatal("expected the stream to be refused")
	}
	se, ok := err.(*evidence.StreamError)
	if !ok {
		t.Fatalf("expected *evidence.StreamError, got %T", err)
	}

	// Chain-traversal order: the link is traversed before the key state.
	if se.Code != evidence.CodeChainPrevDigestMismatch {
		t.Fatalf("leading code must be the traversal-order first failure, got %s", se.Code)
	}
	want := map[string]bool{
		evidence.CodeChainPrevDigestMismatch: false,
		evidence.CodeContinuityMissing:       false,
	}
	for _, c := range se.Codes {
		if _, ok := want[c]; ok {
			want[c] = true
		}
	}
	for code, seen := range want {
		if !seen {
			t.Fatalf("both determinable failures must be reported; %s was suppressed (reported: %v)",
				code, se.Codes)
		}
	}
	if se.Codes[0] != se.Code {
		t.Fatal("Code must be the first entry of Codes")
	}
}
