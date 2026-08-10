package conformance

import (
	"strings"
	"testing"

	"github.com/Align3/evidence-control-plane/verifier-go/internal/evidence"
)

// TestStreamRefusalShapeIsChecked is a test of the harness, not of the
// verifier.
//
// The corpus check for a stream vector runs on two paths — refusal while
// parsing a record, and refusal while verifying the stream — and only the
// second used to assert the break position. A vector pinning break_sequence was
// therefore satisfied by any parse-time error carrying the right code, which is
// the right answer with the wrong shape: CM-017 makes the position the part
// that says how much of the window survived.
//
// A harness only ever run against a corpus it passes cannot show that it would
// catch that, so the cases below are stated directly.
func TestStreamRefusalShapeIsChecked(t *testing.T) {
	pinned := map[string]any{
		"expected": map[string]any{
			"accepted":               false,
			"error_code":             "schema.missing_envelope_member",
			"break_sequence":         float64(7),
			"valid_through_sequence": float64(6),
		},
	}
	unpinned := map[string]any{
		"expected": map[string]any{
			"accepted":   false,
			"error_code": "schema.missing_envelope_member",
		},
	}
	positionless := &evidence.Error{
		Code: "schema.missing_envelope_member", Msg: "missing envelope member",
	}
	positioned := &evidence.StreamError{
		Code: "schema.missing_envelope_member", Msg: "missing envelope member",
		BreakSequence: 7, ValidThrough: 6,
	}

	cases := []struct {
		name     string
		vector   map[string]any
		err      error
		wantFail string
	}{
		{"positionless refusal against a pinned vector", pinned, positionless,
			"carries none"},
		{"wrong break position", pinned, &evidence.StreamError{
			Code: "schema.missing_envelope_member", BreakSequence: 3, ValidThrough: 6,
		}, "break_sequence 3 != 7"},
		{"wrong valid-through position", pinned, &evidence.StreamError{
			Code: "schema.missing_envelope_member", BreakSequence: 7, ValidThrough: 2,
		}, "valid_through_sequence 2 != 6"},
		{"wrong code", pinned, &evidence.StreamError{
			Code: "chain.sequence_gap", BreakSequence: 7, ValidThrough: 6,
		}, "expected schema.missing_envelope_member"},
		{"acceptance where the vector states a refusal", pinned, nil,
			"got acceptance"},
		{"matching refusal", pinned, positioned, ""},
		{"positionless refusal against a vector that pins nothing", unpinned,
			positionless, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := streamRefusalMismatch("synthetic", tc.err, tc.vector)
			switch {
			case tc.wantFail == "" && got != "":
				t.Fatalf("expected a match, got mismatch %q", got)
			case tc.wantFail != "" && !strings.Contains(got, tc.wantFail):
				t.Fatalf("expected a mismatch mentioning %q, got %q", tc.wantFail, got)
			}
		})
	}
}
