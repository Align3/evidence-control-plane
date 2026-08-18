package bundle

import (
	"encoding/json"
	"testing"

	"github.com/Align3/evidence-control-plane/verifier-go/internal/testfixture"
)

func TestOtherRecordChainIsChecked(t *testing.T) {
	b := newBuilder(t)
	var base []json.RawMessage
	if err := json.Unmarshal(b.build(), &base); err != nil {
		t.Fatal(err)
	}
	body := map[string]any{
		"action_id":                   "01890f47-2f58-7cc0-98c4-000000000401",
		"dispatch_attempt":            int64(1),
		"connector_identity":          "connector-1",
		"connector_version":           "1.0.0",
		"destination_response_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"destination_record_ref":      "dest-1",
		"status":                      "accepted",
		"dispatched_at":               "2026-08-02T00:00:00Z",
		"responded_at":                "2026-08-02T00:00:01Z",
	}
	first := testfixture.NewEnvelope("ExecutionReceipt",
		"01890f47-2f58-7cc0-98c4-000000000401", tenant, "receipts-1", body)
	firstWire, err := first.Sign(testfixture.EvidenceKeyID, b.keys.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	second := testfixture.NewEnvelope("ExecutionReceipt",
		"01890f47-2f58-7cc0-98c4-000000000402", tenant, "receipts-1", body)
	second["sequence"] = int64(2)
	second["prev_digest"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	secondWire, err := second.Sign(testfixture.EvidenceKeyID, b.keys.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	records := make([][]byte, 0, len(base)+2)
	for _, raw := range base {
		records = append(records, raw)
	}
	records = append(records, firstWire, secondWire)
	wire, err := testfixture.Bundle(records...)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(wire)
	if err != nil {
		t.Fatal(err)
	}
	findings, unresolved := checkChainLinks(parsed)
	if !hasCode(Result{Findings: findings}, CodeChainBroken) {
		t.Fatalf("broken consecutive ExecutionReceipt chain was accepted: findings=%v unresolved=%v", findings, unresolved)
	}
}
