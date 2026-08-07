package evidence

import (
	"crypto/ed25519"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Align3/evidence-control-plane/verifier-go/internal/jcs"
)

// Receipt error codes.
const (
	CodeReceiptSignatureInvalid = "receipt.signature_invalid"
	CodeReceiptRecordMismatch   = "receipt.record_mismatch"
	CodeReceiptUnknownMember    = "receipt.unknown_member"
	CodeReceiptMissingMember    = "receipt.missing_member"
	CodeReceiptNonCanonical     = "receipt.non_canonical"
	CodeReceiptSkewMismatch     = "receipt.clock_skew_mismatch"
	CodeReceiptUnknownKey       = "receipt.unknown_signing_key"
)

// receiptMembers is the closed payload of ES-030: exactly these three.
var receiptMembers = map[string]bool{
	"record_digest": true, "ingest_time": true, "clock_skew_ms": true,
}

// SignedReceipt is the authoritative receipt bytes and their detached proof.
type SignedReceipt struct {
	CanonicalBytes []byte
	KeyID          string
	Signature      []byte
}

// ReceiptPayload is the verified hosted observation.
type ReceiptPayload struct {
	RecordDigest string
	IngestTime   string
	ClockSkewMS  int64
}

// VerifyIngestionReceipt checks the ES-030 receipt: issuer namespace, the
// issuer proof over the exact stored bytes, and the binding to the complete
// customer record.
//
// The binding is to the complete record including its signature member, which
// is deliberately not the customer's signed_digest (ES-021). Substituting the
// customer signature therefore breaks the receipt even though the record
// content is unchanged: the receipt attests which artifact arrived, not what
// the customer signed.
func VerifyIngestionReceipt(receipt SignedReceipt, record *Record,
	keys map[string]RegisteredKey) (*ReceiptPayload, error) {

	registered, ok := keys[receipt.KeyID]
	if !ok {
		return nil, errf(CodeReceiptUnknownKey,
			"unknown receipt signing key %q", receipt.KeyID)
	}
	// SE-003 before cryptography: an evidence key that produced a perfectly
	// valid proof is still the wrong role, and saying so is more useful than
	// "signature invalid".
	if registered.Namespace != NamespaceIssuer {
		return nil, errf(CodeKeyNamespaceMismatch,
			"key %q is in the %q namespace; ingestion receipts require an issuer key (SE-003)",
			receipt.KeyID, registered.Namespace)
	}

	payloadV, err := jcs.Parse(receipt.CanonicalBytes)
	if err != nil {
		return nil, err
	}
	payload, ok := payloadV.(*jcs.Object)
	if !ok {
		return nil, errf(jcs.CodeMalformed, "receipt payload must be an object")
	}
	for _, k := range payload.Keys() {
		if !receiptMembers[k] {
			return nil, errf(CodeReceiptUnknownMember,
				"unknown receipt member %q (ES-030)", k)
		}
	}
	for k := range receiptMembers {
		if !payload.Has(k) {
			return nil, errf(CodeReceiptMissingMember,
				"missing receipt member %q (ES-030)", k)
		}
	}
	// The stored bytes are authoritative, so they must already be canonical;
	// re-serialising and comparing prevents a second spelling of one receipt.
	reserialised, err := jcs.Serialize(payload)
	if err != nil {
		return nil, err
	}
	if string(reserialised) != string(receipt.CanonicalBytes) {
		return nil, errf(CodeReceiptNonCanonical,
			"receipt bytes are not RFC 8785 canonical (ES-030)")
	}
	if !ed25519.Verify(registered.PublicKey, receipt.CanonicalBytes, receipt.Signature) {
		return nil, errf(CodeReceiptSignatureInvalid,
			"issuer key %q did not sign these receipt bytes", receipt.KeyID)
	}

	digest, _ := objString(payload, "record_digest")
	ingest, _ := objString(payload, "ingest_time")
	skewV, _ := payload.Get("clock_skew_ms")
	skew, ok := skewV.(int64)
	if !ok {
		return nil, errf(CodeReceiptMissingMember, "clock_skew_ms must be an integer")
	}

	complete, err := record.CompleteDigest()
	if err != nil {
		return nil, err
	}
	if digest != complete {
		return nil, errf(CodeReceiptRecordMismatch,
			"receipt names record %s but this record is %s", digest, complete)
	}

	// ES-020 gives a collector-supplied skew no standing, so the measurement is
	// recomputed here rather than believed.
	measured, err := MeasureClockSkewMS(record.SourceTime(), ingest)
	if err != nil {
		return nil, err
	}
	if measured != skew {
		return nil, errf(CodeReceiptSkewMismatch,
			"receipt clock_skew_ms %d does not equal ingest_time - source_time (%d)", skew, measured)
	}

	return &ReceiptPayload{RecordDigest: digest, IngestTime: ingest, ClockSkewMS: skew}, nil
}

// MeasureClockSkewMS returns ingest_time - source_time in whole milliseconds,
// truncating any sub-millisecond remainder toward zero (ES-030).
//
// Toward zero is not the same as flooring, and the two differ only when the
// collector clock ran ahead of ours: an exact -500us skew is 0 truncated and -1
// floored. Go's integer division truncates, which is what is wanted here; the
// hazard runs the other way for languages whose division floors.
//
// The remainder can only come from source_time, so the parse must keep the
// fractional field exactly rather than route it through a millisecond clock.
func MeasureClockSkewMS(sourceTime, ingestTime string) (int64, error) {
	src, err := parseRFC3339(sourceTime)
	if err != nil {
		return 0, err
	}
	ing, err := parseRFC3339(ingestTime)
	if err != nil {
		return 0, err
	}
	return ing.Sub(src).Nanoseconds() / int64(time.Millisecond), nil
}

// parseRFC3339 requires the explicit offset ES-002 mandates and keeps
// nanosecond resolution so sub-millisecond input survives the measurement.
func parseRFC3339(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, errf(jcs.CodeMalformed, "timestamp is empty")
	}
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, errf(jcs.CodeMalformed,
			"timestamp %q is not RFC 3339 with an explicit offset: %v", value, err)
	}
	return t, nil
}

// FormatIngestTime renders an instant the way ES-030 requires: RFC 3339 at
// millisecond precision, UTC, with a Z designator.
func FormatIngestTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

// ParseDigest splits an ES-003 digest into its algorithm and hex halves.
func ParseDigest(d string) (string, string, error) {
	alg, hexPart, found := strings.Cut(d, ":")
	if !found || alg != "sha256" || len(hexPart) != 64 {
		return "", "", errf(jcs.CodeMalformed, "malformed digest %q (ES-003)", d)
	}
	for _, c := range hexPart {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return "", "", errf(jcs.CodeMalformed,
				"digest %q must be lowercase hex (ES-003)", d)
		}
	}
	return alg, hexPart, nil
}

// FormatSkew is a helper for CLI output.
func FormatSkew(ms int64) string { return fmt.Sprintf("%s ms", strconv.FormatInt(ms, 10)) }
