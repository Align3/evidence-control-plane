// Package conformance runs the published vectors (tests/vectors/) through the
// Go verifier. ES-029 makes the vectors normative and authoritative over prose,
// so a disagreement between this package and the corpus is a defect in the Go
// verifier or a finding against the corpus — never something to paper over by
// adjusting the expectation.
//
// This is the Go half of ES-S-007. The Python half runs the same corpus from
// tests/vectors/test_vectors.py; agreement across both is the cross
// implementation guarantee AC-011 exists to make meaningful.
package conformance

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Align3/evidence-control-plane/verifier-go/internal/bundle"
	"github.com/Align3/evidence-control-plane/verifier-go/internal/bundle/checks"
	"github.com/Align3/evidence-control-plane/verifier-go/internal/evidence"
	"github.com/Align3/evidence-control-plane/verifier-go/internal/jcs"
	"github.com/Align3/evidence-control-plane/verifier-go/internal/revocation"
)

type vectorFile struct {
	Format             string           `json:"format"`
	FormatVersion      string           `json:"format_version"`
	SpecVersion        string           `json:"spec_version"`
	Vectors            []map[string]any `json:"vectors"`
	AdversarialVectors []map[string]any `json:"adversarial_vectors"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	path := filepath.Join("..", "..", "..", "tests", "vectors", "vectors-v0.1.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vf vectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(vf.Vectors) == 0 {
		t.Fatal("agreement vector corpus is empty; refusing to report a vacuous pass")
	}
	if len(vf.AdversarialVectors) == 0 {
		t.Fatal("adversarial vector corpus is empty; refusing to certify only agreement")
	}
	return vf
}

func b64(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("vector carries non-unpadded-base64url %q: %v", s, err)
	}
	return raw
}

// remarshal re-encodes a decoded vector member as JSON bytes so the Go verifier
// parses it with its own parser rather than inheriting encoding/json's view.
func remarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("re-marshal vector member: %v", err)
	}
	return b
}

func expectedOf(v map[string]any) map[string]any {
	e, _ := v["expected"].(map[string]any)
	return e
}

func accepted(v map[string]any) bool {
	e := expectedOf(v)
	if a, ok := e["accepted"].(bool); ok {
		return a
	}
	return true
}

func wantCode(v map[string]any) string {
	e := expectedOf(v)
	s, _ := e["error_code"].(string)
	return s
}

func wantString(v map[string]any, key string) string {
	e := expectedOf(v)
	s, _ := e[key].(string)
	return s
}

// checkRefusal asserts the operation failed with exactly the vector's result.
//
// Exactly: the corpus states one error_code per refused vector and the
// implementation must reach that one. Accepting a superset, or treating the
// vector's code as merely the first of several, would let an implementation
// drift from the normative result while still reporting a pass — which is the
// whole failure mode the corpus exists to prevent (ES-029).
func checkRefusal(t *testing.T, id string, err error, want string) {
	t.Helper()
	if want == "" {
		t.Fatalf("%s: vector is marked refused but states no error_code", id)
	}
	if err == nil {
		t.Fatalf("%s: expected refusal %s, got acceptance", id, want)
	}
	if got := evidence.Code(err); got != want {
		t.Fatalf("%s: expected %s, got %s (%v)", id, want, got, err)
	}
}

// streamRefusalMismatch reports why a stream refusal fails to match the
// vector's stated result, or "" when it matches.
//
// It is a plain function rather than a t.Fatalf-calling helper so that
// TestStreamRefusalShapeIsChecked can assert on what it accepts. A harness that
// only ever runs against a corpus it passes cannot show that it would catch a
// verifier that stopped matching.
func streamRefusalMismatch(id string, err error, v map[string]any) string {
	want := wantCode(v)
	if want == "" {
		return fmt.Sprintf("%s: vector is marked refused but states no error_code", id)
	}
	if err == nil {
		return fmt.Sprintf("%s: expected refusal %s, got acceptance", id, want)
	}
	if got := evidence.Code(err); got != want {
		return fmt.Sprintf("%s: expected %s, got %s (%v)", id, want, got, err)
	}
	e := expectedOf(v)
	wantBreak, wantsBreak := e["break_sequence"].(float64)
	wantValid, wantsValid := e["valid_through_sequence"].(float64)
	if !wantsBreak && !wantsValid {
		return ""
	}
	// A vector that pins the break position is answered only by a refusal that
	// carries one. Treating a positionless error as satisfying it accepts the
	// right code with the wrong shape — and CM-017 makes the position the part
	// that says how much of the window survived, which is what a relying party
	// acts on.
	se, ok := err.(*evidence.StreamError)
	if !ok {
		return fmt.Sprintf("%s: vector pins the break position but the refusal is %T, "+
			"which carries none", id, err)
	}
	if wantsBreak && se.BreakSequence != int64(wantBreak) {
		return fmt.Sprintf("%s: break_sequence %d != %d", id, se.BreakSequence, int64(wantBreak))
	}
	if wantsValid && se.ValidThrough != int64(wantValid) {
		return fmt.Sprintf("%s: valid_through_sequence %d != %d", id, se.ValidThrough, int64(wantValid))
	}
	return ""
}

// checkStreamRefusal applies streamRefusalMismatch on every path by which a
// stream vector can be refused, including refusal during record parsing.
func checkStreamRefusal(t *testing.T, id string, err error, v map[string]any) {
	t.Helper()
	if mismatch := streamRefusalMismatch(id, err, v); mismatch != "" {
		t.Fatal(mismatch)
	}
}

func keyring(t *testing.T, raw any) map[string]ed25519.PublicKey {
	t.Helper()
	out := map[string]ed25519.PublicKey{}
	m, _ := raw.(map[string]any)
	for id, val := range m {
		s, _ := val.(string)
		out[id] = ed25519.PublicKey(b64(t, s))
	}
	return out
}

func registeredKeyring(t *testing.T, raw any) map[string]evidence.RegisteredKey {
	t.Helper()
	out := map[string]evidence.RegisteredKey{}
	m, ok := raw.(map[string]any)
	if !ok {
		t.Fatal("vector must state verification_keys with explicit namespaces")
	}
	for id, val := range m {
		entry, ok := val.(map[string]any)
		if !ok {
			t.Fatalf("verification_keys entry %q must be an object", id)
		}
		ns, ok := entry["namespace"].(string)
		if !ok || ns == "" {
			t.Fatalf("verification_keys entry %q must state namespace", id)
		}
		pk, ok := entry["public_key"].(string)
		if !ok || pk == "" {
			t.Fatalf("verification_keys entry %q must state public_key", id)
		}
		out[id] = evidence.RegisteredKey{
			Namespace: ns,
			PublicKey: ed25519.PublicKey(b64(t, pk)),
		}
	}
	return out
}

func TestVectors(t *testing.T) {
	vf := loadVectors(t)
	if vf.Format != "evidence-control-plane-conformance-vectors" {
		t.Fatalf("unexpected corpus format %q", vf.Format)
	}
	if vf.FormatVersion != "1.3.0" {
		t.Fatalf("unexpected corpus format version %q", vf.FormatVersion)
	}
	seen := map[string]bool{}
	all := make([]map[string]any, 0, len(vf.Vectors)+len(vf.AdversarialVectors))
	all = append(all, vf.Vectors...)
	all = append(all, vf.AdversarialVectors...)
	for _, v := range all {
		id, _ := v["id"].(string)
		op, _ := v["operation"].(string)
		if seen[id] {
			t.Fatalf("duplicate vector id %q", id)
		}
		seen[id] = true
		t.Run(id, func(t *testing.T) { runVector(t, id, op, v) })
	}
	t.Logf("executed %d agreement and %d adversarial vectors",
		len(vf.Vectors), len(vf.AdversarialVectors))
}

func runVector(t *testing.T, id, op string, v map[string]any) {
	switch op {
	case "canonicalize":
		runCanonicalize(t, id, v)
	case "sign_record":
		runSignRecord(t, id, v)
	case "validate_record":
		runValidateRecord(t, id, v)
	case "verify_signature":
		runVerifySignature(t, id, v)
	case "verify_attestation_signatures":
		runVerifyAttestation(t, id, v)
	case "verify_stream":
		runVerifyStream(t, id, v)
	case "verify_ingestion_receipt":
		runVerifyReceipt(t, id, v)
	case "verify_evidence_record_signature":
		runVerifyEvidenceRecordSignature(t, id, v)
	case "verify_record_origin_signature":
		runVerifyRecordOriginSignature(t, id, v)
	case "verify_canonical_evidence_record":
		runVerifyCanonicalWire(t, id, v)
	case "verify_bundle":
		runVerifyBundle(t, id, v)
	default:
		t.Fatalf("%s: unimplemented vector operation %q — a conformance runner "+
			"that skips an operation reports a pass it did not earn", id, op)
	}
}

type fixedResponse struct {
	status int
	body   []byte
}

func (r fixedResponse) Fetch(context.Context, string) (int, []byte, error) {
	return r.status, r.body, nil
}

func bundleErrorCode(err error) string {
	if err == nil {
		return ""
	}
	code, _, _ := strings.Cut(err.Error(), ":")
	return code
}

func normalizedVerdict(v bundle.Verdict) string {
	if v == bundle.Indeterminate {
		return "unchecked"
	}
	return v.String()
}

func normalizedUnchecked(values []string) []string {
	out := map[string]bool{}
	for _, value := range values {
		switch {
		case strings.Contains(value, "capped_by_class"):
			out["coverage.capped_by_class"] = true
		case strings.Contains(value, "count_conservation"):
			out["coverage.count_conservation"] = true
		case strings.Contains(value, "assertions:"):
			for i := 1; i <= 10; i++ {
				id := fmt.Sprintf("A-%02d", i)
				if strings.Contains(value, id) {
					out["assertion.payload:"+id] = true
				}
			}
		}
	}
	result := make([]string, 0, len(out))
	for value := range out {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func decodedExpected(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func runVerifyBundle(t *testing.T, id string, v map[string]any) {
	t.Helper()
	hexWire, ok := v["bundle_utf8_hex"].(string)
	if !ok {
		t.Fatalf("%s: verify_bundle carries no bundle_utf8_hex", id)
	}
	wire, err := hex.DecodeString(hexWire)
	if err != nil {
		t.Fatalf("%s: bundle_utf8_hex: %v", id, err)
	}
	evaluated, ok := v["evaluated_at"].(string)
	if !ok {
		t.Fatalf("%s: verify_bundle carries no evaluated_at", id)
	}
	at, err := time.Parse(time.RFC3339, evaluated)
	if err != nil {
		t.Fatalf("%s: evaluated_at: %v", id, err)
	}

	got := map[string]any{
		"accepted":          false,
		"verdict":           "invalid",
		"evaluated_at":      at.UTC().Format("2006-01-02T15:04:05.000Z"),
		"revocation_status": "unchecked",
		"coverage_ratio":    nil,
		"unchecked":         []string{},
	}
	parsed, parseErr := bundle.Parse(wire)
	if parseErr != nil {
		got["error_codes"] = []string{bundleErrorCode(parseErr)}
		compareBundleVectorResult(t, id, got, expectedOf(v))
		return
	}

	checker := revocation.Checker{IssuerKeys: registeredKeyring(t, v["verification_keys"]),
		Now: func() time.Time { return at }}
	if response, ok := v["revocation_response"].(map[string]any); ok {
		status, statusOK := response["status_code"].(float64)
		if !statusOK {
			t.Fatalf("%s: revocation_response has no numeric status_code", id)
		}
		var body []byte
		if bodyHex, ok := response["body_utf8_hex"].(string); ok {
			body, err = hex.DecodeString(bodyHex)
			if err != nil {
				t.Fatalf("%s: revocation body hex: %v", id, err)
			}
		}
		checker.Fetcher = fixedResponse{status: int(status), body: body}
	}
	result := bundle.Verify(context.Background(), parsed, bundle.Options{
		Keys:       registeredKeyring(t, v["verification_keys"]),
		Revocation: checker,
		Checks:     checks.All(),
		Now:        func() time.Time { return at },
	})
	got["accepted"] = result.Verdict != bundle.Invalid
	got["verdict"] = normalizedVerdict(result.Verdict)
	got["revocation_status"] = result.Revocation.Status().String()
	got["unchecked"] = normalizedUnchecked(result.Unresolved)

	if body, bodyErr := parsed.Attestation.Body(); bodyErr == nil {
		if ratio, present := body.Get("coverage_ratio"); present && result.Verdict != bundle.Invalid {
			got["coverage_ratio"] = ratio
		}
	}
	findings := make([]string, 0, len(result.Findings))
	seen := map[string]bool{}
	for _, finding := range result.Findings {
		if !seen[finding.Code] {
			findings = append(findings, finding.Code)
			seen[finding.Code] = true
		}
	}
	if len(findings) > 0 {
		got["error_codes"] = findings
	}
	if !seen[bundle.CodeSchemaUnsupported] {
		got["attestation_id"] = result.AttestationID
	}
	if result.Revocation.EffectiveAt != "" &&
		result.Revocation.Reason() == revocation.ReasonNotYetEffective {
		got["pending_revocation_effective_at"] = result.Revocation.EffectiveAt
	}
	if result.Revocation.SupersededBy != "" {
		got["superseding_ref"] = result.Revocation.SupersededBy
	}
	compareBundleVectorResult(t, id, got, expectedOf(v))
}

func compareBundleVectorResult(t *testing.T, id string, got, expected map[string]any) {
	t.Helper()
	normalized := decodedExpected(t, got)
	if !reflect.DeepEqual(normalized, expected) {
		gotJSON, _ := json.MarshalIndent(normalized, "", "  ")
		wantJSON, _ := json.MarshalIndent(expected, "", "  ")
		t.Fatalf("%s: structured result differs\n got: %s\nwant: %s", id, gotJSON, wantJSON)
	}
}

func runCanonicalize(t *testing.T, id string, v map[string]any) {
	input, _ := v["input_json"].(string)
	got, err := jcs.Canonicalize([]byte(input))
	if !accepted(v) {
		checkRefusal(t, id, err, wantCode(v))
		return
	}
	if err != nil {
		t.Fatalf("%s: expected acceptance, got %v", id, err)
	}
	if want := wantString(v, "canonical_json"); string(got) != want {
		t.Fatalf("%s: canonical bytes differ\n  got  %q\n  want %q", id, got, want)
	}
	if want := wantString(v, "canonical_utf8_hex"); hex.EncodeToString(got) != want {
		t.Fatalf("%s: canonical hex differs\n  got  %s\n  want %s",
			id, hex.EncodeToString(got), want)
	}
	if want := wantString(v, "digest"); jcs.Digest(got) != want {
		t.Fatalf("%s: digest differs\n  got  %s\n  want %s", id, jcs.Digest(got), want)
	}
}

func runValidateRecord(t *testing.T, id string, v map[string]any) {
	_, err := evidence.ParseRecord(remarshal(t, v["record"]))
	if !accepted(v) {
		checkRefusal(t, id, err, wantCode(v))
		return
	}
	if err != nil {
		t.Fatalf("%s: expected acceptance, got %v", id, err)
	}
}

// runSignRecord reproduces a signature from the published seed. Verifying a
// stored signature would only prove Ed25519 works; reproducing it proves the
// Go writer reaches the same signing input, which is where implementations
// actually diverge.
func runSignRecord(t *testing.T, id string, v map[string]any) {
	seed, _ := v["private_key_seed"].(string)
	keyID, _ := v["key_id"].(string)
	priv := ed25519.NewKeyFromSeed(b64(t, seed))

	unsignedBytes := remarshal(t, v["unsigned_record"])
	parsed, err := jcs.Parse(unsignedBytes)
	if err != nil {
		t.Fatalf("%s: parse unsigned record: %v", id, err)
	}
	obj, ok := parsed.(*jcs.Object)
	if !ok {
		t.Fatalf("%s: unsigned record is not an object", id)
	}
	// ES-021: the signing input is the canonical record with signature excluded.
	signingBytes, err := jcs.Serialize(obj.Without("signature"))
	if err != nil {
		t.Fatalf("%s: serialize signing bytes: %v", id, err)
	}
	signedDigest := jcs.Digest(signingBytes)
	if want := wantString(v, "signed_digest"); signedDigest != want {
		t.Fatalf("%s: signed_digest differs\n  got  %s\n  want %s", id, signedDigest, want)
	}
	sig := ed25519.Sign(priv, jcs.DigestRaw(signingBytes))

	e := expectedOf(v)
	wantSig, _ := e["signature"].(map[string]any)
	gotSigB64 := base64.RawURLEncoding.EncodeToString(sig)
	if want, _ := wantSig["sig"].(string); gotSigB64 != want {
		t.Fatalf("%s: signature differs\n  got  %s\n  want %s", id, gotSigB64, want)
	}
	if want, _ := wantSig["key_id"].(string); want != keyID {
		t.Fatalf("%s: key_id differs", id)
	}

	// Rebuild the complete signed record and check it byte-for-byte.
	signature := jcs.NewObject()
	signature.Set("alg", "ed25519")
	signature.Set("key_id", keyID)
	signature.Set("sig", gotSigB64)
	signature.Set("signed_digest", signedDigest)
	complete := jcs.NewObject()
	for _, k := range obj.Keys() {
		if k == "signature" {
			continue
		}
		val, _ := obj.Get(k)
		complete.Set(k, val)
	}
	complete.Set("signature", signature)
	completeBytes, err := jcs.Serialize(complete)
	if err != nil {
		t.Fatalf("%s: serialize signed record: %v", id, err)
	}
	if wantRecord, ok := e["signed_record"]; ok {
		want := string(canonicalOf(t, id, wantRecord))
		if string(completeBytes) != want {
			t.Fatalf("%s: signed record bytes differ\n  got  %s\n  want %s",
				id, completeBytes, want)
		}
	}
	if want := wantString(v, "signed_record_digest"); want != "" {
		if got := jcs.Digest(completeBytes); got != want {
			t.Fatalf("%s: signed record digest differs\n  got  %s\n  want %s", id, got, want)
		}
	}
}

func canonicalOf(t *testing.T, id string, v any) []byte {
	t.Helper()
	b, err := jcs.Canonicalize(remarshal(t, v))
	if err != nil {
		t.Fatalf("%s: canonicalise expected record: %v", id, err)
	}
	return b
}

func runVerifySignature(t *testing.T, id string, v map[string]any) {
	rec, err := evidence.ParseRecord(remarshal(t, v["record"]))
	if err != nil {
		if !accepted(v) {
			checkRefusal(t, id, err, wantCode(v))
			return
		}
		t.Fatalf("%s: parse record: %v", id, err)
	}
	_, err = evidence.VerifyRecordSignature(rec, keyring(t, v["public_keys"]))
	if !accepted(v) {
		checkRefusal(t, id, err, wantCode(v))
		return
	}
	if err != nil {
		t.Fatalf("%s: expected acceptance, got %v", id, err)
	}
}

func runVerifyEvidenceRecordSignature(t *testing.T, id string, v map[string]any) {
	rec, err := evidence.ParseRecord(remarshal(t, v["record"]))
	if err != nil {
		if !accepted(v) {
			checkRefusal(t, id, err, wantCode(v))
			return
		}
		t.Fatalf("%s: parse record: %v", id, err)
	}
	_, err = evidence.VerifyEvidenceRecordSignature(rec, registeredKeyring(t, v["verification_keys"]))
	if !accepted(v) {
		checkRefusal(t, id, err, wantCode(v))
		return
	}
	if err != nil {
		t.Fatalf("%s: expected acceptance, got %v", id, err)
	}
}

func runVerifyRecordOriginSignature(t *testing.T, id string, v map[string]any) {
	rec, err := evidence.ParseRecord(remarshal(t, v["record"]))
	if err != nil {
		if !accepted(v) {
			checkRefusal(t, id, err, wantCode(v))
			return
		}
		t.Fatalf("%s: parse record: %v", id, err)
	}
	keyID, err := evidence.VerifyRecordOriginSignature(
		rec, registeredKeyring(t, v["verification_keys"]))
	if !accepted(v) {
		checkRefusal(t, id, err, wantCode(v))
		return
	}
	if err != nil {
		t.Fatalf("%s: expected acceptance, got %v", id, err)
	}
	if want := wantString(v, "key_id"); want != "" && keyID != want {
		t.Fatalf("%s: key id %s != %s", id, keyID, want)
	}
}

func runVerifyCanonicalWire(t *testing.T, id string, v map[string]any) {
	var wire []byte
	var err error
	if record, ok := v["record"]; ok {
		wire = remarshal(t, record)
	} else {
		wireHex, _ := v["received_wire_utf8_hex"].(string)
		wire, err = hex.DecodeString(wireHex)
		if err != nil {
			t.Fatalf("%s: decode wire hex: %v", id, err)
		}
	}
	_, err = evidence.VerifyCanonicalEvidenceRecord(wire, registeredKeyring(t, v["verification_keys"]))
	if !accepted(v) {
		checkRefusal(t, id, err, wantCode(v))
		return
	}
	if err != nil {
		t.Fatalf("%s: expected acceptance, got %v", id, err)
	}
	// The control bytes must be accepted, or the refusal above proves nothing
	// about canonicality specifically.
	if ctrlHex, ok := v["canonical_control_utf8_hex"].(string); ok {
		ctrl, err := hex.DecodeString(ctrlHex)
		if err != nil {
			t.Fatalf("%s: decode control hex: %v", id, err)
		}
		if _, err := evidence.VerifyCanonicalEvidenceRecord(ctrl,
			registeredKeyring(t, v["verification_keys"])); err != nil {
			t.Fatalf("%s: canonical control record was refused: %v", id, err)
		}
	}
}

func runVerifyAttestation(t *testing.T, id string, v map[string]any) {
	rec, err := evidence.ParseRecord(remarshal(t, v["record"]))
	if err != nil {
		if !accepted(v) {
			checkRefusal(t, id, err, wantCode(v))
			return
		}
		t.Fatalf("%s: parse record: %v", id, err)
	}
	evKeyID, isKeyID, err := evidence.VerifyAttestationSignatures(rec,
		keyring(t, v["evidence_public_keys"]), keyring(t, v["issuer_public_keys"]))
	if !accepted(v) {
		checkRefusal(t, id, err, wantCode(v))
		return
	}
	if err != nil {
		t.Fatalf("%s: expected acceptance, got %v", id, err)
	}
	if want := wantString(v, "evidence_key_id"); want != "" && evKeyID != want {
		t.Fatalf("%s: evidence key id %s != %s", id, evKeyID, want)
	}
	if want := wantString(v, "issuer_key_id"); want != "" && isKeyID != want {
		t.Fatalf("%s: issuer key id %s != %s", id, isKeyID, want)
	}
	if want := wantString(v, "record_digest"); want != "" {
		got, err := rec.CompleteDigest()
		if err != nil {
			t.Fatalf("%s: complete digest: %v", id, err)
		}
		if got != want {
			t.Fatalf("%s: record digest differs\n  got  %s\n  want %s", id, got, want)
		}
	}
}

func runVerifyStream(t *testing.T, id string, v map[string]any) {
	rawRecords, _ := v["records"].([]any)
	records := make([]*evidence.Record, 0, len(rawRecords))
	for i, raw := range rawRecords {
		rec, err := evidence.ParseRecord(remarshal(t, raw))
		if err != nil {
			if !accepted(v) {
				// Previously this branch checked the code alone and returned,
				// so a vector pinning the break position was satisfied by any
				// parse-time error carrying the right code.
				checkStreamRefusal(t, id, err, v)
				return
			}
			t.Fatalf("%s: parse record %d: %v", id, i, err)
		}
		records = append(records, rec)
	}
	keys := registeredKeyring(t, v["verification_keys"])
	res, err := evidence.VerifyEvidenceStream(records, keys)
	if !accepted(v) {
		checkStreamRefusal(t, id, err, v)
		return
	}
	if err != nil {
		t.Fatalf("%s: expected acceptance, got %v", id, err)
	}
	e := expectedOf(v)
	if want, ok := e["start_sequence"].(float64); ok && res.StartSequence != int64(want) {
		t.Fatalf("%s: start_sequence %d != %d", id, res.StartSequence, int64(want))
	}
	if want, ok := e["end_sequence"].(float64); ok && res.EndSequence != int64(want) {
		t.Fatalf("%s: end_sequence %d != %d", id, res.EndSequence, int64(want))
	}
	if want := wantString(v, "last_digest"); want != "" && res.LastDigest != want {
		t.Fatalf("%s: last_digest\n  got  %s\n  want %s", id, res.LastDigest, want)
	}
	if want := wantString(v, "last_key_id"); want != "" && res.LastKeyID != want {
		t.Fatalf("%s: last_key_id %s != %s", id, res.LastKeyID, want)
	}
	// ES-006a: prev_digest must be the signature-inclusive digest. This vector
	// publishes both forms precisely so an implementation that used the
	// signature-excluded one cannot pass.
	if want := wantString(v, "sequence_2_prev_digest"); want != "" {
		got, err := records[0].CompleteDigest()
		if err != nil {
			t.Fatalf("%s: complete digest: %v", id, err)
		}
		if got != want {
			t.Fatalf("%s: sequence 2 prev_digest\n  got  %s\n  want %s", id, got, want)
		}
	}
	if want := wantString(v, "signature_excluded_digest_must_differ"); want != "" {
		got, err := records[0].SignedDigest()
		if err != nil {
			t.Fatalf("%s: signed digest: %v", id, err)
		}
		if got != want {
			t.Fatalf("%s: signature-excluded digest\n  got  %s\n  want %s", id, got, want)
		}
		complete, _ := records[0].CompleteDigest()
		if complete == got {
			t.Fatalf("%s: signature-inclusive and signature-excluded digests are equal; "+
				"ES-006a requires them to differ", id)
		}
	}
}

func runVerifyReceipt(t *testing.T, id string, v map[string]any) {
	rec, err := evidence.ParseRecord(remarshal(t, v["record"]))
	if err != nil {
		if !accepted(v) {
			checkRefusal(t, id, err, wantCode(v))
			return
		}
		t.Fatalf("%s: parse record: %v", id, err)
	}
	rawReceipt, _ := v["receipt"].(map[string]any)
	canonHex, _ := rawReceipt["canonical_utf8_hex"].(string)
	canonical, err := hex.DecodeString(canonHex)
	if err != nil {
		t.Fatalf("%s: decode receipt hex: %v", id, err)
	}
	keyID, _ := rawReceipt["key_id"].(string)
	sigB64, _ := rawReceipt["signature"].(string)
	receipt := evidence.SignedReceipt{
		CanonicalBytes: canonical,
		KeyID:          keyID,
		Signature:      b64(t, sigB64),
	}
	payload, err := evidence.VerifyIngestionReceipt(receipt, rec,
		registeredKeyring(t, v["verification_keys"]))
	if !accepted(v) {
		checkRefusal(t, id, err, wantCode(v))
		return
	}
	if err != nil {
		t.Fatalf("%s: expected acceptance, got %v", id, err)
	}
	if want := wantString(v, "canonical_json"); want != "" && string(canonical) != want {
		t.Fatalf("%s: receipt canonical json differs", id)
	}
	if want := wantString(v, "digest"); want != "" {
		if got := jcs.Digest(canonical); got != want {
			t.Fatalf("%s: receipt digest\n  got  %s\n  want %s", id, got, want)
		}
	}
	if want := wantString(v, "record_digest"); want != "" && payload.RecordDigest != want {
		t.Fatalf("%s: receipt record_digest\n  got  %s\n  want %s", id, payload.RecordDigest, want)
	}
	e := expectedOf(v)
	if want, ok := e["measured_clock_skew_ms"].(float64); ok {
		if payload.ClockSkewMS != int64(want) {
			t.Fatalf("%s: measured clock skew %d != %d (ES-030 truncates toward zero)",
				id, payload.ClockSkewMS, int64(want))
		}
	}
}
