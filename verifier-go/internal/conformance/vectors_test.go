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
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Align3/evidence-control-plane/verifier-go/internal/evidence"
	"github.com/Align3/evidence-control-plane/verifier-go/internal/jcs"
)

type vectorFile struct {
	Format        string           `json:"format"`
	FormatVersion string           `json:"format_version"`
	SpecVersion   string           `json:"spec_version"`
	Vectors       []map[string]any `json:"vectors"`
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
		t.Fatal("vector corpus is empty; refusing to report a vacuous pass")
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

// checkRefusal asserts the operation failed with exactly the vector's code.
func checkRefusal(t *testing.T, id string, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected refusal %s, got acceptance", id, want)
	}
	if got := evidence.Code(err); got != want {
		t.Fatalf("%s: expected %s, got %s (%v)", id, want, got, err)
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
	m, _ := raw.(map[string]any)
	for id, val := range m {
		entry, _ := val.(map[string]any)
		ns, _ := entry["namespace"].(string)
		pk, _ := entry["public_key"].(string)
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
	seen := map[string]bool{}
	for _, v := range vf.Vectors {
		id, _ := v["id"].(string)
		op, _ := v["operation"].(string)
		if seen[id] {
			t.Fatalf("duplicate vector id %q", id)
		}
		seen[id] = true
		t.Run(id, func(t *testing.T) { runVector(t, id, op, v) })
	}
	t.Logf("executed %d vectors", len(vf.Vectors))
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
	case "verify_canonical_evidence_record":
		runVerifyCanonicalWire(t, id, v)
	default:
		t.Fatalf("%s: unimplemented vector operation %q — a conformance runner "+
			"that skips an operation reports a pass it did not earn", id, op)
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

func runVerifyCanonicalWire(t *testing.T, id string, v map[string]any) {
	wireHex, _ := v["received_wire_utf8_hex"].(string)
	wire, err := hex.DecodeString(wireHex)
	if err != nil {
		t.Fatalf("%s: decode wire hex: %v", id, err)
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
				checkRefusal(t, id, err, wantCode(v))
				return
			}
			t.Fatalf("%s: parse record %d: %v", id, i, err)
		}
		records = append(records, rec)
	}
	res, err := evidence.VerifyStream(records, keyring(t, v["public_keys"]))
	if !accepted(v) {
		checkRefusal(t, id, err, wantCode(v))
		var se *evidence.StreamError
		if e, ok := err.(*evidence.StreamError); ok {
			se = e
		}
		e := expectedOf(v)
		if bs, ok := e["break_sequence"].(float64); ok && se != nil {
			if se.BreakSequence != int64(bs) {
				t.Fatalf("%s: break_sequence %d != %d", id, se.BreakSequence, int64(bs))
			}
		}
		if vt, ok := e["valid_through_sequence"].(float64); ok && se != nil {
			if se.ValidThrough != int64(vt) {
				t.Fatalf("%s: valid_through_sequence %d != %d", id, se.ValidThrough, int64(vt))
			}
		}
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
