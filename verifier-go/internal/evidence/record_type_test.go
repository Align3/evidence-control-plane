package evidence

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/Align3/evidence-control-plane/verifier-go/internal/jcs"
)

// attestationBody is the §5.13 body, complete. Tests below remove or relabel
// exactly one thing about a record carrying it.
func attestationBody() map[string]any {
	return map[string]any{
		"boundary_ref":           "boundary-1",
		"window_start":           "2026-08-01T00:00:00.000Z",
		"window_end":             "2026-08-01T23:59:59.999Z",
		"methodology_version":    "1.0.0",
		"denominator_class":      "C1",
		"population_record_refs": []any{},
		"coverage_level":         "observed",
		"verification_status":    "self_computed",
		"coverage_ratio":         "1.0",
		"counts":                 map[string]any{},
		"gaps":                   []any{},
		"assertions":             []any{},
		"exclusions":             []any{},
		"relying_parties":        []any{},
		"validity_from":          "2026-08-01T12:00:00.000Z",
		"validity_until":         "2026-09-01T12:00:00.000Z",
		"liability_ref":          "terms-1",
		"issued_at":              "2026-08-01T12:00:00.000Z",
		"issuer":                 "issuer-1",
		"verifier_version":       "0.1.0",
	}
}

// signAs re-signs a record map and returns the parsed record. Use signBytes
// where the record under test is one this verifier must refuse: parsing is part
// of what refuses it, and an attacker's record does not have to survive it.
func signAs(t *testing.T, rec map[string]any, keyID string,
	priv ed25519.PrivateKey, continuity map[string]any) *Record {
	t.Helper()
	r, err := ParseRecord(signBytes(t, rec, keyID, priv, continuity))
	if err != nil {
		t.Fatalf("signed record did not parse: %v", err)
	}
	return r
}

// signBytes produces the canonical wire form of a record signed by key, with
// any signature it already carried replaced. The continuity assertion, when
// supplied, is placed inside the signature member per ES-024a.
func signBytes(t *testing.T, rec map[string]any, keyID string,
	priv ed25519.PrivateKey, continuity map[string]any) []byte {
	t.Helper()
	rec["signature"] = map[string]any{
		"alg": algorithm, "key_id": keyID, "sig": "", "signed_digest": "",
	}
	obj := parseObject(t, rec)
	// ES-021: the signing input excludes the whole signature member, so the
	// placeholder above cannot affect what is signed.
	signing, err := jcs.Serialize(obj.Without("signature"))
	if err != nil {
		t.Fatal(err)
	}
	signature := map[string]any{
		"alg":           algorithm,
		"key_id":        keyID,
		"sig":           base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, jcs.DigestRaw(signing))),
		"signed_digest": jcs.Digest(signing),
	}
	if continuity != nil {
		signature["key_continuity"] = continuity
	}
	rec["signature"] = signature
	wire, err := jcs.Serialize(parseObject(t, rec))
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func parseObject(t *testing.T, rec map[string]any) *jcs.Object {
	t.Helper()
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	v, err := jcs.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	obj, ok := v.(*jcs.Object)
	if !ok {
		t.Fatal("record is not an object")
	}
	return obj
}

// counterSign adds the ES-023 issuer counter-signature over the record carrying
// the customer signature but excluding signature.issuer itself.
func counterSign(t *testing.T, r *Record, issuerKeyID string, priv ed25519.PrivateKey) *Record {
	t.Helper()
	signing, err := jcs.Serialize(withoutIssuer(r))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := r.Signature()
	if err != nil {
		t.Fatal(err)
	}
	issuer := jcs.NewObject()
	issuer.Set("alg", algorithm)
	issuer.Set("key_id", issuerKeyID)
	issuer.Set("sig", base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, jcs.DigestRaw(signing))))
	issuer.Set("signed_digest", jcs.Digest(signing))
	sig.Set("issuer", issuer)
	return r
}

func newKey(t *testing.T, seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	raw := make([]byte, ed25519.SeedSize)
	for i := range raw {
		raw[i] = seed
	}
	priv := ed25519.NewKeyFromSeed(raw)
	return priv.Public().(ed25519.PublicKey), priv
}

// TestUnknownRecordTypeRefused covers the §3 requirement that record_type name
// a §5 type. A validly signed record of an unrecognised type was previously
// accepted: the signature is real, but "this is a valid FutureRecord" is a
// claim about a schema the verifier has never seen.
func TestUnknownRecordTypeRefused(t *testing.T) {
	rec := baseRecord()
	rec["record_type"] = "FutureRecord"
	_, err := parse(t, rec)
	if err == nil || Code(err) != CodeUnknownRecordType {
		t.Fatalf("expected %s, got %v", CodeUnknownRecordType, err)
	}
}

// TestRelabelledBodyRefused is the substitution the type table exists to catch:
// an AttestationWindow body presented under a type that carries no issuer
// counter-signature requirement, re-signed with the customer key that is
// entitled to sign an AgentIdentity. Every coverage claim in that body would
// otherwise be accepted with no issuer proof at all (ES-023).
func TestRelabelledBodyRefused(t *testing.T) {
	pub, priv := newKey(t, 1)
	rec := baseRecord()
	rec["record_type"] = "AgentIdentity"
	rec["body"] = attestationBody()
	wire := signBytes(t, rec, "K1", priv, nil)

	// Through the wire entry point, which is what a relying party runs: the
	// bytes are canonical and the signature over them verifies, so nothing
	// short of the type check refuses this record.
	keys := map[string]RegisteredKey{"K1": {Namespace: NamespaceEvidence, PublicKey: pub}}
	_, err := VerifyCanonicalEvidenceRecord(wire, keys)
	if err == nil || Code(err) != CodeMissingBodyMember {
		t.Fatalf("expected %s, got %v", CodeMissingBodyMember, err)
	}
}

// TestAttestationWindowRequiresIssuerCounterSignature pins the ES-023 dispatch
// in the library rather than in one command. A caller reaching the record entry
// point must not be able to have an attestation verified as a record.
func TestAttestationWindowRequiresIssuerCounterSignature(t *testing.T) {
	evPub, evPriv := newKey(t, 2)
	isPub, isPriv := newKey(t, 3)
	keys := map[string]RegisteredKey{
		"K1": {Namespace: NamespaceEvidence, PublicKey: evPub},
		"I1": {Namespace: NamespaceIssuer, PublicKey: isPub},
	}

	rec := baseRecord()
	rec["record_type"] = "AttestationWindow"
	rec["body"] = attestationBody()
	unsigned := signAs(t, rec, "K1", evPriv, nil)

	// Customer signature alone: real, and not sufficient for this type.
	if _, err := VerifyEvidenceRecord(unsigned, keys); err == nil ||
		Code(err) != CodeMissingIssuerMember {
		t.Fatalf("expected %s, got %v", CodeMissingIssuerMember, err)
	}

	countersigned := counterSign(t, signAs(t, rec, "K1", evPriv, nil), "I1", isPriv)
	verified, err := VerifyEvidenceRecord(countersigned, keys)
	if err != nil {
		t.Fatalf("a complete attestation must verify: %v", err)
	}
	if verified.KeyID != "K1" || verified.IssuerKeyID != "I1" {
		t.Fatalf("verification reported %+v", verified)
	}

	// SE-003 again: the issuer proof is not satisfiable by an evidence key, so
	// one party holding one key cannot produce both signatures.
	evidenceOnly := map[string]RegisteredKey{
		"K1": {Namespace: NamespaceEvidence, PublicKey: evPub},
		"I1": {Namespace: NamespaceEvidence, PublicKey: isPub},
	}
	if _, err := VerifyEvidenceRecord(countersigned, evidenceOnly); err == nil ||
		Code(err) != CodeUnknownSigningKey {
		t.Fatalf("expected %s, got %v", CodeUnknownSigningKey, err)
	}
}

// TestPopulationRecordIdentifierShape covers the one §5 body whose shape is a
// choice rather than a list: CM-002's denominator is either enumerated or
// committed to by digest, and neither "both" nor "neither" states a population.
func TestPopulationRecordIdentifierShape(t *testing.T) {
	body := func() map[string]any {
		return map[string]any{
			"action_family": "email.send", "destination_system": "system-1",
			"window_start":      "2026-08-01T00:00:00.000Z",
			"window_end":        "2026-08-01T23:59:59.999Z",
			"enumeration_query": map[string]any{"api": "list"}, "count": 1,
			"pagination_complete": true, "result_cap_hit": false,
			"retrieved_at":             "2026-08-01T12:00:00.000Z",
			"authoritative_timestamps": map[string]any{},
		}
	}
	digest := "sha256:" + "ab" + "cd"
	for name, mutate := range map[string]func(map[string]any){
		"neither": func(map[string]any) {},
		"both": func(b map[string]any) {
			b["record_identifiers"] = []any{"r-1"}
			b["identifier_digest"] = digest
		},
	} {
		t.Run(name, func(t *testing.T) {
			rec := baseRecord()
			rec["record_type"] = "PopulationRecord"
			b := body()
			mutate(b)
			rec["body"] = b
			_, err := parse(t, rec)
			if err == nil || Code(err) != CodeBodyShapeInvalid {
				t.Fatalf("expected %s, got %v", CodeBodyShapeInvalid, err)
			}
		})
	}

	rec := baseRecord()
	rec["record_type"] = "PopulationRecord"
	b := body()
	b["identifier_digest"] = digest
	rec["body"] = b
	if _, err := parse(t, rec); err != nil {
		t.Fatalf("a digest-committed population must be accepted: %v", err)
	}
}
