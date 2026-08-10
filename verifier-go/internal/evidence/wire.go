package evidence

import (
	"crypto/ed25519"

	"github.com/Align3/evidence-control-plane/verifier-go/internal/jcs"
)

// VerifyCanonicalEvidenceRecord checks the received bytes against ES-001 before
// authenticating anything.
//
// ES-001 requires the comparison to happen and to fail as wire.non_canonical.
// The alternative — silently normalising and then reporting an invalid
// signature — is explicitly forbidden, and for good reason: it converts a
// producer conformance bug into a misleading cryptographic complaint, and it
// means the bytes retained are ours rather than the ones that arrived.
func VerifyCanonicalEvidenceRecord(wire []byte, keys map[string]RegisteredKey) (*RecordVerification, error) {
	v, err := jcs.Parse(wire)
	if err != nil {
		return nil, err
	}
	canonical, err := jcs.Serialize(v)
	if err != nil {
		return nil, err
	}
	if string(canonical) != string(wire) {
		return nil, errf(CodeWireNonCanonical,
			"received record is not RFC 8785 canonical (ES-001)")
	}
	obj, ok := v.(*jcs.Object)
	if !ok {
		return nil, errf(jcs.CodeMalformed, "record envelope must be a JSON object")
	}
	r := &Record{Obj: obj}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return VerifyEvidenceRecord(r, keys)
}

// RecordVerification is what a fully verified record yields: which key signed
// it, and, for a type that requires one, which issuer key counter-signed it.
type RecordVerification struct {
	RecordType  string
	KeyID       string
	IssuerKeyID string
}

// VerifyEvidenceRecord verifies a complete record: the customer signature under
// SE-003, and every further signature the record's type requires.
//
// The dispatch belongs here rather than in a caller. ES-023 gives the
// AttestationWindow a second signature, and a verifier that checks only the
// customer's reports an attestation with its counter-signature stripped as a
// valid record — a true statement about one signature presented as a conclusion
// about the record. Leaving that to "whoever remembers to ask for the issuer
// check" means the answer depends on which entry point a relying party happened
// to call.
func VerifyEvidenceRecord(r *Record, keys map[string]RegisteredKey) (*RecordVerification, error) {
	keyID, err := VerifyEvidenceRecordSignature(r, keys)
	if err != nil {
		return nil, err
	}
	out := &RecordVerification{RecordType: r.RecordType(), KeyID: keyID}
	if r.RecordType() != "AttestationWindow" {
		return out, nil
	}
	// Split by namespace so the issuer proof cannot be satisfied by an evidence
	// key: two signatures from one namespace are one signature (SE-003).
	evidenceKeys := map[string]ed25519.PublicKey{}
	issuerKeys := map[string]ed25519.PublicKey{}
	for id, k := range keys {
		switch k.Namespace {
		case NamespaceEvidence:
			evidenceKeys[id] = k.PublicKey
		case NamespaceIssuer:
			issuerKeys[id] = k.PublicKey
		}
	}
	_, issuerKeyID, err := VerifyAttestationSignatures(r, evidenceKeys, issuerKeys)
	if err != nil {
		return nil, err
	}
	out.IssuerKeyID = issuerKeyID
	return out, nil
}
