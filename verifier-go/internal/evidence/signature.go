package evidence

import (
	"crypto/ed25519"
	"encoding/base64"

	"github.com/Align3/evidence-control-plane/verifier-go/internal/jcs"
)

// algorithm is the only value ES-022 permits in v0.1. Agility means the field
// exists for a future migration, not that a verifier negotiates: anything else
// is refused rather than attempted.
const algorithm = "ed25519"

// Namespaces are structurally distinct per SE-003. ES-033 dispatches which
// namespace may authenticate a record from its type; the caller never chooses.
const (
	NamespaceEvidence = "evidence"
	NamespaceIssuer   = "issuer"
)

// RegisteredKey is a public key together with the namespace that bounds the
// role it may play.
type RegisteredKey struct {
	Namespace string
	PublicKey ed25519.PublicKey
}

// customerSignatureMembers is the closed member set of ES-021a.
var customerSignatureMembers = map[string]bool{
	"alg": true, "key_id": true, "sig": true, "signed_digest": true,
}

// issuerSignatureMembers is the nested ES-023 counter-signature member set.
var issuerSignatureMembers = map[string]bool{
	"alg": true, "key_id": true, "sig": true, "signed_digest": true,
}

// decodeUnpadded decodes base64url without padding. ES-021 specifies unpadded,
// so a padded string is a distinct encoding of the same bytes and is refused —
// otherwise one signature would have two spellings.
func decodeUnpadded(s string, want int) ([]byte, error) {
	// Reject anything outside the base64url alphabet before decoding. Go's
	// decoder tolerates embedded newlines, so whitespace inside a signature
	// would otherwise decode to the same bytes under a different spelling.
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_':
		default:
			return nil, errf(CodeEncodingInvalid,
				"value contains %q, which is not base64url", string(c))
		}
	}
	// Strict() additionally requires the trailing bits of the final quantum to
	// be zero. Without it several distinct strings decode to one byte sequence,
	// so a signature would have more than one valid spelling.
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, errf(CodeEncodingInvalid, "value is not unpadded base64url: %v", err)
	}
	if want > 0 && len(raw) != want {
		return nil, errf(CodeEncodingInvalid, "expected %d bytes, got %d", want, len(raw))
	}
	return raw, nil
}

// checkMembers enforces a closed member set, distinguishing missing from
// unknown because ES-021a requires a verifier to reject either rather than
// ignore it, and the vectors separate the two codes.
func checkMembers(obj *jcs.Object, allowed, required map[string]bool,
	extraAllowed map[string]bool, unknownCode, missingCode string) error {
	for _, k := range obj.Keys() {
		if allowed[k] || (extraAllowed != nil && extraAllowed[k]) {
			continue
		}
		return errf(unknownCode, "unknown signature member %q (ES-021a)", k)
	}
	for k := range required {
		if !obj.Has(k) {
			return errf(missingCode, "missing signature member %q (ES-021a)", k)
		}
	}
	return nil
}

func objString(obj *jcs.Object, key string) (string, bool) {
	v, ok := obj.Get(key)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// VerifyRecordSignature validates the customer signature and returns the
// signing key id. It does not consider namespaces; see
// VerifyEvidenceRecordSignature for the SE-003 check.
func VerifyRecordSignature(r *Record, keys map[string]ed25519.PublicKey) (string, error) {
	sig, err := r.Signature()
	if err != nil {
		return "", err
	}
	// An AttestationWindow may additionally carry the ES-023 issuer
	// counter-signature; a plain record may not. key_continuity is permitted
	// only where ES-024a asserts a rotation, which chain verification checks.
	extra := map[string]bool{"key_continuity": true}
	if r.RecordType() == "AttestationWindow" {
		extra["issuer"] = true
	}
	if err := checkMembers(sig, customerSignatureMembers, customerSignatureMembers,
		extra, CodeUnknownCustomerMember, CodeMissingCustomerMember); err != nil {
		return "", err
	}
	keyID, err := verifyOneSignature(r, sig, keys, CodeUnknownCustomerMember)
	if err != nil {
		return "", err
	}
	return keyID, nil
}

// verifyOneSignature checks alg, encoding, signed_digest and the Ed25519 proof
// over the ES-021 signing bytes.
func verifyOneSignature(r *Record, sig *jcs.Object,
	keys map[string]ed25519.PublicKey, _ string) (string, error) {
	alg, ok := objString(sig, "alg")
	if !ok {
		return "", errf(CodeMissingCustomerMember, "signature.alg must be a string")
	}
	if alg != algorithm {
		return "", errf(CodeAlgorithmUnsupported,
			"alg %q is not supported; v0.1 rejects rather than negotiates (ES-022)", alg)
	}
	keyID, ok := objString(sig, "key_id")
	if !ok {
		return "", errf(CodeMissingCustomerMember, "signature.key_id must be a string")
	}
	sigB64, ok := objString(sig, "sig")
	if !ok {
		return "", errf(CodeMissingCustomerMember, "signature.sig must be a string")
	}
	raw, err := decodeUnpadded(sigB64, ed25519.SignatureSize)
	if err != nil {
		return "", err
	}
	declared, ok := objString(sig, "signed_digest")
	if !ok {
		return "", errf(CodeMissingCustomerMember, "signature.signed_digest must be a string")
	}
	signing, err := r.SigningBytes()
	if err != nil {
		return "", err
	}
	if got := jcs.Digest(signing); got != declared {
		return "", errf(CodeSignedDigestMismatch,
			"signed_digest %s does not match the canonical record (%s)", declared, got)
	}
	pub, ok := keys[keyID]
	if !ok {
		return "", errf(CodeUnknownSigningKey, "no public key for key_id %q", keyID)
	}
	// The signing input is the bare 32-byte digest, not the canonical bytes.
	// ES-021 does not say which; the normative vectors do (ES-029). See the
	// spec-gap note in the EV-05 PR.
	if !ed25519.Verify(pub, jcs.DigestRaw(signing), raw) {
		return "", errf(CodeSignatureInvalid, "Ed25519 verification failed for key %q", keyID)
	}
	return keyID, nil
}

// VerifyEvidenceRecordSignature retains the pre-ES-033 API name while applying
// the closed primary-signer dispatch. Keeping its former evidence-only
// semantics would make this exported function a namespace bypass for issuer
// observations.
//
// This answers a question about one signature, not a verdict on the record, and
// the two differ for any type ES-023 gives a second signature to. It exists
// because the corpus defines verify_evidence_record_signature as exactly this
// operation. Verify a record with VerifyEvidenceRecord, which dispatches on
// record_type and checks every signature the type requires.
func VerifyEvidenceRecordSignature(r *Record, keys map[string]RegisteredKey) (string, error) {
	return VerifyRecordOriginSignature(r, keys)
}

// VerifyRecordOriginSignature verifies the primary proof and enforces the
// closed record-type namespace dispatch in ES-033.
func VerifyRecordOriginSignature(r *Record, keys map[string]RegisteredKey) (string, error) {
	plain := make(map[string]ed25519.PublicKey, len(keys))
	for id, k := range keys {
		plain[id] = k.PublicKey
	}
	keyID, err := VerifyRecordSignature(r, plain)
	if err != nil {
		return "", err
	}
	want, err := r.PrimarySignerNamespace()
	if err != nil {
		return "", err
	}
	if keys[keyID].Namespace != want {
		return "", errf(CodeKeyNamespaceMismatch,
			"key %q is in the %q namespace; %s requires a %q primary signer (ES-033)",
			keyID, keys[keyID].Namespace, r.RecordType(), want)
	}
	return keyID, nil
}

// VerifyAttestationSignatures validates the two structurally distinct
// signatures of ES-023: the customer's over the record, and the issuer's
// counter-signature. Both closed member sets are enforced (ES-021a).
func VerifyAttestationSignatures(r *Record,
	evidenceKeys, issuerKeys map[string]ed25519.PublicKey) (string, string, error) {
	sig, err := r.Signature()
	if err != nil {
		return "", "", err
	}
	evidenceKeyID, err := VerifyRecordSignature(r, evidenceKeys)
	if err != nil {
		return "", "", err
	}
	issuerV, ok := sig.Get("issuer")
	if !ok {
		return "", "", errf(CodeMissingIssuerMember,
			"attestation is missing the issuer counter-signature (ES-023)")
	}
	issuer, ok := issuerV.(*jcs.Object)
	if !ok {
		return "", "", errf(jcs.CodeMalformed, "signature.issuer must be an object")
	}
	if err := checkMembers(issuer, issuerSignatureMembers, issuerSignatureMembers,
		nil, CodeUnknownIssuerMember, CodeMissingIssuerMember); err != nil {
		return "", "", err
	}
	alg, _ := objString(issuer, "alg")
	if alg != algorithm {
		return "", "", errf(CodeAlgorithmUnsupported,
			"issuer alg %q is not supported (ES-022)", alg)
	}
	issuerKeyID, _ := objString(issuer, "key_id")
	sigB64, _ := objString(issuer, "sig")
	raw, err := decodeUnpadded(sigB64, ed25519.SignatureSize)
	if err != nil {
		return "", "", err
	}
	// The issuer counter-signs the record carrying the customer signature but
	// not the issuer member itself, which cannot commit to its own bytes.
	signing, err := jcs.Serialize(withoutIssuer(r))
	if err != nil {
		return "", "", err
	}
	declared, _ := objString(issuer, "signed_digest")
	if got := jcs.Digest(signing); got != declared {
		return "", "", errf(CodeSignedDigestMismatch,
			"issuer signed_digest %s does not match (%s)", declared, got)
	}
	pub, ok := issuerKeys[issuerKeyID]
	if !ok {
		return "", "", errf(CodeUnknownSigningKey, "no issuer public key for %q", issuerKeyID)
	}
	if !ed25519.Verify(pub, jcs.DigestRaw(signing), raw) {
		return "", "", errf(CodeSignatureInvalid,
			"issuer Ed25519 verification failed for key %q", issuerKeyID)
	}
	return evidenceKeyID, issuerKeyID, nil
}

// withoutIssuer rebuilds the record with signature.issuer removed.
func withoutIssuer(r *Record) *jcs.Object {
	out := jcs.NewObject()
	for _, k := range r.Obj.Keys() {
		v, _ := r.Obj.Get(k)
		if k != "signature" {
			out.Set(k, v)
			continue
		}
		sig, ok := v.(*jcs.Object)
		if !ok {
			out.Set(k, v)
			continue
		}
		out.Set(k, sig.Without("issuer"))
	}
	return out
}
