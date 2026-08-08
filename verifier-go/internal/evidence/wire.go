package evidence

import (
	"crypto/ed25519"
	"fmt"

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
func VerifyCanonicalEvidenceRecord(wire []byte, keys map[string]RegisteredKey) (string, error) {
	v, err := jcs.Parse(wire)
	if err != nil {
		return "", err
	}
	canonical, err := jcs.Serialize(v)
	if err != nil {
		return "", err
	}
	if string(canonical) != string(wire) {
		return "", errf(CodeWireNonCanonical,
			"received record is not RFC 8785 canonical (ES-001)")
	}
	obj, ok := v.(*jcs.Object)
	if !ok {
		return "", errf(jcs.CodeMalformed, "record envelope must be a JSON object")
	}
	r := &Record{Obj: obj}
	if err := r.Validate(); err != nil {
		return "", err
	}
	return VerifyEvidenceRecordSignature(r, keys)
}

// VerifyEvidenceStream verifies a stream and enforces SE-003 on every record
// in it: each signing key, including one reached by an authenticated rotation,
// must be in the evidence namespace.
//
// This exists because the namespace-free VerifyStream is a primitive, and a
// caller that reaches for it is silently opting out of SE-003. An issuer key
// authenticating a customer stream is the exact confusion the two namespaces
// exist to make impossible, and it is not made impossible by being unlikely.
func VerifyEvidenceStream(records []*Record, keys map[string]RegisteredKey) (*StreamResult, error) {
	for _, r := range records {
		sig, err := r.Signature()
		if err != nil {
			return nil, err
		}
		keyID, _ := objString(sig, "key_id")
		registered, ok := keys[keyID]
		if !ok {
			// An unknown key is left to VerifyStream, which reports it with the
			// stream position attached.
			continue
		}
		if registered.Namespace != NamespaceEvidence {
			return nil, &StreamError{
				Code: CodeKeyNamespaceMismatch, BreakSequence: r.Sequence(),
				Msg: fmt.Sprintf("record is signed by %q, which is in the %q namespace; "+
					"evidence streams require evidence keys (SE-003)", keyID, registered.Namespace),
			}
		}
	}
	result, err := VerifyStream(records, publicKeyMap(keys))
	if err != nil {
		return nil, err
	}
	// A rotation can introduce a key the keyring never listed; the continuity
	// assertion authenticates it but says nothing about its namespace.
	if registered, ok := keys[result.LastKeyID]; ok && registered.Namespace != NamespaceEvidence {
		return nil, &StreamError{
			Code: CodeKeyNamespaceMismatch, BreakSequence: result.EndSequence,
			Msg: "stream rotated onto a key outside the evidence namespace (SE-003)",
		}
	}
	return result, nil
}

// publicKeyMap narrows a registered keyring to raw keys. Deliberately
// unexported: exporting it invites a caller to drop the namespaces on the way
// into a primitive, which is how SE-003 came to be unenforced on streams.
func publicKeyMap(keys map[string]RegisteredKey) map[string]ed25519.PublicKey {
	out := make(map[string]ed25519.PublicKey, len(keys))
	for id, k := range keys {
		out[id] = k.PublicKey
	}
	return out
}
