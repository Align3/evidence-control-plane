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

// PublicKeyMap narrows a registered keyring to raw keys, for the paths that do
// not themselves enforce a namespace.
func PublicKeyMap(keys map[string]RegisteredKey) map[string]ed25519.PublicKey {
	out := make(map[string]ed25519.PublicKey, len(keys))
	for id, k := range keys {
		out[id] = k.PublicKey
	}
	return out
}
