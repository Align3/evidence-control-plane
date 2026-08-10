package evidence

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/Align3/evidence-control-plane/verifier-go/internal/jcs"
)

// streamRecord builds record `seq` of stream-1, linked to prev.
func streamRecord(t *testing.T, seq int, prev string, keyID string,
	priv ed25519.PrivateKey, continuity map[string]any) *Record {
	t.Helper()
	rec := baseRecord()
	rec["record_id"] = "01890f47-2f58-7cc0-98c4-00000000000" + string(rune('0'+seq))
	rec["sequence"] = seq
	if prev == "" {
		rec["prev_digest"] = nil
	} else {
		rec["prev_digest"] = prev
	}
	return signAs(t, rec, keyID, priv, continuity)
}

// continuityFor builds the ES-024a assertion the predecessor signs to introduce
// a successor key on stream-1.
func continuityFor(t *testing.T, predecessorKeyID string, predecessorPriv ed25519.PrivateKey,
	newKeyID string, newPub ed25519.PublicKey) map[string]any {
	t.Helper()
	assertion := map[string]any{
		"alg":                algorithm,
		"predecessor_key_id": predecessorKeyID,
		"new_key_id":         newKeyID,
		"new_public_key":     base64.RawURLEncoding.EncodeToString(newPub),
		"tenant_id":          "tenant-1",
		"stream_id":          "stream-1",
	}
	// ES-024a: the predecessor signs the canonical form of the other six
	// members — the canonical bytes themselves, not their digest.
	signed, err := jcs.Serialize(parseObject(t, assertion))
	if err != nil {
		t.Fatal(err)
	}
	assertion["sig"] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(predecessorPriv, signed))
	return assertion
}

// rotatedStream is two records: an anchor signed by K1, and a rotation onto K2
// carrying the continuity assertion that authenticates it.
func rotatedStream(t *testing.T, k1Priv ed25519.PrivateKey,
	k2Pub ed25519.PublicKey, k2Priv ed25519.PrivateKey) []*Record {
	t.Helper()
	first := streamRecord(t, 1, "", "K1", k1Priv, nil)
	link, err := first.CompleteDigest()
	if err != nil {
		t.Fatal(err)
	}
	second := streamRecord(t, 2, link, "K2", k2Priv,
		continuityFor(t, "K1", k1Priv, "K2", k2Pub))
	return []*Record{first, second}
}

// TestStreamRotationRequiresRegisteredEvidenceKey covers the SE-003 hole the
// wrapper left open. The three rotations below are identical to the verifier
// except for what the keyring says about the successor, which is the only place
// a namespace can come from.
func TestStreamRotationRequiresRegisteredEvidenceKey(t *testing.T) {
	k1Pub, k1Priv := newKey(t, 11)
	k2Pub, k2Priv := newKey(t, 12)
	otherPub, _ := newKey(t, 13)
	anchor := RegisteredKey{Namespace: NamespaceEvidence, PublicKey: k1Pub}

	cases := []struct {
		name string
		keys map[string]RegisteredKey
		want string
	}{
		{
			// The case that was accepted as VALID: the keyring never listed K2,
			// so the pre-check skipped it and the post-check found nothing to
			// look at. Nothing anywhere established that K2 may sign evidence.
			name: "successor absent from the keyring",
			keys: map[string]RegisteredKey{"K1": anchor},
			want: CodeUnknownSigningKey,
		},
		{
			name: "successor registered in the issuer namespace",
			keys: map[string]RegisteredKey{
				"K1": anchor,
				"K2": {Namespace: NamespaceIssuer, PublicKey: k2Pub},
			},
			want: CodeKeyNamespaceMismatch,
		},
		{
			// One key id naming two keys. Trusting either would mean the
			// keyring and the stream disagree about what "K2" is.
			name: "successor registered with different key material",
			keys: map[string]RegisteredKey{
				"K1": anchor,
				"K2": {Namespace: NamespaceEvidence, PublicKey: otherPub},
			},
			want: CodeContinuityKeyConflict,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			records := rotatedStream(t, k1Priv, k2Pub, k2Priv)
			_, err := VerifyEvidenceStream(records, tc.keys)
			if err == nil || Code(err) != tc.want {
				t.Fatalf("expected %s, got %v", tc.want, err)
			}
			se, ok := err.(*StreamError)
			if !ok {
				t.Fatalf("a stream refusal must carry its position, got %T", err)
			}
			// CM-017: the anchor still verified, and the window terminates at
			// the rotation rather than being invalidated wholesale.
			if se.BreakSequence != 2 || se.ValidThrough != 1 {
				t.Fatalf("break at %d valid through %d; want 2 and 1",
					se.BreakSequence, se.ValidThrough)
			}
		})
	}

	// The control: with the successor registered as an evidence key, the same
	// rotation verifies. Without this the refusals above would prove only that
	// the stream was unverifiable for some other reason.
	records := rotatedStream(t, k1Priv, k2Pub, k2Priv)
	res, err := VerifyEvidenceStream(records, map[string]RegisteredKey{
		"K1": anchor,
		"K2": {Namespace: NamespaceEvidence, PublicKey: k2Pub},
	})
	if err != nil {
		t.Fatalf("a registered evidence successor must verify: %v", err)
	}
	if res.LastKeyID != "K2" || res.EndSequence != 2 {
		t.Fatalf("stream result %+v", res)
	}
}

// TestStreamAnchorMustBeAnEvidenceKey is SE-S-001 at the stream entry point.
func TestStreamAnchorMustBeAnEvidenceKey(t *testing.T) {
	k1Pub, k1Priv := newKey(t, 14)
	records := []*Record{streamRecord(t, 1, "", "K1", k1Priv, nil)}
	_, err := VerifyEvidenceStream(records, map[string]RegisteredKey{
		"K1": {Namespace: NamespaceIssuer, PublicKey: k1Pub},
	})
	if err == nil || Code(err) != CodeKeyNamespaceMismatch {
		t.Fatalf("expected %s, got %v", CodeKeyNamespaceMismatch, err)
	}
}
