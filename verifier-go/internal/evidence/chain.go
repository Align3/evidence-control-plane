package evidence

import (
	"crypto/ed25519"
	"fmt"

	"github.com/Align3/evidence-control-plane/verifier-go/internal/jcs"
)

// Chain and continuity error codes.
const (
	CodeChainFork               = "chain.fork"
	CodeChainSequenceGap        = "chain.sequence_gap"
	CodeChainPrevDigestMismatch = "chain.prev_digest_mismatch"
	CodeChainStreamMismatch     = "chain.stream_id_mismatch"

	CodeContinuityMissing        = "continuity.missing"
	CodeContinuityUnknownMember  = "continuity.unknown_member"
	CodeContinuityMissingMember  = "continuity.missing_member"
	CodeContinuityTenantMismatch = "continuity.tenant_mismatch"
	CodeContinuityStreamMismatch = "continuity.stream_mismatch"
	CodeContinuitySigInvalid     = "continuity.signature_invalid"
	CodeContinuityFirstRecord    = "continuity.first_record_forbidden"
	CodeContinuityNoKeyChange    = "continuity.no_key_change"
	CodeContinuityKeyMismatch    = "continuity.key_id_mismatch"
	CodeContinuityKeyConflict    = "continuity.registered_key_mismatch"
	CodeContinuityAlgUnsupported = "continuity.algorithm_unsupported"
)

// StreamError reports where a chain stopped being verifiable. CM-017 makes a
// break terminate the window rather than invalidate it wholesale, so the
// sequence that still verified is part of the result, not a detail.
//
// One failure is reported, not a set. Reporting every determinable failure at a
// break is a real improvement and was drafted here, but it is a behavioural
// change that the specification does not yet require and the corpus does not
// yet record; it lands in EV-28, where the specification, the vectors, Python
// and Go move together.
type StreamError struct {
	Code          string
	Msg           string
	BreakSequence int64
	ValidThrough  int64
}

func (e *StreamError) Error() string {
	return fmt.Sprintf("%s at sequence %d: %s", e.Code, e.BreakSequence, e.Msg)
}

// failure is one determinable defect at a break point.
type failure struct {
	code string
	msg  string
}

// breakAt reports the first determinable failure in chain-traversal order.
func breakAt(seq, validThrough int64, failures ...failure) *StreamError {
	for _, f := range failures {
		if f.code != "" {
			return &StreamError{
				Code: f.code, Msg: f.msg,
				BreakSequence: seq, ValidThrough: validThrough,
			}
		}
	}
	return &StreamError{Code: CodeChainSequenceGap, Msg: "unspecified break",
		BreakSequence: seq, ValidThrough: validThrough}
}

// StreamResult describes a fully verified stream.
type StreamResult struct {
	StartSequence int64
	EndSequence   int64
	LastDigest    string
	LastKeyID     string
}

// continuityMembers is the closed member set of ES-024a.
var continuityMembers = map[string]bool{
	"alg": true, "predecessor_key_id": true, "new_key_id": true,
	"new_public_key": true, "tenant_id": true, "stream_id": true, "sig": true,
}

// trustedStreamKey admits one key to a stream, or says why it cannot.
//
// Every key that ever becomes the active signing key passes through here, which
// is the only reason SE-003 holds for a stream rather than for the records
// someone remembered to check. The previous shape — a loop over the declared
// key ids before verification, plus a look at the final key afterwards — left
// two gaps: a key the keyring does not list was skipped by the first check and
// invisible to the second.
//
// asserted is the public key an ES-024a continuity assertion introduced, or nil
// at the sequence-1 trust anchor.
//
// A rotation onto an unlisted key is refused, and that is the substantive
// decision here. The primitive reading of ES-024a is that the predecessor's
// signature is sufficient to trust the successor — and for the *chain* it is:
// the assertion authenticates the new key. It cannot establish the new key's
// namespace, because a namespace is a custody fact about how a key is held,
// stated by the keyring, and no signature made with one key can confer it on
// another. A verifier that accepted the delegation would be reporting SE-003 as
// enforced while the successor's namespace was simply unknown to it. The corpus
// agrees: every rotation vector lists the rotated key in its keyring.
func trustedStreamKey(keys map[string]RegisteredKey, keyID, namespace string,
	asserted ed25519.PublicKey) (ed25519.PublicKey, error) {
	registered, ok := keys[keyID]
	if !ok {
		if asserted == nil {
			return nil, errf(CodeUnknownSigningKey, "no trusted key for %q", keyID)
		}
		return nil, errf(CodeUnknownSigningKey,
			"the rotation to %q is authenticated, but the keyring does not list that "+
				"key and so states no namespace for it; SE-003 is a property of how a "+
				"key is held and cannot be conferred by the key it replaces", keyID)
	}
	if registered.Namespace != namespace {
		return nil, errf(CodeKeyNamespaceMismatch,
			"key %q is in the %q namespace; this stream requires %q keys (ES-033/SE-003)",
			keyID, registered.Namespace, namespace)
	}
	if asserted != nil && !registered.PublicKey.Equal(asserted) {
		return nil, errf(CodeContinuityKeyConflict,
			"the continuity assertion introduces different key material for %q than the "+
				"keyring holds; one key id naming two keys is unresolvable, not a rotation",
			keyID)
	}
	return registered.PublicKey, nil
}

// VerifyEvidenceStream validates links, sequence continuity, forks, and key
// rotation across one stream, in arrival order, and enforces SE-003 on every
// key that authenticates any record in it.
//
// The trust model is per-stream (ES-024a): sequence 1 anchors to the caller's
// trusted keyring, and every later key must be reached by an authenticated
// rotation. Starting a new stream after a tenant rotation proves nothing about
// the old one, so no continuity is inferred across streams.
//
// There is deliberately no namespace-free variant of this function. One existed
// and was exported; the wrapper that added SE-003 around it could be bypassed
// by any caller in the module that reached for the primitive instead, and an
// issuer key authenticating a customer stream is exactly the confusion the two
// namespaces exist to make impossible. A weakening path that is merely
// unattractive is still a path.
func VerifyEvidenceStream(records []*Record, keys map[string]RegisteredKey) (*StreamResult, error) {
	if len(records) == 0 {
		return nil, &StreamError{Code: CodeChainSequenceGap, Msg: "empty stream"}
	}

	// A stream is the records sharing one stream_id (ES-006). Verifying a
	// mixture would compute links and rotations across chains that were never
	// one chain, and report the result as a single verified stream.
	streamID := records[0].StreamID()
	streamNamespace, err := records[0].PrimarySignerNamespace()
	if err != nil {
		return nil, streamErr(err, records[0].Sequence(), 0)
	}
	for _, r := range records {
		if r.StreamID() != streamID {
			return nil, &StreamError{
				Code: CodeChainStreamMismatch, BreakSequence: r.Sequence(),
				Msg: fmt.Sprintf("stream contains records from %q and %q; "+
					"verify one stream at a time", streamID, r.StreamID()),
			}
		}
		recordNamespace, err := r.PrimarySignerNamespace()
		if err != nil {
			return nil, streamErr(err, r.Sequence(), 0)
		}
		if recordNamespace != streamNamespace {
			return nil, &StreamError{
				Code: CodeKeyNamespaceMismatch, BreakSequence: r.Sequence(),
				Msg: fmt.Sprintf("stream changes primary signer namespace from %q to %q; "+
					"ES-033 requires a new stream rather than cross-role continuity",
					streamNamespace, recordNamespace),
			}
		}
	}

	// ES-003: sequence is monotonic within stream_id, starting at 1, no gaps.
	// Without this a stream handed to the verifier starting at 5 verifies
	// clean, and the four records before it are simply not mentioned -- the
	// silent-omission failure the methodology exists to prevent.
	if first := records[0].Sequence(); first != 1 {
		return nil, &StreamError{
			Code: CodeChainSequenceGap, BreakSequence: first, ValidThrough: 0,
			Msg: fmt.Sprintf("stream begins at sequence %d; a stream anchors at 1 "+
				"and everything before this is unaccounted for", first),
		}
	}

	var (
		start        = records[0].Sequence()
		validThrough int64
		prevComplete string
		activeKeyID  string
		activePub    ed25519.PublicKey
		seenSeq      = map[int64]string{}
	)

	for i, r := range records {
		seq := r.Sequence()

		// ES-006: two records at one stream position with differing record_id
		// are a fatal integrity failure, reported rather than resolved. This is
		// checked before anything else because a fork is not a link problem.
		if prevID, seen := seenSeq[seq]; seen {
			if prevID != r.RecordID() {
				return nil, &StreamError{
					Code: CodeChainFork, BreakSequence: seq, ValidThrough: validThrough,
					Msg: "two records occupy this stream position with differing record_id",
				}
			}
			return nil, &StreamError{
				Code: CodeChainFork, BreakSequence: seq, ValidThrough: validThrough,
				Msg: "record replayed at an occupied stream position",
			}
		}
		if i > 0 && seq != records[i-1].Sequence()+1 {
			// ES-008: a gap is detectable and terminates the window here.
			return nil, &StreamError{
				Code: CodeChainSequenceGap, BreakSequence: seq, ValidThrough: validThrough,
				Msg: "sequence is not contiguous with the preceding record",
			}
		}
		seenSeq[seq] = r.RecordID()

		sig, err := r.Signature()
		if err != nil {
			return nil, streamErr(err, seq, validThrough)
		}
		declaredKeyID, _ := objString(sig, "key_id")
		continuityV, hasContinuity := sig.Get("key_continuity")

		// ES-006a: the link is evaluated first, so it leads the report when
		// several failures coincide. It is evaluated *independently* of the key
		// state rather than short-circuiting, because a broken link and an
		// unauthenticated rotation are distinct integrity failures and a
		// relying party needs to see both.
		var linkFail failure
		prev, present := r.PrevDigest()
		switch {
		case i == 0 && present:
			linkFail = failure{CodeChainPrevDigestMismatch,
				"first record of a stream must carry prev_digest null"}
		case i > 0 && !present:
			linkFail = failure{CodeChainPrevDigestMismatch,
				"prev_digest is null but this is not the first record"}
		case i > 0 && prev != prevComplete:
			linkFail = failure{CodeChainPrevDigestMismatch,
				fmt.Sprintf("prev_digest %s does not match the previous complete record %s",
					prev, prevComplete)}
		}

		if i == 0 {
			// Trust anchor. ES-024a forbids a continuity assertion here: there
			// is no predecessor in this stream for it to chain from.
			if hasContinuity {
				return nil, breakAt(seq, validThrough, linkFail, failure{CodeContinuityFirstRecord,
					"sequence 1 anchors to the trusted keyring and must not carry key_continuity"})
			}
			pub, err := trustedStreamKey(keys, declaredKeyID, streamNamespace, nil)
			if err != nil {
				return nil, breakAt(seq, validThrough, linkFail, failure{Code(err), err.Error()})
			}
			activeKeyID, activePub = declaredKeyID, pub
		} else if declaredKeyID != activeKeyID {
			// ES-024: rotation without continuity is a chain break, not a warning.
			if !hasContinuity {
				return nil, breakAt(seq, validThrough, linkFail, failure{CodeContinuityMissing,
					"signing key changed without a key_continuity assertion"})
			}
			newPub, err := verifyContinuity(continuityV, r, activeKeyID, activePub, declaredKeyID)
			if err != nil {
				return nil, breakAt(seq, validThrough, linkFail, failure{Code(err), err.Error()})
			}
			// The assertion authenticates the successor; the keyring is what
			// says it may play the evidence role at all (SE-003).
			pub, err := trustedStreamKey(keys, declaredKeyID, streamNamespace, newPub)
			if err != nil {
				return nil, breakAt(seq, validThrough, linkFail, failure{Code(err), err.Error()})
			}
			activeKeyID, activePub = declaredKeyID, pub
		} else if hasContinuity {
			// ES-024a: an assertion on a record that is not the first after a
			// real key change is rejected, so a replayed proof cannot be parked
			// on an arbitrary record.
			return nil, breakAt(seq, validThrough, linkFail, failure{CodeContinuityNoKeyChange,
				"key_continuity present but the signing key did not change"})
		}

		// A link failure with no accompanying key failure still stops here.
		if linkFail.code != "" {
			return nil, breakAt(seq, validThrough, linkFail)
		}

		if _, err := VerifyRecordSignature(r, map[string]ed25519.PublicKey{activeKeyID: activePub}); err != nil {
			return nil, streamErr(err, seq, validThrough)
		}

		complete, err := r.CompleteDigest()
		if err != nil {
			return nil, streamErr(err, seq, validThrough)
		}
		prevComplete = complete
		validThrough = seq
	}

	return &StreamResult{
		StartSequence: start,
		EndSequence:   validThrough,
		LastDigest:    prevComplete,
		LastKeyID:     activeKeyID,
	}, nil
}

func streamErr(err error, seq, validThrough int64) *StreamError {
	return &StreamError{
		Code: Code(err), Msg: err.Error(),
		BreakSequence: seq, ValidThrough: validThrough,
	}
}

// verifyContinuity checks the ES-024a assertion carried on the first record
// signed by a new key, and returns the newly trusted public key.
//
// The assertion sits inside signature, so the carrying record's own
// signed_digest does not cover it. What authenticates it is the predecessor's
// signature over the other six members; what commits it is the next record's
// prev_digest under ES-006a.
func verifyContinuity(v jcs.Value, r *Record, predecessorKeyID string,
	predecessorPub ed25519.PublicKey, declaredKeyID string) (ed25519.PublicKey, error) {
	cont, ok := v.(*jcs.Object)
	if !ok {
		return nil, errf(jcs.CodeMalformed, "key_continuity must be an object")
	}
	for _, k := range cont.Keys() {
		if !continuityMembers[k] {
			return nil, errf(CodeContinuityUnknownMember,
				"unknown key_continuity member %q (ES-024a)", k)
		}
	}
	for k := range continuityMembers {
		if !cont.Has(k) {
			return nil, errf(CodeContinuityMissingMember,
				"missing key_continuity member %q (ES-024a)", k)
		}
	}
	if alg, _ := objString(cont, "alg"); alg != algorithm {
		return nil, errf(CodeContinuityAlgUnsupported,
			"key_continuity alg must be %q (ES-022)", algorithm)
	}
	// Context binding. Without these two checks a valid proof from one tenant
	// or stream could be replayed into another.
	if got, _ := objString(cont, "tenant_id"); got != r.TenantID() {
		return nil, errf(CodeContinuityTenantMismatch,
			"continuity tenant_id %q does not match the carrying record %q", got, r.TenantID())
	}
	if got, _ := objString(cont, "stream_id"); got != r.StreamID() {
		return nil, errf(CodeContinuityStreamMismatch,
			"continuity stream_id %q does not match the carrying record %q", got, r.StreamID())
	}
	if got, _ := objString(cont, "new_key_id"); got != declaredKeyID {
		return nil, errf(CodeContinuityKeyMismatch,
			"continuity new_key_id %q does not match the signing key %q", got, declaredKeyID)
	}
	if got, _ := objString(cont, "predecessor_key_id"); got != predecessorKeyID {
		return nil, errf(CodeContinuityKeyMismatch,
			"continuity predecessor_key_id %q is not the outgoing key %q", got, predecessorKeyID)
	}
	newPubB64, _ := objString(cont, "new_public_key")
	newPubRaw, err := decodeUnpadded(newPubB64, ed25519.PublicKeySize)
	if err != nil {
		return nil, err
	}
	sigB64, _ := objString(cont, "sig")
	sigRaw, err := decodeUnpadded(sigB64, ed25519.SignatureSize)
	if err != nil {
		return nil, err
	}
	signed, err := jcs.Serialize(cont.Without("sig"))
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(predecessorPub, signed, sigRaw) {
		return nil, errf(CodeContinuitySigInvalid,
			"predecessor key %q did not sign this continuity assertion", predecessorKeyID)
	}
	return ed25519.PublicKey(newPubRaw), nil
}
