// Package evidence verifies signed evidence records, chains, and ingestion
// receipts against evidence-spec.md, independently of the Python writer
// (AC-011). Every rule here is traced to a requirement in the comment above it.
package evidence

import (
	"fmt"

	"github.com/Align3/evidence-control-plane/verifier-go/internal/jcs"
)

// Stable dotted error codes, shared with tests/vectors/ (vectors README).
const (
	CodeUnknownEnvelopeMember  = "schema.unknown_envelope_member"
	CodeMissingEnvelopeMember  = "schema.missing_envelope_member"
	CodeHostedClockFieldForbid = "schema.hosted_clock_field_forbidden"
	CodeWireNonCanonical       = "wire.non_canonical"
	CodeKeyNamespaceMismatch   = "key.namespace_mismatch"
	CodeAlgorithmUnsupported   = "signature.algorithm_unsupported"
	CodeEncodingInvalid        = "signature.encoding_invalid"
	CodeUnknownCustomerMember  = "signature.unknown_customer_member"
	CodeMissingCustomerMember  = "signature.missing_customer_member"
	CodeUnknownIssuerMember    = "signature.unknown_issuer_member"
	CodeMissingIssuerMember    = "signature.missing_issuer_member"
	CodeSignatureInvalid       = "signature.invalid"
	CodeSignedDigestMismatch   = "signature.signed_digest_mismatch"
	CodeUnknownSigningKey      = "signature.unknown_key"
)

// Error carries a stable code. Wording is ours; the code is normative.
type Error struct {
	Code string
	Msg  string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func errf(code, format string, args ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Code extracts the dotted code from any error this package or jcs produces.
func Code(err error) string {
	switch e := err.(type) {
	case *Error:
		return e.Code
	case *jcs.Error:
		return e.Code
	case *StreamError:
		return e.Code
	}
	return ""
}

// envelopeMembers is the closed envelope of evidence-spec.md §3. ES-005 makes
// an unknown member here fatal — deliberately the opposite of body, which
// tolerates unknown members and still digests them.
var envelopeMembers = map[string]bool{
	"record_id":      true,
	"record_type":    true,
	"schema_version": true,
	"tenant_id":      true,
	"boundary_ref":   true,
	"stream_id":      true,
	"sequence":       true,
	"prev_digest":    true,
	"source":         true,
	"clocks":         true,
	"body":           true,
	"signature":      true,
}

// hostedClockFields are observations only the hosted ingestion service can
// make. ES-019: a customer-signed record supplying either is rejected, because
// a collector asserting our receipt time is asserting something it cannot know.
var hostedClockFields = []string{"ingest_time", "clock_skew_ms"}

// Record is a parsed evidence record.
type Record struct {
	Obj *jcs.Object
}

// ParseRecord parses and structurally validates one record.
func ParseRecord(data []byte) (*Record, error) {
	v, err := jcs.Parse(data)
	if err != nil {
		return nil, err
	}
	obj, ok := v.(*jcs.Object)
	if !ok {
		return nil, errf(jcs.CodeMalformed, "record envelope must be a JSON object")
	}
	r := &Record{Obj: obj}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate applies ES-005 (closed envelope, open body) and ES-019 (no hosted
// clock fields in a customer-signed record).
func (r *Record) Validate() error {
	for _, k := range r.Obj.Keys() {
		if !envelopeMembers[k] {
			return errf(CodeUnknownEnvelopeMember,
				"unknown envelope member %q (ES-005)", k)
		}
	}
	for k := range envelopeMembers {
		if !r.Obj.Has(k) {
			return errf(CodeMissingEnvelopeMember, "missing envelope member %q", k)
		}
	}
	clocksV, _ := r.Obj.Get("clocks")
	clocks, ok := clocksV.(*jcs.Object)
	if !ok {
		return errf(jcs.CodeMalformed, "clocks must be an object")
	}
	for _, forbidden := range hostedClockFields {
		if clocks.Has(forbidden) {
			return errf(CodeHostedClockFieldForbid,
				"clocks.%s is a hosted observation and MUST NOT appear in a "+
					"customer-signed record (ES-019)", forbidden)
		}
	}
	if !clocks.Has("source_time") {
		return errf(CodeMissingEnvelopeMember, "clocks.source_time is required (ES-019)")
	}
	return nil
}

func (r *Record) str(key string) string {
	v, _ := r.Obj.Get(key)
	s, _ := v.(string)
	return s
}

func (r *Record) RecordID() string   { return r.str("record_id") }
func (r *Record) RecordType() string { return r.str("record_type") }
func (r *Record) TenantID() string   { return r.str("tenant_id") }
func (r *Record) StreamID() string   { return r.str("stream_id") }

func (r *Record) Sequence() int64 {
	v, _ := r.Obj.Get("sequence")
	n, _ := v.(int64)
	return n
}

// PrevDigest returns the link and whether it is present (non-null).
func (r *Record) PrevDigest() (string, bool) {
	v, ok := r.Obj.Get("prev_digest")
	if !ok || v == nil {
		return "", false
	}
	s, _ := v.(string)
	return s, true
}

func (r *Record) SourceTime() string {
	clocksV, _ := r.Obj.Get("clocks")
	clocks, ok := clocksV.(*jcs.Object)
	if !ok {
		return ""
	}
	v, _ := clocks.Get("source_time")
	s, _ := v.(string)
	return s
}

func (r *Record) Signature() (*jcs.Object, error) {
	v, _ := r.Obj.Get("signature")
	sig, ok := v.(*jcs.Object)
	if !ok {
		return nil, errf(jcs.CodeMalformed, "signature must be an object")
	}
	return sig, nil
}

// SigningBytes is the ES-021 signing input: the canonical record with the
// signature member excluded.
func (r *Record) SigningBytes() ([]byte, error) {
	return jcs.Serialize(r.Obj.Without("signature"))
}

// SignedDigest is the ES-021 digest over SigningBytes.
func (r *Record) SignedDigest() (string, error) {
	b, err := r.SigningBytes()
	if err != nil {
		return "", err
	}
	return jcs.Digest(b), nil
}

// CompleteBytes is the whole record including its signature member. ES-006a
// makes this — not SigningBytes — the input to prev_digest, so that replacing
// a signature breaks the chain at the following record. ES-030 uses the same
// form for the receipt's record_digest.
func (r *Record) CompleteBytes() ([]byte, error) {
	return jcs.Serialize(r.Obj)
}

// CompleteDigest is the ES-006a / ES-030 digest over CompleteBytes.
func (r *Record) CompleteDigest() (string, error) {
	b, err := r.CompleteBytes()
	if err != nil {
		return "", err
	}
	return jcs.Digest(b), nil
}
