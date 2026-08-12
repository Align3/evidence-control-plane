// Package bundle validates a complete attestation bundle: the records it
// carries, the versions it was computed under, the qualification that entitles
// its denominator class, its validity period, and its revocation status.
//
// SPEC GAP (recorded, not guessed).
//
// No document in the corpus defines what an attestation bundle *is*. TM-S-004
// says "it validates an attestation bundle", QA-008 requires bundles to be
// byte-identical, SE-021 scopes buyer access to "the attestation and the
// evidence explicitly included in its bundle", and data-model.md DM-023
// explicitly defers the reassembly to this story — "an export bundle must carry
// the full record including signature, so EV-19 needs a defined, tested
// reconstruction". None of them states a container: no member names, no
// required record set, no serialization. There are no bundle vectors either, so
// ES-029 cannot decide it.
//
// The container below is therefore this implementation's, and it is reported as
// a finding rather than resolved silently. Two properties drove it:
//
//   - Every record is carried as its **exact received bytes**. ES-001 makes the
//     wire form the thing that is checked, and a container that re-serializes
//     its members destroys the only artifact the signature covers. That is why
//     the members are json.RawMessage and never a decoded struct.
//   - The container carries no verdict, no status, and no summary of its own
//     contents. Anything a bundle asserted about itself would be an input the
//     verifier could be tempted to trust, and the entire point of this verifier
//     is that it recomputes rather than reads.
package bundle

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Align3/evidence-control-plane/verifier-go/internal/evidence"
	"github.com/Align3/evidence-control-plane/verifier-go/internal/jcs"
)

// Wire is the on-disk container. Each member holds the complete wire bytes of
// a signed record, exactly as received.
type Wire struct {
	// Attestation is the AttestationWindow under verification. Required.
	Attestation json.RawMessage `json:"attestation"`
	// Qualifications are the QualificationRecords entitling the claimed
	// denominator class. TM-013 makes these mandatory in practice: without
	// them the verifier cannot check the class independently, and a verifier
	// that cannot check does not conclude.
	Qualifications []json.RawMessage `json:"qualification_records"`
	// Boundary is the AssuranceBoundary the attestation names. Optional here;
	// scope checks that need it are outside EV-19's stated acceptance.
	Boundary json.RawMessage `json:"boundary,omitempty"`
	// Populations are the PopulationRecords the attestation references. They
	// are carried for coverage recomputation, which is the other half of
	// EV-19; this package parses and authenticates them and passes them on.
	Populations []json.RawMessage `json:"population_records,omitempty"`
	// Gaps are CoverageGap records covering the window.
	Gaps []json.RawMessage `json:"gap_records,omitempty"`
}

// Bundle is a parsed, structurally valid bundle. Signatures are *not* checked
// by Parse — that is Verify's job, and keeping them separate means a caller
// cannot obtain a Bundle and mistake having one for having verified it.
type Bundle struct {
	Attestation    *Record
	Qualifications []*Record
	Boundary       *Record
	Populations    []*Record
	Gaps           []*Record
}

// Record pairs a parsed record with the exact bytes it arrived as. Both are
// needed: the bytes for the ES-001 canonical-wire check, the parse for
// everything else.
type Record struct {
	Wire   []byte
	Parsed *evidence.Record
}

// Body returns the record's body object.
func (r *Record) Body() (*jcs.Object, error) {
	v, ok := r.Parsed.Obj.Get("body")
	if !ok {
		return nil, errors.New("record has no body")
	}
	obj, ok := v.(*jcs.Object)
	if !ok {
		return nil, errors.New("record body is not an object")
	}
	return obj, nil
}

// BodyString reads a string member from the body.
func (r *Record) BodyString(key string) (string, bool) {
	body, err := r.Body()
	if err != nil {
		return "", false
	}
	v, ok := body.Get(key)
	if !ok || v == nil {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// EnvelopeString reads a string member from the envelope.
func (r *Record) EnvelopeString(key string) (string, bool) {
	v, ok := r.Parsed.Obj.Get(key)
	if !ok || v == nil {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// Parse decodes a bundle container and structurally validates every record in
// it. It does not authenticate anything.
func Parse(data []byte) (*Bundle, error) {
	// The container is required to be JCS-canonical, and the reason is
	// mechanical rather than aesthetic. Each record is extracted from it as a
	// raw byte range, and ES-001 checks that range against the canonical form.
	// If the container were free-form, a pretty-printed bundle would present
	// every record it carries as non-canonical, and the only ways out would be
	// to re-serialize the records — which destroys the bytes the signature
	// covers — or to stop checking ES-001 inside a bundle. Requiring it here
	// makes QA-008's byte-identical bundle a property of the whole artifact.
	canonical, err := jcs.Canonicalize(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", CodeBundleMalformed, err)
	}
	if !bytes.Equal(canonical, data) {
		return nil, fmt.Errorf(
			"%s: bundle is not RFC 8785 canonical, so the records inside it "+
				"cannot be checked against the bytes that were signed (ES-001)",
			CodeBundleNonCanonical)
	}

	var w Wire
	decoder := json.NewDecoder(bytes.NewReader(data))
	// A container member nobody recognises is refused rather than ignored: the
	// same reasoning as ES-005's closed envelope, applied one level up. A
	// bundle carrying "coverage_summary" that this verifier silently drops is a
	// bundle whose relying party and whose verifier are reading different
	// documents.
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&w); err != nil {
		return nil, fmt.Errorf("%s: %w", CodeBundleMalformed, err)
	}
	if len(w.Attestation) == 0 {
		return nil, fmt.Errorf("%s: bundle carries no attestation", CodeBundleMalformed)
	}

	b := &Bundle{}
	if b.Attestation, err = parseOne(w.Attestation, "attestation"); err != nil {
		return nil, err
	}
	if len(w.Boundary) > 0 {
		if b.Boundary, err = parseOne(w.Boundary, "boundary"); err != nil {
			return nil, err
		}
	}
	if b.Qualifications, err = parseEach(w.Qualifications, "qualification_records"); err != nil {
		return nil, err
	}
	if b.Populations, err = parseEach(w.Populations, "population_records"); err != nil {
		return nil, err
	}
	if b.Gaps, err = parseEach(w.Gaps, "gap_records"); err != nil {
		return nil, err
	}
	return b, nil
}

func parseOne(raw json.RawMessage, where string) (*Record, error) {
	rec, err := evidence.ParseRecord(raw)
	if err != nil {
		return nil, fmt.Errorf("bundle.%s: %w", where, err)
	}
	return &Record{Wire: append([]byte(nil), raw...), Parsed: rec}, nil
}

func parseEach(raws []json.RawMessage, where string) ([]*Record, error) {
	out := make([]*Record, 0, len(raws))
	for i, raw := range raws {
		rec, err := parseOne(raw, fmt.Sprintf("%s[%d]", where, i))
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, nil
}
