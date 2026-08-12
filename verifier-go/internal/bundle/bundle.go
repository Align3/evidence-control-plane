// Package bundle validates a complete attestation bundle: the records it
// carries, the versions it was computed under, the qualification that entitles
// its denominator class, its validity period, and its revocation status.
//
// The container is the JSON array defined by ES-034: complete signed records,
// each classified by its own `record_type`. Nothing about a record's role is
// stated by the container, and that is the point of the shape.
//
// The alternative considered and rejected was a keyed object with named members
// —`attestation`, `population_records`, `gap_records` and so on. It reads
// better and it is wrong, for a reason worth recording because it was found by
// building it: a keyed container states each record's role *independently of
// the record*, so the two can disagree. A validly signed CoverageGap filed
// under `population_records` parsed, authenticated, and reached the coverage
// engine as a population — counted in the wrong place, and simultaneously
// absent from the gap set that CM-014 conservation is checked against. Every
// signature on that bundle was good. It is a gap-hiding path built out of
// nothing but valid records, which is the precise overclaim shape this product
// exists to prevent.
//
// An array cannot express that failure, because there is no filing to get
// wrong. ES-033 already makes `record_type` a closed dispatch, so the closure a
// keyed container would add is inherited rather than invented, and adding a
// record type needs no container change.
//
// Two further properties are load-bearing:
//
//   - Every record is carried as its **exact received bytes**. ES-001 makes the
//     wire form the thing that is checked, and a container that re-serializes
//     its members destroys the only artifact the signature covers. The elements
//     are json.RawMessage and never a decoded struct.
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

// Bundle is a parsed, structurally valid bundle, with its records classified by
// their own record_type. Signatures are *not* checked by Parse — that is
// Verify's job, and keeping them separate means a caller cannot obtain a Bundle
// and mistake having one for having verified it.
type Bundle struct {
	Attestation    *Record
	Qualifications []*Record
	Boundary       *Record
	Populations    []*Record
	Gaps           []*Record
	// Other is every record whose type this package does not route: agent
	// identities, reviews, receipts and anything a later schema adds. They are
	// authenticated and carried rather than dropped, because a record silently
	// discarded by the verifier is a record the relying party believes was
	// checked.
	Other []*Record
	// Records is every record in bundle order, so checks that care about
	// position (ES-006a links) see what was actually supplied.
	Records []*Record
}

// Record pairs a parsed record with the exact bytes it arrived as. Both are
// needed: the bytes for the ES-001 canonical-wire check, the parse for
// everything else.
type Record struct {
	Wire   []byte
	Parsed *evidence.Record
	// Index is the record's position in the container, used in findings so an
	// operator can point at the element that failed.
	Index int
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

// Parse decodes an ES-034 bundle and structurally validates every record in it.
// It does not authenticate anything.
func Parse(data []byte) (*Bundle, error) {
	// ES-034 requires the container to be JCS-canonical, and the reason is
	// mechanical rather than aesthetic. Each record is extracted as a raw byte
	// range, and ES-001 checks that range against the canonical form. If the
	// container were free-form, a pretty-printed bundle would present every
	// record it carries as non-canonical, and the only ways out would be to
	// re-serialize the records — destroying the bytes the signature covers — or
	// to stop checking ES-001 inside a bundle. Requiring it here makes QA-008's
	// byte-identical bundle a property of the whole artifact.
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

	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf(
			"%s: bundle must be a JSON array of complete evidence records "+
				"(ES-034): %v", CodeBundleMalformed, err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("%s: bundle is empty", CodeBundleMalformed)
	}

	// ES-034: elements ordered by their canonical bytes, lexicographic
	// ascending. Canonicalizing the container is not enough on its own — RFC
	// 8785 sorts the members of an object and does not reorder the elements of
	// an array, so the same record set emitted in two orders yields two
	// conformant bundles with different digests. QA-008 fails CI on any bundle
	// diff, so without a total order that gate reports divergence between
	// implementations that agree about everything substantive.
	//
	// Each element is already its own canonical form (the container is
	// canonical and every record is checked against ES-001 below), so
	// comparing the raw element bytes is comparing the canonical bytes.
	for i := 1; i < len(raw); i++ {
		if bytes.Compare(raw[i-1], raw[i]) > 0 {
			return nil, fmt.Errorf(
				"%s: bundle elements %d and %d are out of order; ES-034 orders "+
					"them by canonical bytes, lexicographic ascending, so that one "+
					"record set has one bundle",
				CodeBundleUnordered, i-1, i)
		}
		if bytes.Equal(raw[i-1], raw[i]) {
			// Two byte-identical elements are one record presented twice. The
			// duplicate adds nothing and the pair would make counts and chain
			// links depend on how many copies a producer happened to include.
			return nil, fmt.Errorf(
				"%s: bundle elements %d and %d are byte-identical; a record "+
					"appears once in a bundle", CodeBundleMalformed, i-1, i)
		}
	}

	b := &Bundle{}
	for i, item := range raw {
		parsed, err := evidence.ParseRecord(item)
		if err != nil {
			return nil, fmt.Errorf("%s: bundle[%d]: %w", CodeBundleMalformed, i, err)
		}
		rec := &Record{Wire: append([]byte(nil), item...), Parsed: parsed, Index: i}
		b.Records = append(b.Records, rec)

		// Routing is read from the record, never from the container. An
		// unrecognised record_type never reaches here: evidence.ParseRecord
		// refuses it under the closed §5 enumeration.
		switch parsed.RecordType() {
		case "AttestationWindow":
			if b.Attestation != nil {
				return nil, fmt.Errorf(
					"%s: bundle carries more than one AttestationWindow; the "+
						"status reported would depend on which one the verifier "+
						"chose", CodeBundleMalformed)
			}
			b.Attestation = rec
		case "AssuranceBoundary":
			if b.Boundary != nil {
				return nil, fmt.Errorf(
					"%s: bundle carries more than one AssuranceBoundary; the "+
						"scope verified would depend on which one the verifier "+
						"chose", CodeBundleMalformed)
			}
			b.Boundary = rec
		case "QualificationRecord":
			b.Qualifications = append(b.Qualifications, rec)
		case "PopulationRecord":
			b.Populations = append(b.Populations, rec)
		case "CoverageGap":
			b.Gaps = append(b.Gaps, rec)
		default:
			b.Other = append(b.Other, rec)
		}
	}

	if b.Attestation == nil {
		return nil, fmt.Errorf(
			"%s: bundle carries no AttestationWindow; there is no attestation "+
				"to verify", CodeBundleMalformed)
	}
	return b, nil
}
