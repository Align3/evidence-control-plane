package bundle

import (
	"github.com/Align3/evidence-control-plane/verifier-go/internal/jcs"
)

// checkBoundaryBinding ties the bundle's supporting records to the boundary the
// attestation actually names, where the corpus determines how.
//
// Without this, the bundle is a bag: an attestation naming boundary-1 travels
// beside a boundary-2 record and a qualification that boundary-2 declared, and
// every signature verifies. Signature validity is a claim about who wrote each
// record, not about whether they belong together, and "these records were all
// validly signed" is not "these records describe one boundary".
//
// SPEC GAP (recorded, not guessed) — the family-level check stays unbuilt.
// ES-009 requires every `action_families[]` entry to carry a
// `qualification_ref`, and DM-030 shows what the relationship really is: a
// qualification earns a class for one (action_family, destination_system) pair,
// which is why the database foreign key is on four columns rather than on the
// ref alone. But §5.1 lists `action_families[]` and `qualification_refs[]` as
// two separate members, the writer types the first as an untyped list, and
// nothing states whether family entries are objects carrying their own ref or
// whether the two lists are positionally parallel. Two conformant readings
// exist, so mapping a family to its qualification here would be this verifier
// inventing the encoding. What is checked below is only what the corpus
// determines; the rest is disclosed as a standing limitation rather than
// assumed.
//
// The three return values are distinct claims and are kept apart deliberately:
// findings refuse; unresolved says something about *this bundle* could not be
// decided, and blocks a verdict of "valid"; notes are standing limitations of
// this verifier version, true of every bundle, which must be disclosed on every
// run but cannot block a verdict — a limitation that blocked one would make
// "valid" unreachable for all inputs, which is not honesty, it is a broken
// scale that hides the difference between a good bundle and a bad one.
func checkBoundaryBinding(b *Bundle) ([]Finding, []string, []string) {
	var (
		out        []Finding
		unresolved []string
	)

	// Standing limitation, disclosed on every run. See the SPEC GAP note above.
	notes := []string{
		"per-family qualification coverage (ES-009): action_families[] has no " +
			"determined encoding for its qualification_ref, so this verifier " +
			"does not check which family a qualification covers",
	}

	claimed, _ := b.Attestation.BodyString("boundary_ref")

	if b.Boundary == nil {
		// Not carrying the boundary is permitted — ES-026 requires selective
		// disclosure to be possible, and a bundle proving a narrow claim need
		// not ship every constitutive record. It does mean the scope of the
		// claim was not checked, and that is disclosed rather than passed over.
		unresolved = append(unresolved,
			"assurance boundary: the bundle does not carry the boundary the "+
				"attestation names, so its declared scope was not checked")
		return out, unresolved, notes
	}

	// The attestation's boundary_ref must name the boundary supplied. ES-031
	// makes a boundary constitutive and self-referencing, so the reference is
	// matched against the boundary's own record_id as well as its envelope
	// boundary_ref: ES-S-016 exists precisely because that self-reference is
	// checked rather than assumed.
	boundaryID := b.Boundary.Parsed.RecordID()
	envelopeRef, _ := b.Boundary.EnvelopeString("boundary_ref")
	if claimed != "" && claimed != boundaryID && claimed != envelopeRef {
		out = append(out, finding(CodeBoundaryMismatch,
			"attestation names boundary %q but the bundle carries boundary %q; "+
				"a claim verified against a boundary it does not name is a claim "+
				"about a different scope", claimed, boundaryID))
		return out, unresolved, notes
	}

	// qualification_refs[] is typed as a list of strings by §5.1 and the
	// writer alike, so membership in it is determinate and checkable. A
	// qualification record the boundary never declared is not a qualification
	// this attestation may rest on, whoever validly signed it.
	declared, ok := stringList(b.Boundary, "qualification_refs")
	if !ok {
		unresolved = append(unresolved,
			"assurance boundary: qualification_refs[] is not a list of strings, "+
				"so declared-qualification membership was not checked")
		return out, unresolved, notes
	}
	declaredSet := make(map[string]bool, len(declared))
	for _, ref := range declared {
		declaredSet[ref] = true
	}
	for i, rec := range b.Qualifications {
		id := rec.Parsed.RecordID()
		if !declaredSet[id] {
			out = append(out, finding(CodeQualificationUndeclared,
				"bundle qualification %d (%s) is not among the boundary's "+
					"qualification_refs; ES-009 makes the boundary the place a "+
					"family's qualification is declared, so a record it does not "+
					"declare cannot entitle a class under it", i, id))
		}
	}

	return out, unresolved, notes
}

// stringList reads a body member that must be a list of strings.
func stringList(r *Record, key string) ([]string, bool) {
	body, err := r.Body()
	if err != nil {
		return nil, false
	}
	v, ok := body.Get(key)
	if !ok || v == nil {
		return nil, false
	}
	arr, ok := v.([]jcs.Value)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		s, ok := item.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}
