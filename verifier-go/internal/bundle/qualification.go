package bundle

import (
	"time"
)

// checkQualification enforces TM-013 and CM-004: a denominator class applies
// only to windows beginning after the date it was qualified.
//
// The requirement is emphatic that this is checked *independently*. That word
// is doing real work, and it rules out the obvious implementation. An
// AttestationWindow states its own `denominator_class`, and ES-018 has it state
// `capped_by_class` too; a verifier that read either and reported it would be
// restating the claim under a different name. What is checked here instead is
// the entitlement: does a correctly signed QualificationRecord exist, for this
// tenant, assigning this class, dated no later than the window start?
//
// The failure this defends against is the one in threat-model §4.10 and
// CM-S-009. A connector is improved in September, the customer is re-qualified
// at C1, and August's window is then re-attested at C1. Every signature on that
// bundle is valid, the class it claims is one the customer genuinely holds, and
// the claim is still false: in August the evidence did not exist. The only
// thing separating the two is a date comparison, which is why it is done here
// rather than trusted from a flag.
//
// SPEC GAP (recorded): matching a qualification to the families a window covers
// requires the boundary, since ES-009 puts qualification_refs on the boundary's
// action_families and the AttestationWindow body carries no action_family of
// its own. Nothing states whether a bundle must carry the boundary, so this
// check is deliberately scoped to what it can establish without one — the
// temporal and provenance rule TM-013 states — and does not claim to have
// verified family-level scope coverage. The distinction is reported rather than
// papered over, because "class C1 was qualified before this window" and "every
// family in this window was qualified at C1 before it" are different claims and
// only the first is checked here.
func checkQualification(b *Bundle) []Finding {
	att := b.Attestation

	claimed, ok := att.BodyString("denominator_class")
	if !ok || claimed == "" {
		return []Finding{finding(CodeQualificationMissing,
			"attestation states no denominator_class, so no qualification can entitle it (CM-003)")}
	}

	windowStartStr, ok := att.BodyString("window_start")
	if !ok {
		return []Finding{finding(CodeWindowUnparseable,
			"attestation has no window_start, so TM-013 cannot be checked")}
	}
	windowStart, err := time.Parse(time.RFC3339, windowStartStr)
	if err != nil {
		return []Finding{finding(CodeWindowUnparseable,
			"window_start %q is not RFC 3339: %v", windowStartStr, err)}
	}

	var (
		out       []Finding
		entitling bool
		seenClass bool
	)

	for i, rec := range b.Qualifications {
		// No type check is needed: ES-034 routes by the record's own
		// record_type, so a record reaching this slice is a
		// QualificationRecord by construction. Under a keyed container it
		// would not have been, which is why that container was rejected.
		assigned, ok := rec.BodyString("assigned_class")
		if !ok {
			out = append(out, finding(CodeQualificationUnparsed,
				"bundle qualification %d has no assigned_class", i))
			continue
		}
		if assigned != claimed {
			// A qualification for another class is not evidence about this
			// one. Whether a stronger class also admits a weaker claim is a
			// lattice question under CM-008, decided by the coverage checks,
			// not smuggled in here as a date comparison.
			continue
		}
		seenClass = true

		qualifiedAtStr, ok := rec.BodyString("qualified_at")
		if !ok {
			out = append(out, finding(CodeQualificationUnparsed,
				"bundle qualification %d has no qualified_at, so TM-013 cannot be checked", i))
			continue
		}
		qualifiedAt, err := time.Parse(time.RFC3339, qualifiedAtStr)
		if err != nil {
			out = append(out, finding(CodeQualificationUnparsed,
				"bundle qualification %d qualified_at %q is not RFC 3339: %v",
				i, qualifiedAtStr, err))
			continue
		}

		if qualifiedAt.After(windowStart) {
			// The message wording is pinned by TM-S-005, which requires
			// verification to fail with "qualification postdates window".
			out = append(out, finding(CodeQualificationPostdates,
				"qualification postdates window: class %s was qualified at %s, "+
					"but the window begins at %s; CM-004 permits a class only for "+
					"windows beginning after its qualification date",
				assigned, qualifiedAtStr, windowStartStr))
			continue
		}
		entitling = true
	}

	if entitling {
		return out
	}
	if seenClass {
		// Every record for this class postdated the window, and each already
		// produced its own finding above. Adding a second refusal for the same
		// fact would just make the output harder to read.
		return out
	}
	return append(out, finding(CodeQualificationMissing,
		"no QualificationRecord in the bundle assigns class %s on or before the "+
			"window start %s; the claimed class cannot be verified independently "+
			"and is therefore not accepted (TM-013)", claimed, windowStartStr))
}
