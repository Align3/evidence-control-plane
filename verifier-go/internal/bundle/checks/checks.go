// Package checks adapts EV-19's coverage recomputation and assertion
// catalogue to the bundle verification seam.
//
// It exists as a separate package so that neither side depends on the other.
// internal/bundle knows only the Check interface; internal/coverage knows only
// records and the specification. Putting the adapter in either one would make
// the bundle path and the recomputation engine a single unit, and the reason
// they are not is AG-017: they were built independently, from the
// specification, by builders who had not seen each other's work, and the
// disagreements that surfaces are the point of the exercise.
//
// The adapter is deliberately thin, and it is thin in one direction: it
// translates, and it never decides. It does not reinterpret a finding, promote
// an unresolved item to a pass, or suppress anything. Where the two halves
// model the same thing differently — and they do — that is reported, not
// smoothed over here.
package checks

import (
	"fmt"
	"strings"

	"github.com/Align3/evidence-control-plane/verifier-go/internal/bundle"
	"github.com/Align3/evidence-control-plane/verifier-go/internal/coverage"
	"github.com/Align3/evidence-control-plane/verifier-go/internal/evidence"
)

// All returns every check the verifier runs against an authenticated bundle.
func All() []bundle.Check {
	return []bundle.Check{Coverage{}}
}

// Coverage runs CM-008 lattice re-checking, the ES-017 null-ratio rule, CM-014
// gap conservation and the AR-003 assertion catalogue over the bundle.
//
// INTEGRATION NOTE. The two halves of EV-19 were built independently and
// invented different bundle containers for the same undefined slot: a flat
// record array here in internal/coverage, a keyed object in internal/bundle.
// ES-034 settled it on the array, so this adapter no longer converts between
// two shapes — both sides now classify records the same way, from each
// record's own record_type, and the conversion below is a field mapping that
// cannot misfile anything. The keyed container's ability to state a role that
// disagreed with the record it held is what disqualified it; see the note in
// internal/bundle.
type Coverage struct{}

// Name identifies the check in verifier output.
func (Coverage) Name() string { return "coverage" }

// Check recomputes the coverage claim and translates the result.
func (Coverage) Check(b *bundle.Bundle) bundle.CheckResult {
	recomputed, err := coverage.Recompute(toCoverageBundle(b))
	if err != nil {
		// A recomputation that could not start is not a recomputation that
		// found nothing. It refuses, because the coverage claim is the claim
		// the bundle exists to make and an unexamined one must not travel
		// under a verified verdict.
		return bundle.CheckResult{Findings: []bundle.Finding{{
			Code:    codeOf(err),
			Message: fmt.Sprintf("coverage recomputation could not run: %v", err),
		}}}
	}

	out := bundle.CheckResult{}
	for _, f := range recomputed.Findings {
		out.Findings = append(out.Findings, bundle.Finding{
			Code: f.Code,
			// A coverage error that wraps one from another package carries the
			// inner code at the front of its message. bundle.Finding renders
			// the code itself, so the prefix is dropped here to avoid printing
			// it twice. Presentation only: the code and the text are unchanged.
			Message: strings.TrimPrefix(f.Msg, f.Code+": "),
		})
	}
	// Unresolved travels as unresolved. The bundle verdict machine turns it
	// into Indeterminate rather than Valid, which is the same distinction the
	// recomputation drew, carried one level up instead of being flattened into
	// a pass.
	out.Unresolved = append(out.Unresolved, recomputed.Unresolved...)
	return out
}

// codeOf extracts the dotted code from a coverage error.
func codeOf(err error) string {
	if code := coverage.Code(err); code != "" {
		return code
	}
	return "coverage.recomputation_failed"
}

// toCoverageBundle maps one already-classified bundle onto the other's struct.
//
// Both sides route from record_type, so this is a field mapping and not a
// reclassification: no record can land in a different bucket here than the one
// it was parsed into. Only records already authenticated by bundle.Verify reach
// this function, which runs every signature check before it calls any Check.
func toCoverageBundle(b *bundle.Bundle) *coverage.Bundle {
	out := &coverage.Bundle{Window: b.Attestation.Parsed}
	for _, rec := range b.Populations {
		out.Populations = append(out.Populations, rec.Parsed)
	}
	for _, rec := range b.Gaps {
		out.Gaps = append(out.Gaps, rec.Parsed)
	}
	other := make([]*evidence.Record, 0,
		len(b.Qualifications)+len(b.Other)+1)
	for _, rec := range b.Qualifications {
		other = append(other, rec.Parsed)
	}
	for _, rec := range b.Other {
		other = append(other, rec.Parsed)
	}
	if b.Boundary != nil {
		other = append(other, b.Boundary.Parsed)
	}
	out.Other = other
	return out
}
