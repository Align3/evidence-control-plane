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
// INTEGRATION NOTE — two bundle containers, recorded rather than reconciled.
//
// internal/coverage defines its own Bundle: a flat JSON array of complete
// records, classified by record_type. internal/bundle defines a keyed object
// container. Both were invented to fill the same hole — no document in the
// corpus defines a bundle container, and data-model.md:261 explicitly leaves
// the reconstruction to EV-19 — and the two builders, working from the
// specification without seeing each other's code, produced different shapes.
//
// That is not a defect in either. It is the AG-017 detector firing exactly as
// designed: two independent readings of the same corpus diverged because the
// corpus does not decide, and the divergence is visible only because neither
// side read the other. This adapter converts between them so the verifier
// works today. It does not pick a winner, because picking one here is the
// decision that belongs in the specification.
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

// toCoverageBundle converts the keyed container into the flat one.
//
// Only records that were already authenticated by internal/bundle reach here,
// so this conversion cannot introduce an unverified input: bundle.Verify runs
// every signature check before it calls any Check.
func toCoverageBundle(b *bundle.Bundle) *coverage.Bundle {
	out := &coverage.Bundle{Window: b.Attestation.Parsed}
	for _, rec := range b.Populations {
		out.Populations = append(out.Populations, rec.Parsed)
	}
	for _, rec := range b.Gaps {
		out.Gaps = append(out.Gaps, rec.Parsed)
	}
	other := make([]*evidence.Record, 0, len(b.Qualifications)+1)
	for _, rec := range b.Qualifications {
		other = append(other, rec.Parsed)
	}
	if b.Boundary != nil {
		other = append(other, b.Boundary.Parsed)
	}
	out.Other = other
	return out
}
