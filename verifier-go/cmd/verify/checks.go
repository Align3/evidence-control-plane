package main

import (
	"github.com/Align3/evidence-control-plane/verifier-go/internal/bundle"
	"github.com/Align3/evidence-control-plane/verifier-go/internal/bundle/checks"
)

// registeredChecks is the single place EV-19's coverage recomputation, lattice
// re-checking, null-ratio rule and assertion catalogue are wired into the
// bundle path.
//
// It is its own file, and it is a list rather than a call graph, for one
// reason: what this verifier checks has to be readable in one place by someone
// deciding whether to rely on its output. A check reached from three levels
// down inside Verify is a check nobody can enumerate, and a relying party
// cannot tell an omitted check from a passed one.
//
// The contract for anything added here is on bundle.Check: return one finding
// per refusal, and return nil only when the check actually ran and found
// nothing. A check that could not run returns a finding — the same rule the
// revocation machine follows, for the same reason.
func registeredChecks() []bundle.Check {
	return checks.All()
}
