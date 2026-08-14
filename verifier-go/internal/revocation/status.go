// Package revocation implements the four-state offline-honest revocation
// machine required by TM-014 and AR-013.
//
// The whole point of this package is a negative one: there is no path, and no
// combination of transport failure, timeout, malformed response, or missing
// configuration, that produces "valid". A verifier that cannot reach the
// issuer has not learned that the attestation is unrevoked; it has learned
// nothing, and saying "valid" there is the false claim this product exists to
// prevent (agent-working-agreement §3).
//
// The type system carries that rule rather than the reviewer's attention:
//
//   - Status is an integer enum whose *zero value* is Unchecked. A forgotten
//     assignment, a zero-valued struct literal, and a dropped error all decay
//     toward "I could not check" instead of toward "fine".
//   - Result's status is unexported and every constructor lives in this file,
//     so no caller anywhere in the verifier can spell revocation.Result{Status:
//     Valid} into existence. Valid is reachable only through checkedValid,
//     which is called from exactly one place: after a successful, authenticated
//     answer from the issuer.
package revocation

// Status is the four-state answer TM-S-004 requires the verifier to be able to
// give. Checked-and-fine, checked-and-revoked, and checked-and-superseded are
// three different facts about the world; unchecked is the absence of any of
// them, and is deliberately not a fourth kind of "fine".
type Status int

const (
	// Unchecked is the zero value on purpose. See the package comment.
	Unchecked Status = iota
	Valid
	Revoked
	Superseded
)

// String renders the status as it appears in verifier output and in the
// revocation_status field TM-014 names.
func (s Status) String() string {
	switch s {
	case Valid:
		return "valid"
	case Revoked:
		return "revoked"
	case Superseded:
		return "superseded"
	case Unchecked:
		return "unchecked"
	}
	// An out-of-range Status is not a licence to guess. It reports as unchecked
	// because that is the only answer that is never an overclaim.
	return "unchecked"
}

// Checked reports whether the issuer actually answered. It is the predicate a
// caller should use before treating the status as information, and it is
// false for every failure path.
func (s Status) Checked() bool {
	return s == Valid || s == Revoked || s == Superseded
}

// Stable dotted reason codes. The code is normative for tests and output; the
// message wording is not.
const (
	// Unchecked reasons.
	ReasonOffline         = "revocation.offline"
	ReasonNoEndpoint      = "revocation.no_endpoint"
	ReasonTransport       = "revocation.transport_error"
	ReasonTimeout         = "revocation.timeout"
	ReasonHTTPStatus      = "revocation.unexpected_http_status"
	ReasonMalformed       = "revocation.malformed_response"
	ReasonUnauthenticated = "revocation.unauthenticated_response"
	ReasonWrongSubject    = "revocation.response_names_another_attestation"
	ReasonBodyShape       = "revocation.record_body_invalid"

	// Checked reasons.
	ReasonNonePublished   = "revocation.none_published"
	ReasonNotYetEffective = "revocation.not_yet_effective"
	ReasonRevoked         = "revocation.revoked"
	ReasonSuperseded      = "revocation.superseded"
)

// Result is what a check yields. It always carries a reason, including on the
// affirmative paths, because "valid" with no account of how that was
// established is the shape of claim this repository refuses to make.
type Result struct {
	status Status
	reason string
	detail string

	// SupersededBy is the superseding attestation reference, present only
	// when Status is Superseded (AR-011).
	SupersededBy string
	// EffectiveAt is the revocation's effective_at as published, present
	// whenever an authenticated RevocationRecord was retrieved.
	EffectiveAt string
}

// Status returns the four-state answer.
func (r Result) Status() Status { return r.status }

// Reason returns the stable dotted code explaining how the status was reached.
func (r Result) Reason() string { return r.reason }

// Detail returns human-readable context. It is never load-bearing.
func (r Result) Detail() string { return r.detail }

// Checked reports whether the issuer answered.
func (r Result) Checked() bool { return r.status.Checked() }

// unchecked builds the only kind of Result a failure may produce.
func unchecked(reason, detail string) Result {
	return Result{status: Unchecked, reason: reason, detail: detail}
}

// checkedValid and checkedPendingValid are the only constructors of Valid in
// the verifier. Both are reached only after an authenticated issuer answer.
func checkedValid(reason, detail string) Result {
	return Result{status: Valid, reason: reason, detail: detail}
}

func checkedPendingValid(effectiveAt, supersededBy, detail string) Result {
	return Result{
		status:       Valid,
		reason:       ReasonNotYetEffective,
		detail:       detail,
		EffectiveAt:  effectiveAt,
		SupersededBy: supersededBy,
	}
}

func checkedRevoked(effectiveAt, detail string) Result {
	return Result{
		status: Revoked, reason: ReasonRevoked, detail: detail,
		EffectiveAt: effectiveAt,
	}
}

func checkedSuperseded(effectiveAt, supersededBy, detail string) Result {
	return Result{
		status: Superseded, reason: ReasonSuperseded, detail: detail,
		EffectiveAt: effectiveAt, SupersededBy: supersededBy,
	}
}
