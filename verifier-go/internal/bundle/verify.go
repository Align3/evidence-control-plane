package bundle

import (
	"context"
	"fmt"
	"time"

	"github.com/Align3/evidence-control-plane/verifier-go/internal/evidence"
	"github.com/Align3/evidence-control-plane/verifier-go/internal/revocation"
)

// Stable dotted codes. Wording is ours; the code is what tests and output pin.
const (
	CodeBundleMalformed     = "bundle.malformed"
	CodeBundleNonCanonical  = "bundle.non_canonical"
	CodeBundleUnordered     = "bundle.elements_unordered"
	CodeWrongRecordType     = "bundle.wrong_record_type"
	CodeSignatureInvalid    = "bundle.signature_invalid"
	CodeTenantMismatch      = "bundle.tenant_mismatch"
	CodeSchemaUnsupported   = "schema.version_unsupported"
	CodeMethodologyUnknown  = "methodology.version_unsupported"
	CodeValidityUnparseable = "validity.unparseable"
	CodeWindowUnparseable   = "window.unparseable"

	CodeQualificationMissing   = "qualification.record_missing"
	CodeQualificationPostdates = "qualification.postdates_window"
	CodeQualificationTenant    = "qualification.tenant_mismatch"
	CodeQualificationUnparsed  = "qualification.qualified_at_unparseable"

	CodeBoundaryMismatch        = "boundary.attestation_names_another"
	CodeQualificationUndeclared = "qualification.not_declared_by_boundary"
	CodeChainBroken             = "chain.link_broken"
	CodeChainFork               = "chain.fork"
)

// Finding is a reason the bundle does not verify. Every finding refuses;
// there is no advisory severity, because AG-002's failure mode is precisely a
// refusal quietly demoted to a warning. Something worth saying that is not
// worth refusing over goes in Result.Notes.
type Finding struct {
	Code    string
	Message string
}

func (f Finding) String() string { return f.Code + ": " + f.Message }

func finding(code, format string, args ...any) Finding {
	return Finding{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Check is the extension point the rest of EV-19 plugs into: coverage
// recomputation, lattice re-checking, the null-ratio rule, and the assertion
// catalogue are separate packages that see a parsed, *already authenticated*
// bundle and return refusals.
//
// The seam is deliberately narrow. A check receives the bundle and returns
// findings; it cannot reach into the verdict, cannot mark itself as passed, and
// cannot downgrade another check's finding. A check that wants to claim
// something has to do it by not returning a finding, which is the only shape
// that makes "the verifier concluded X" mean the verifier actually looked.
type Check interface {
	// Name identifies the check in output and in the notes.
	Name() string
	// Check runs against an already-authenticated bundle.
	Check(*Bundle) CheckResult
}

// CheckResult separates the two things a check can conclude, because they are
// not the same claim and collapsing them is the failure this whole verifier is
// built against.
//
// A zero CheckResult means "ran, found nothing, checked everything" — the only
// shape that lets a bundle reach Valid. A check that cannot run at all must
// therefore say so explicitly, in one field or the other.
type CheckResult struct {
	// Findings are determinate violations: the rule is settled and the bundle
	// broke it. Any finding refuses the bundle.
	Findings []Finding
	// Unresolved are things the check could not decide — because the
	// specification does not determine them, or because the bundle does not
	// carry what they would be checked against. These do not refuse, because
	// no rule was broken; they do prevent a verdict of "valid", because a
	// claim nobody could check has not been verified. They surface as
	// Indeterminate, which is exit 3: "I could not check", not "this is
	// invalid".
	Unresolved []string
}

// Verdict is the conclusion. Its zero value is Indeterminate, so a Result
// nobody filled in does not read as an endorsement.
type Verdict int

const (
	// Indeterminate is the zero value: the verifier reached no conclusion.
	Indeterminate Verdict = iota
	// Invalid means a check refused. This is a positive negative conclusion.
	Invalid
	// Revoked and Superseded are the issuer's answers (AR-010, AR-011).
	Revoked
	Superseded
	// Expired is AR-009's required distinct outcome: expired verifies as
	// expired, never as valid-with-a-warning.
	Expired
	// NotYetValid is validity_from in the future.
	NotYetValid
	// UncheckedRevocation means everything checkable checked out and the
	// revocation state is unknown. TM-S-004 requires this to be reportable
	// without the output claiming the attestation is valid.
	UncheckedRevocation
	// Valid is every check passed, inside validity, and the issuer
	// affirmatively answered that nothing is published against it.
	Valid
)

func (v Verdict) String() string {
	switch v {
	case Invalid:
		return "invalid"
	case Revoked:
		return "revoked"
	case Superseded:
		return "superseded"
	case Expired:
		return "expired"
	case NotYetValid:
		return "not_yet_valid"
	case UncheckedRevocation:
		return "unchecked_revocation"
	case Valid:
		return "valid"
	case Indeterminate:
		return "indeterminate"
	}
	return "indeterminate"
}

// Result is the whole answer.
type Result struct {
	Verdict    Verdict
	Findings   []Finding
	Unresolved []string
	Notes      []string
	Revocation revocation.Result

	// AttestationID is the record_id of the attestation examined.
	AttestationID string
	// EvidenceKeyID and IssuerKeyID are the two ES-023 signers.
	EvidenceKeyID string
	IssuerKeyID   string
	// ChecksRun names every Check that executed, so the output can state what
	// was *not* checked rather than leaving a relying party to assume.
	ChecksRun []string
}

// Options configures a verification.
type Options struct {
	// Keys is the trusted keyring. Namespaces come from the keyring, never
	// from the records being verified.
	Keys map[string]evidence.RegisteredKey
	// Revocation is the four-state checker. Its zero value checks nothing and
	// reports unchecked, which is the correct behaviour for a verifier run
	// with no endpoint.
	Revocation revocation.Checker
	// Checks are the pluggable refusals described on Check.
	Checks []Check
	// Now is the clock used for validity and revocation effectiveness.
	Now func() time.Time
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// Verify runs the whole bundle path and returns a verdict.
func Verify(ctx context.Context, b *Bundle, opts Options) Result {
	res := Result{
		AttestationID: b.Attestation.Parsed.RecordID(),
	}

	// 1. The attestation must be an AttestationWindow. A bundle presenting some
	//    other record type under the attestation member would otherwise have
	//    every attestation-specific rule below silently skip it.
	if got := b.Attestation.Parsed.RecordType(); got != "AttestationWindow" {
		res.Findings = append(res.Findings, finding(CodeWrongRecordType,
			"bundle attestation is a %s, not an AttestationWindow", got))
		res.Verdict = Invalid
		return res
	}

	// 2. Both ES-023 signatures, through the complete canonical-wire entry
	//    point. VerifyCanonicalEvidenceRecord dispatches on record_type and
	//    requires the issuer counter-signature for this type, so a bundle whose
	//    attestation had its counter-signature stripped is refused here rather
	//    than reaching the coverage checks and being reported on.
	verified, err := evidence.VerifyCanonicalEvidenceRecord(b.Attestation.Wire, opts.Keys)
	if err != nil {
		res.Findings = append(res.Findings, finding(CodeSignatureInvalid,
			"attestation does not verify: %v", err))
		res.Verdict = Invalid
		return res
	}
	res.EvidenceKeyID = verified.KeyID
	res.IssuerKeyID = verified.IssuerKeyID

	// 3. Every other record in the bundle is authenticated too, under the same
	//    ES-033 namespace dispatch. An unauthenticated supporting record is not
	//    context; it is an input a later check would trust.
	res.Findings = append(res.Findings, verifySupporting(b, opts.Keys)...)

	// 4. Versions, before anything that depends on them. ES-027/ES-028 and
	//    CM-023 all say the same thing from different directions: an artifact
	//    is verified under the version that produced it, so a version this
	//    verifier does not implement is a refusal, not a best effort.
	res.Findings = append(res.Findings, checkVersions(b.Attestation)...)

	// 5. TM-013 / CM-004, verified independently of the claimed class.
	res.Findings = append(res.Findings, checkQualification(b)...)

	// 6. The records must describe one boundary, and the links between any
	//    contiguous run of them must hold. Valid signatures say who wrote each
	//    record; neither says the records belong together.
	bindingFindings, bindingUnresolved, bindingNotes := checkBoundaryBinding(b)
	res.Findings = append(res.Findings, bindingFindings...)
	res.Unresolved = append(res.Unresolved, bindingUnresolved...)
	res.Notes = append(res.Notes, bindingNotes...)

	chainFindings, chainUnresolved := checkChainLinks(b)
	res.Findings = append(res.Findings, chainFindings...)
	res.Unresolved = append(res.Unresolved, chainUnresolved...)

	// 7. Pluggable checks: coverage recomputation, lattice re-checking, the
	//    null-ratio rule, the assertion catalogue.
	for _, c := range opts.Checks {
		res.ChecksRun = append(res.ChecksRun, c.Name())
		out := c.Check(b)
		res.Findings = append(res.Findings, out.Findings...)
		for _, u := range out.Unresolved {
			res.Unresolved = append(res.Unresolved, c.Name()+": "+u)
		}
	}
	if len(opts.Checks) == 0 {
		res.Notes = append(res.Notes,
			"no coverage, lattice or assertion checks were registered; "+
				"this verdict says nothing about the coverage claim")
	}

	// 8. Revocation. Run regardless of findings, because a relying party
	//    holding a refused bundle still benefits from knowing it was revoked,
	//    and because a check that only runs on the happy path is a check whose
	//    failure modes are never exercised.
	res.Revocation = opts.Revocation.Check(ctx, res.AttestationID)

	res.Verdict = decide(&res, b, opts.now())
	return res
}

// decide is the verdict machine, kept as one pure function over an assembled
// Result so the ordering is auditable in one place and directly testable.
//
// The ordering is load-bearing:
//
//   - Refusals first. A bundle that failed a check has no validity period worth
//     reporting on.
//   - Revoked and superseded next: the issuer's own answer about the artifact
//     outranks the artifact's self-declared dates.
//   - Expiry before unchecked revocation. AR-S-004 runs a verifier that has no
//     revocation endpoint, and an expired attestation there must report
//     "expired" (AR-009) rather than disappearing into "unchecked".
//   - Unchecked revocation last before Valid, so Valid is reachable only when
//     the issuer affirmatively answered.
func decide(res *Result, b *Bundle, now time.Time) Verdict {
	if len(res.Findings) > 0 {
		return Invalid
	}
	switch res.Revocation.Status() {
	case revocation.Revoked:
		return Revoked
	case revocation.Superseded:
		return Superseded
	}

	from, until, err := validityPeriod(b.Attestation)
	if err != nil {
		// A validity period that does not parse is not an absent one. AR-009
		// makes the period enforceable, and an unenforceable period is a
		// refusal rather than an unbounded licence.
		res.Findings = append(res.Findings, finding(CodeValidityUnparseable, "%v", err))
		return Invalid
	}
	if now.After(until) {
		return Expired
	}
	if now.Before(from) {
		return NotYetValid
	}
	if !res.Revocation.Checked() {
		return UncheckedRevocation
	}
	// Everything determinate passed and the issuer answered — but if a check
	// could not decide part of the claim, this verifier has not verified it.
	// Reporting Valid here would be the exact overclaim the product exists to
	// prevent, one level up: a headline verdict resting on a check that ran
	// and came back "I do not know".
	if len(res.Unresolved) > 0 {
		return Indeterminate
	}
	return Valid
}

// verifySupporting authenticates every non-attestation record in the bundle and
// binds it to the attestation's tenant.
func verifySupporting(b *Bundle, keys map[string]evidence.RegisteredKey) []Finding {
	var out []Finding
	tenant := b.Attestation.Parsed.TenantID()

	// Every record, whatever its type — including the ones this package does
	// not route. A record carried but never authenticated is a record the
	// relying party believes was checked.
	for _, rec := range b.Records {
		if rec == b.Attestation {
			continue // already verified, with its ES-023 counter-signature
		}
		if _, err := evidence.VerifyCanonicalEvidenceRecord(rec.Wire, keys); err != nil {
			out = append(out, finding(CodeSignatureInvalid,
				"bundle[%d] (%s) does not verify: %v",
				rec.Index, rec.Parsed.RecordType(), err))
			continue
		}
		// SE-011 at bundle level: a record from another tenant is another
		// customer's evidence, and assembling it into this bundle is how a
		// weak tenant's qualification would come to support a strong
		// tenant's claim.
		if got := rec.Parsed.TenantID(); got != tenant {
			out = append(out, finding(CodeTenantMismatch,
				"bundle[%d] (%s) belongs to tenant %q, but the attestation is for %q",
				rec.Index, rec.Parsed.RecordType(), got, tenant))
		}
	}
	return out
}
