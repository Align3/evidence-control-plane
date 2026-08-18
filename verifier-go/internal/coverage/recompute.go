package coverage

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Align3/evidence-control-plane/verifier-go/internal/attestation"
	"github.com/Align3/evidence-control-plane/verifier-go/internal/evidence"
	"github.com/Align3/evidence-control-plane/verifier-go/internal/jcs"
)

// CodeGapOmittedFromClaim fires when a signed CoverageGap record covering part
// of the window is not among the gaps the attestation declares. CM-015 makes
// the gap record the evidence; an attestation that holds one and does not list
// it is claiming coverage over an interval it has itself recorded as unknown.
const CodeGapOmittedFromClaim = "coverage.gap_omitted_from_claim"

// Bundle is the set of signed records a relying party is given, from which the
// attestation's status must be reproducible offline (evidence-spec.md §1,
// QA-003).
//
// **Specification gap, recorded rather than invented around.** No document in
// this corpus defines a bundle container. `evidence-spec.md` §1 and ES-026 say
// a relying party is given a bundle, `testing-qa.md` §2 makes the verifier the
// oracle "from the bundle alone", and `data-model.md` §261 notes that EV-19
// "needs a defined, tested reconstruction" of the wire form — but no
// requirement states the container's shape, and no published vector contains
// one.
//
// CORRECTED AT INTEGRATION. This comment previously said the array shape below
// was "this verifier's own" container. It is not, and the correction is
// recorded rather than quietly applied: the shipped container is the keyed
// object in internal/bundle, which `-mode bundle` accepts and which preserves
// each record's exact signed bytes as a byte range of the container. Two
// containers were invented independently for the same undefined slot — that
// divergence is the AG-017 detector firing, and it is reported for a
// specification decision rather than settled here.
//
// ParseBundle is retained as the input path for this package's own tests and
// fixtures, which predate the shipped container. It is not reachable from the
// binary: internal/bundle/checks builds a Bundle directly from
// already-authenticated records. The equivalence between the two record
// classifications is pinned by a test in that package, so this path cannot
// drift into passing against a container the verifier no longer accepts.
type Bundle struct {
	Window      *evidence.Record
	Populations []*evidence.Record
	Gaps        []*evidence.Record
	Other       []*evidence.Record
}

// ParseBundle reads a JSON array of complete evidence records.
//
// Exactly one AttestationWindow is required. Zero means there is nothing to
// recompute; more than one means the verdict would depend on which the
// verifier happened to pick, and a bundle carrying two conclusions is not a
// bundle whose status can be reproduced.
func ParseBundle(data []byte) (*Bundle, error) {
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, errf(CodeBundleShape,
			"bundle must be a JSON array of complete evidence records: %v", err)
	}
	b := &Bundle{}
	for i, item := range raw {
		rec, err := evidence.ParseRecord(item)
		if err != nil {
			return nil, errf(CodeBundleShape, "bundle entry %d: %v", i, err)
		}
		switch rec.RecordType() {
		case "AttestationWindow":
			if b.Window != nil {
				return nil, errf(CodeBundleShape,
					"bundle carries more than one AttestationWindow; the status "+
						"reproduced would depend on which one the verifier chose")
			}
			b.Window = rec
		case "PopulationRecord":
			b.Populations = append(b.Populations, rec)
		case "CoverageGap":
			b.Gaps = append(b.Gaps, rec)
		default:
			b.Other = append(b.Other, rec)
		}
	}
	if b.Window == nil {
		return nil, errf(CodeBundleShape,
			"bundle carries no AttestationWindow; there is no coverage claim to recompute")
	}
	return b, nil
}

// Result is the recomputation. Every field is derived from the bundle: none is
// copied from the attestation's own claim about itself.
type Result struct {
	Window Interval

	// DenominatorClass is read from the record — it is an input, being the
	// output of the §7 qualification procedure — but everything downstream of
	// it is recomputed from it rather than taken from the record.
	DenominatorClass Class

	// ClaimedLevel is what the record claims. AdmissibleLevel is recomputed
	// from DenominatorClass through the §6 lattice, independently of it.
	ClaimedLevel    Level
	AdmissibleLevel Level

	// CappedByClass is recomputed, not read. See the note in recheckLattice.
	CappedByClass        bool
	CappedByClassDecided bool

	// RatioEligible is recomputed from the class (CM-009/ES-017).
	RatioEligible bool
	// Ratio is the record's ratio as written, or "" where it is null.
	Ratio string

	// Covered and Gaps partition Window exactly (CM-014). Gaps are derived
	// from the signed CoverageGap records in the bundle, not from the
	// attestation's gaps[] list; Covered is the complement.
	Covered []Interval
	Gaps    []Interval

	Assertions attestation.AssertionSet

	// Findings are determinate rule violations: things the specification
	// settles and the bundle got wrong.
	Findings []*Error
	// Unresolved are things this verifier could not check, because the
	// specification does not determine them or the bundle does not carry what
	// they would be checked against. They are never findings and never a pass:
	// "I could not check" and "this is invalid" are different claims.
	Unresolved []string
}

// Reproduced reports whether the recomputation both found no violation and was
// able to check everything it needed to.
func (r *Result) Reproduced() bool { return len(r.Findings) == 0 && len(r.Unresolved) == 0 }

// Valid reports whether any determinate rule was broken.
func (r *Result) Valid() bool { return len(r.Findings) == 0 }

func (r *Result) fail(err *Error) { r.Findings = append(r.Findings, err) }

func (r *Result) unresolved(s string) { r.Unresolved = append(r.Unresolved, s) }

// Recompute re-derives an attestation's coverage claim from the bundle.
//
// **CM-013 — purity.** This is a pure function of its argument. It performs no
// I/O, consults no clock, reads no package state, and does not mutate the
// bundle or any record in it: parsed records are read through jcs.Object
// accessors, which return values rather than handles into the record, and
// every list in Result is sorted before it is returned so that no result can
// depend on Go's map iteration order. determinism_test.go property-tests this.
//
// **No vector exercises any of this.** tests/vectors/vectors-v0.1.json contains
// no coverage operation: the corpus covers canonicalize, sign_record,
// verify_signature, verify_attestation_signatures, verify_stream,
// verify_ingestion_receipt, verify_record_origin_signature, validate_record and
// verify_canonical_evidence_record, and nothing else. Under ES-029 the vectors
// are the authority where prose and implementation disagree, so the rules below
// rest on the prose alone and have no cross-implementation agreement behind
// them. Where the prose did not determine an answer this function records an
// Unresolved entry rather than choosing one (AG-017).
func Recompute(b *Bundle) (*Result, error) {
	body, err := bodyOf(b.Window)
	if err != nil {
		return nil, err
	}
	r := &Result{}

	window, err := windowInterval(body)
	if err != nil {
		return nil, err
	}
	r.Window = window

	class, err := classOf(body)
	if err != nil {
		return nil, err
	}
	r.DenominatorClass = class
	r.AdmissibleLevel = AdmissibleLevel(class)
	r.RatioEligible = RatioEligible(class)

	recheckLattice(r, body)
	recheckRatio(r, b, body)
	recheckCounts(r, b, body)
	recheckGaps(r, b, body)
	recheckAssertions(r, body)

	sort.Strings(r.Unresolved)
	return r, nil
}

func bodyOf(rec *evidence.Record) (*jcs.Object, error) {
	raw, _ := rec.Obj.Get("body")
	body, ok := raw.(*jcs.Object)
	if !ok {
		return nil, errf(CodeBundleShape, "AttestationWindow body must be an object")
	}
	return body, nil
}

func classOf(body *jcs.Object) (Class, error) {
	raw, _ := body.Get("denominator_class")
	s, ok := raw.(string)
	if !ok {
		return classInvalid, errf(CodeClassUnknown,
			"denominator_class must be a string naming a §3 class (CM-003)")
	}
	return ParseClass(s)
}

func windowInterval(body *jcs.Object) (Interval, error) {
	start, err := timestamp(body, "window_start")
	if err != nil {
		return Interval{}, err
	}
	end, err := timestamp(body, "window_end")
	if err != nil {
		return Interval{}, err
	}
	// A window whose end does not follow its start is not a window. Equal
	// bounds are refused too: an instantaneous window has no interval for
	// CM-014 to partition, and every coverage claim over it is vacuous.
	if !start.Before(end) {
		return Interval{}, errf(CodeWindowInvalid,
			"window_end %s does not follow window_start %s",
			end.Format(time.RFC3339Nano), start.Format(time.RFC3339Nano))
	}
	return Interval{Start: start, End: end}, nil
}

// timestamp reads an ES-002 timestamp: RFC 3339, explicit offset, at least
// millisecond precision.
func timestamp(obj *jcs.Object, key string) (time.Time, error) {
	raw, ok := obj.Get(key)
	if !ok {
		return time.Time{}, errf(CodeWindowInvalid, "missing %q", key)
	}
	s, ok := raw.(string)
	if !ok {
		return time.Time{}, errf(CodeWindowInvalid,
			"%s must be an RFC 3339 string with an explicit offset (ES-002)", key)
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, errf(CodeWindowInvalid,
			"%s %q is not RFC 3339 with an explicit offset (ES-002)", key, s)
	}
	if !strings.Contains(s, ".") {
		return time.Time{}, errf(CodeWindowInvalid,
			"%s %q lacks the millisecond precision ES-002 requires", key, s)
	}
	return t, nil
}

// recheckLattice is CM-008 and ES-018.
//
// The class-admissible level is recomputed from denominator_class through the
// §6 table. The record's own `capped_by_class` is never consulted: the flag is
// the issuer's account of whether the cap bound, and taking the issuer's word
// for whether the issuer's cap applied is the one thing CM-008 says must be
// "enforced in code, not by convention".
//
// What the bundle permits us to recompute is one-sided, and the asymmetry is
// worth being precise about. `claimed <= admissible` is fully determined and is
// the overclaim direction — a C3 window claiming reconciled is refused here.
// The other operand of the minimum, the level the *evidence* supports, is not
// determined: coverage-methodology.md §5 describes each level in prose but no
// requirement in any document maps record types to a level, so a verifier
// cannot derive evidence-supported from the bundle. That is recorded as
// Unresolved rather than guessed.
//
// `capped_by_class` is still partly recomputable without it. If the claim sits
// strictly below the admissible ceiling then the minimum was taken from the
// evidence and the cap did not bind, so the flag MUST be false — a record
// claiming otherwise is refused. If the claim sits exactly at the ceiling the
// flag is genuinely undecidable from the bundle, because evidence at, above, or
// below the ceiling all produce the same claimed level, and it is left
// undecided rather than assumed to agree.
func recheckLattice(r *Result, body *jcs.Object) {
	raw, _ := body.Get("coverage_level")
	s, ok := raw.(string)
	if !ok {
		r.fail(errf(CodeLevelUnknown, "coverage_level must be a string"))
		return
	}
	claimed, err := ParseLevel(s)
	if err != nil {
		r.fail(err.(*Error))
		return
	}
	r.ClaimedLevel = claimed

	if claimed > r.AdmissibleLevel {
		r.fail(errf(CodeLevelExceedsAdmissible,
			"coverage_level %q exceeds %q, the maximum the §6 lattice admits at "+
				"denominator class %s; CM-008 makes the claim the minimum of "+
				"evidence-supported and class-admissible",
			claimed, r.AdmissibleLevel, r.DenominatorClass))
		return
	}

	if claimed < r.AdmissibleLevel {
		r.CappedByClass = false
		r.CappedByClassDecided = true
	} else {
		r.unresolved(
			"capped_by_class: the claim sits exactly at the class-admissible " +
				"level, and the evidence-supported level is not derivable from " +
				"the bundle, so whether the cap bound cannot be recomputed")
	}

	declared, present := body.Get("capped_by_class")
	if !present {
		// Absence is no longer an unresolved on its own. §5.13 now carries the
		// member, required from schema 2.0.0 and optional by presence at 1.0.0,
		// so an absent flag at 1.0.0 is conformant rather than contradictory.
		//
		// More to the point, absence does not stop the verifier knowing the
		// answer. Where the claim sits strictly below the ceiling, ES-018 makes
		// the flag determinately false whether or not the record says so, and
		// that case is already resolved above. Where it sits at the ceiling the
		// unresolved above already fires, and it fires for the real reason —
		// evidence_supported_level is not derivable from the bundle — rather
		// than for the absence of a field that would not have settled it
		// either, since a self-asserted flag is a claim to check, not evidence.
		return
	}
	flag, ok := declared.(bool)
	if !ok {
		r.fail(errf(CodeCappedFlagMisreported,
			"capped_by_class must be a boolean (ES-018)"))
		return
	}
	// ES-018's comparison is strict: capped_by_class is true iff
	// class_admissible < evidence_supported, and false where they are equal.
	// Below the ceiling, min() forces evidence_supported to equal the claim, so
	// the flag is determinately false and a record asserting true is refused.
	// At the ceiling nothing here can decide it, and the unresolved above says
	// so rather than accepting the record's own account of itself.
	if r.CappedByClassDecided && flag != r.CappedByClass {
		r.fail(errf(CodeCappedFlagMisreported,
			"capped_by_class is %v, but the claimed level %q is below the "+
				"class-admissible %q, so a stronger denominator class would not "+
				"have produced a higher claim and the cap did not bind "+
				"(CM-008, ES-018)",
			flag, claimed, r.AdmissibleLevel))
	}
}

// recheckRatio is ES-017, CM-009, ES-011 and ES-012.
//
// ES-017 makes the null a claim about the world: at C4 and C5 the population is
// not independently enumerable, so a ratio does not exist to be emitted, and
// serialising zero or omitting the field are both non-conformant. ES-002b
// classes coverage_ratio as required-and-nullable, which is why absence is a
// finding rather than an omitted option.
//
// ES-011 and ES-012 extend the same refusal to a truncated enumeration at any
// class: a capped or incompletely paginated PopulationRecord is not a
// denominator, so the ratio is null there too (ES-S-021 — null, not zero).
// Those flags are read from the referenced PopulationRecords in the bundle, so
// the refusal does not depend on the attestation admitting to the truncation.
func recheckRatio(r *Result, b *Bundle, body *jcs.Object) {
	raw, present := body.Get("coverage_ratio")
	if !present {
		r.fail(errf(CodeRatioMissing,
			"coverage_ratio is absent; ES-017 makes omission non-conformant and "+
				"ES-002b makes the member required and nullable"))
		return
	}

	truncated, resolved := truncationState(r, b, body)
	mustBeNull := !r.RatioEligible || truncated

	if raw == nil {
		if r.RatioEligible && !truncated && resolved {
			// A null at an eligible class with an intact denominator is not a
			// violation of anything stated: CM-001 permits withholding, and
			// withholding is never the overclaim direction. Recorded so a
			// reviewer sees it was noticed.
			r.unresolved("coverage_ratio: null at class " + r.DenominatorClass.String() +
				", which CM-009 permits a ratio for; withholding is not refused")
		}
		return
	}

	if mustBeNull {
		reason := "denominator class " + r.DenominatorClass.String() +
			" emits no coverage ratio (CM-009, ES-017)"
		if truncated {
			reason = "a referenced PopulationRecord is truncated " +
				"(result_cap_hit or pagination_complete false); a truncated " +
				"enumeration is not a denominator (ES-011, ES-012)"
		}
		r.fail(errf(CodeRatioMustBeNull,
			"coverage_ratio is present with a value, but %s. The null is a claim "+
				"about the world and must be explicit", reason))
		return
	}

	s, ok := raw.(string)
	if !ok {
		// ES-002 forbids IEEE-754 floats anywhere in a signed record and
		// requires quantity values to be strings; the canonicalizer already
		// refuses a fractional token under ES-002a, so a numeric ratio can only
		// arrive as an integer 0 or 1, which is still the prohibited encoding.
		r.fail(errf(CodeRatioNotString,
			"coverage_ratio must be a decimal string; ES-002 forbids representing "+
				"a quantity as a JSON number and ES-002a refuses a fractional token"))
		return
	}
	if err := validRatioString(s); err != nil {
		r.fail(err)
		return
	}
	r.Ratio = s

	// ES-017 now states the formula, so the value is recomputed rather than
	// accepted. Until it did, a bundle claiming "1.0" over a population it had
	// matched nothing in reproduced cleanly — the overclaim direction, and the
	// reason this was the last thing blocking a verdict of valid.
	recomputeRatio(r, b, body, s)
}

// recomputeRatio derives the ratio from the counts and the enumerated
// population and compares it to the claim, per ES-017.
func recomputeRatio(r *Result, b *Bundle, body *jcs.Object, claimed string) {
	counts, ok := countsObject(body)
	if !ok {
		r.unresolved("coverage_ratio: counts is not readable, so the ratio's " +
			"numerator cannot be derived")
		return
	}
	matched, okM := countMember(counts, "matched")
	outOfScope, okO := countMember(counts, "out_of_scope")
	if !okM || !okO {
		// out_of_scope is optional by presence at schema 1.0.0 and required
		// from 2.0.0; where it is absent the denominator exclusion cannot be
		// applied and the ratio is not recomputable rather than assumed zero.
		r.unresolved("coverage_ratio: counts.matched and counts.out_of_scope are " +
			"both required to derive the ratio (ES-017) and at least one is absent")
		return
	}
	population, known := populationTotal(b, body)
	if !known {
		r.unresolved("coverage_ratio: the enumerated population is not resolvable " +
			"from the bundle, so the ratio cannot be derived")
		return
	}

	// One derivation, used by both this path and the conformance runner. Two
	// copies of the denominator rule could drift, and a mutation test proved
	// they would drift silently: changing one left the other's tests green.
	want, err := RatioFor(matched, population, outOfScope)
	if err != nil {
		r.fail(err.(*Error))
		return
	}
	denominator := population - outOfScope
	if claimed != want {
		r.fail(errf(CodeRatioMismatch,
			"coverage_ratio is %q, but %d matched over an in-scope denominator "+
				"of %d (population %d less %d out-of-scope) is %q (ES-017)",
			claimed, matched, denominator, population, outOfScope, want))
	}
}

// RatioFor is ES-017's formula as a pure function, exposed for the conformance
// vectors. It is the same arithmetic recomputeRatio performs; a runner that
// re-derived the ratio itself would be testing the vector against the runner.
func RatioFor(matched, population, outOfScope int64) (string, error) {
	denominator := population - outOfScope
	if denominator < 0 {
		return "", errf(CodeRatioMismatch,
			"out_of_scope %d exceeds population %d", outOfScope, population)
	}
	if denominator == 0 {
		return "", errf(CodeRatioMustBeNull,
			"the in-scope denominator is zero, so ES-017 requires null")
	}
	if matched > denominator {
		return "", errf(CodeRatioMismatch,
			"matched %d exceeds the in-scope denominator %d", matched, denominator)
	}
	return formatRatio(matched, denominator), nil
}

// formatRatio renders matched/denominator as ES-017's fixed four-decimal
// string, truncating toward zero.
//
// The arithmetic is integer throughout. Computing this as a float and
// formatting with %.4f would round to nearest and would reintroduce exactly
// the floating-point divergence ES-002a exists to keep out of this system: two
// implementations could then disagree on the last digit for reasons neither
// could see. Scaling first and dividing once keeps the result exact.
func formatRatio(matched, denominator int64) string {
	scaled := matched * 10000 / denominator // truncates toward zero
	return fmt.Sprintf("%d.%04d", scaled/10000, scaled%10000)
}

func countsObject(body *jcs.Object) (*jcs.Object, bool) {
	raw, ok := body.Get("counts")
	if !ok {
		return nil, false
	}
	counts, ok := raw.(*jcs.Object)
	return counts, ok
}

func countMember(counts *jcs.Object, key string) (int64, bool) {
	raw, ok := counts.Get(key)
	if !ok {
		return 0, false
	}
	n, ok := raw.(int64)
	if !ok || n < 0 {
		return 0, false
	}
	return n, true
}

// validRatioString enforces ES-017's encoding: a decimal string in [0, 1] with
// exactly four decimal places and no trailing-zero stripping.
//
// The fixed scale is not cosmetic. QA-008 compares golden bundles
// byte-for-byte, so a free scale would let two implementations that computed
// the same ratio disagree on bytes — a diff reporting a divergence that says
// nothing about either of them. "1", "1.0" and "1.0000" are one value with
// three spellings, and only the last is conformant.
func validRatioString(s string) *Error {
	malformed := errf(CodeRatioMalformed,
		"coverage_ratio %q is not a decimal string in [0, 1]", s)
	if s == "" {
		return malformed
	}
	intPart, fracPart, hasFrac := strings.Cut(s, ".")
	if !hasFrac {
		return errf(CodeRatioMalformed,
			"coverage_ratio %q has no decimal part; ES-017 requires exactly four, "+
				"so %q is a different spelling of the same value and only one is "+
				"conformant", s, s+".0000")
	}
	if intPart != "0" && intPart != "1" {
		return malformed
	}
	if len(fracPart) != 4 {
		return errf(CodeRatioMalformed,
			"coverage_ratio %q has %d decimal places; ES-017 requires exactly "+
				"four, with no trailing-zero stripping, so that a byte-for-byte "+
				"golden comparison under QA-008 cannot fail on spelling alone",
			s, len(fracPart))
	}
	for _, c := range fracPart {
		if c < '0' || c > '9' {
			return malformed
		}
	}
	if intPart == "1" && strings.Trim(fracPart, "0") != "" {
		return errf(CodeRatioMalformed,
			"coverage_ratio %q exceeds 1", s)
	}
	return nil
}

// truncationState resolves the referenced PopulationRecords and reports whether
// any is truncated, and whether every reference resolved.
//
// An unresolved reference is not treated as "no truncation". ES-011 makes a
// truncated enumeration disqualifying, and a bundle that omits the population
// record is a bundle in which the disqualifying condition cannot be ruled out —
// so the ratio is unverifiable rather than fine. Under the CM-021 adversary
// assumption, the party that benefits from a favourable number is the party
// assembling the bundle.
func truncationState(r *Result, b *Bundle, body *jcs.Object) (truncated, resolved bool) {
	refsRaw, ok := body.Get("population_record_refs")
	if !ok {
		r.unresolved("population_record_refs: absent")
		return false, false
	}
	refs, ok := refsRaw.([]jcs.Value)
	if !ok {
		r.fail(errf(CodeBundleShape, "population_record_refs must be an array"))
		return false, false
	}
	if len(refs) == 0 {
		return false, true
	}

	index := map[string]*evidence.Record{}
	for _, rec := range b.Populations {
		index[rec.RecordID()] = rec
		if digest, err := rec.CompleteDigest(); err == nil {
			index[digest] = rec
		}
	}

	resolved = true
	seen := map[*evidence.Record]bool{}
	for _, refRaw := range refs {
		ref, ok := refRaw.(string)
		if !ok {
			r.fail(errf(CodeBundleShape,
				"population_record_refs entries must be strings"))
			resolved = false
			continue
		}
		// A reference is matched on record_id or on the ES-006a complete
		// digest. Nothing states which identifies a PopulationRecord; matching
		// either cannot produce a false accept, because an unmatched reference
		// stays unresolved under both readings.
		rec, found := index[ref]
		if !found {
			r.unresolved("population_record_refs: " + ref +
				" is not in the bundle, so ES-011/ES-012 truncation cannot be ruled out")
			resolved = false
			continue
		}
		if seen[rec] {
			r.fail(errf(CodePopulationRefDuplicate,
				"population_record_refs repeats %q; one signed population cannot be counted twice",
				ref))
			resolved = false
			continue
		}
		seen[rec] = true
		popBody, err := bodyOf(rec)
		if err != nil {
			resolved = false
			continue
		}
		capHit, capOK := requiredBoolMember(r, popBody, "result_cap_hit")
		paginationComplete, pageOK := requiredBoolMember(r, popBody, "pagination_complete")
		if !capOK || !pageOK {
			resolved = false
			continue
		}
		if capHit || !paginationComplete {
			truncated = true
		}
	}
	return truncated, resolved
}

// refOf reads the envelope boundary_ref. A schema-2 constitutive record omits
// it (ES-031), but neither AttestationWindow nor CoverageGap is constitutive,
// so both carry one and comparing them is well defined.
func refOf(rec *evidence.Record) string {
	raw, _ := rec.Obj.Get("boundary_ref")
	s, _ := raw.(string)
	return s
}

func requiredBoolMember(r *Result, obj *jcs.Object, key string) (bool, bool) {
	raw, ok := obj.Get(key)
	if !ok {
		r.fail(errf(CodeBundleShape, "PopulationRecord body.%s is absent", key))
		return false, false
	}
	v, ok := raw.(bool)
	if !ok {
		r.fail(errf(CodeBundleShape,
			"PopulationRecord body.%s must be a boolean", key))
		return false, false
	}
	return v, true
}

// recheckCounts applies what CM-012 determines about the classification counts.
//
// CM-012 makes classification exhaustive over six buckets: matched,
// unmatched-with-evidence, unmatched-without-evidence, duplicate, ambiguous,
// and out-of-scope. §5.13's `counts` member enumerates only the first five, so
// the counts cannot be checked to *equal* the enumerated population — the sixth
// bucket has nowhere to be recorded. What remains determinate is the
// inequality: five disjoint subsets of the denominator cannot together exceed
// it. That is still the overclaim direction, which is the one worth checking.
func recheckCounts(r *Result, b *Bundle, body *jcs.Object) {
	raw, ok := body.Get("counts")
	if !ok {
		r.fail(errf(CodeCountsInvalid, "counts is absent (evidence-spec.md §5.13)"))
		return
	}
	counts, ok := raw.(*jcs.Object)
	if !ok {
		r.fail(errf(CodeCountsInvalid, "counts must be an object"))
		return
	}
	if r.DenominatorClass == C4 || r.DenominatorClass == C5 {
		r.unresolved(
			"count_conservation: denominator classes C4 and C5 do not establish an " +
				"independently enumerable population, so the supplied count cannot " +
				"independently prove conservation")
	}
	// The six CM-012 buckets, now enumerated by §5.13 as well. ES-005 keeps
	// body open, so a member this verifier does not recognise must not be
	// folded into the total: an unrelated integer would inflate the sum and
	// produce a false *rejection*, which is a different defect from the one
	// being looked for but still a verifier reporting something the evidence
	// does not say.
	buckets := map[string]bool{
		"matched": true, "unmatched_with_evidence": true,
		"unmatched_without_evidence": true, "duplicate": true,
		"ambiguous": true, "out_of_scope": true,
	}
	var total int64
	var counted int
	for _, key := range counts.Keys() {
		v, _ := counts.Get(key)
		n, ok := v.(int64)
		if !ok {
			r.fail(errf(CodeCountsInvalid,
				"counts.%s must be an integer (ES-002a)", key))
			return
		}
		if n < 0 {
			r.fail(errf(CodeCountsInvalid, "counts.%s is negative", key))
			return
		}
		if !buckets[key] {
			r.unresolved("counts: member " + key +
				" is not a CM-012 classification bucket and was not counted")
			continue
		}
		counted++
		total += n
	}
	if counted == 0 {
		r.unresolved("counts: no CM-012 classification bucket present, so " +
			"exhaustiveness cannot be checked")
		return
	}

	population, known := populationTotal(b, body)
	if !known {
		r.unresolved("counts: the enumerated population is not resolvable from " +
			"the bundle, so counts cannot be checked against it")
		return
	}
	if total > population {
		r.fail(errf(CodeCountsExceedPopulation,
			"counts sum to %d over an enumerated population of %d; the CM-012 "+
				"buckets are disjoint subsets of the denominator and cannot exceed it",
			total, population))
		return
	}

	// §5.13 now enumerates all six CM-012 buckets. Where all six are present
	// the check strengthens from an inequality to an equality: CM-012 admits no
	// residual bucket and ES-015 closes the enumeration, so every enumerated
	// action falls into exactly one of them and the six must account for the
	// denominator exactly. A shortfall is the silent-overclaim shape — actions
	// in the population that the attestation classified as nothing at all.
	//
	// Until §5.13 was corrected this could only ever be an inequality, because
	// out_of_scope had nowhere to be reported and a conformant attestation
	// could legitimately sum to less than its population.
	if counted < len(buckets) {
		missing := make([]string, 0, len(buckets))
		for name := range buckets {
			if !counts.Has(name) {
				missing = append(missing, name)
			}
		}
		sort.Strings(missing)
		r.unresolved("counts: " + strings.Join(missing, ", ") +
			" absent from the counts object, so the six CM-012 buckets cannot be " +
			"checked for exhaustiveness and only the inequality holds")
		return
	}
	if total != population {
		r.fail(errf(CodeCountsExceedPopulation,
			"the six CM-012 buckets sum to %d over an enumerated population of "+
				"%d; the enumeration is closed and admits no residual, so every "+
				"enumerated action must fall into exactly one bucket",
			total, population))
	}
}

// populationTotal sums the count of every referenced PopulationRecord.
//
// Summing is an assumption: §5.13 carries one `counts` object for a window that
// may reference several PopulationRecords (one per action family under CM-003),
// and no requirement says how the per-family denominators combine. Summation is
// the only reading under which the single counts object is comparable to
// anything at all, and it is used only for the one-sided inequality above.
func populationTotal(b *Bundle, body *jcs.Object) (int64, bool) {
	refsRaw, ok := body.Get("population_record_refs")
	if !ok {
		return 0, false
	}
	refs, ok := refsRaw.([]jcs.Value)
	if !ok || len(refs) == 0 {
		return 0, false
	}
	index := map[string]*evidence.Record{}
	for _, rec := range b.Populations {
		index[rec.RecordID()] = rec
		if digest, err := rec.CompleteDigest(); err == nil {
			index[digest] = rec
		}
	}
	var total int64
	seen := map[*evidence.Record]bool{}
	for _, refRaw := range refs {
		ref, ok := refRaw.(string)
		if !ok {
			return 0, false
		}
		rec, found := index[ref]
		if !found {
			return 0, false
		}
		if seen[rec] {
			return 0, false
		}
		seen[rec] = true
		popBody, err := bodyOf(rec)
		if err != nil {
			return 0, false
		}
		raw, _ := popBody.Get("count")
		n, ok := raw.(int64)
		if !ok || n < 0 {
			return 0, false
		}
		total += n
	}
	return total, true
}

// recheckGaps is CM-014 and CM-015.
//
// The unknown intervals are re-derived from the signed CoverageGap records the
// bundle carries, and the covered intervals are the complement of those within
// the window. Neither is read from the attestation's own gaps[] list, which is
// the whole point: an attestation that holds a signed gap record and omits it
// from its list is claiming coverage over an interval it has itself recorded as
// unknown, and a verifier that partitions the window using the claimed list can
// never see that. CM-015 makes the signed gap record the evidence.
//
// The claimed list is then checked for omissions against the derived set. Where
// an element of gaps[] cannot be resolved to a record — its encoding is not
// stated anywhere, and the one published AttestationWindow vector has
// `"gaps": []` — the comparison is left unresolved rather than assumed to
// agree.
func recheckGaps(r *Result, b *Bundle, body *jcs.Object) {
	derived := make([]Interval, 0, len(b.Gaps))
	for _, rec := range b.Gaps {
		// A gap governs the window only if it is under the same tenant and
		// boundary version. Without this a CoverageGap from another tenant, or
		// from a different boundary version, could be dropped into the bundle
		// and counted — an unknown interval manufactured from evidence that
		// says nothing about this window (§3, ES-031).
		if rec.TenantID() != b.Window.TenantID() ||
			refOf(rec) != refOf(b.Window) {
			r.fail(errf(CodeGapInvalid,
				"CoverageGap %s is under tenant %q boundary %q, not the "+
					"attestation's tenant %q boundary %q",
				rec.RecordID(), rec.TenantID(), refOf(rec),
				b.Window.TenantID(), refOf(b.Window)))
			continue
		}
		gapBody, err := bodyOf(rec)
		if err != nil {
			r.fail(errf(CodeGapInvalid, "CoverageGap %s: %v", rec.RecordID(), err))
			continue
		}
		start, err := timestamp(gapBody, "gap_start")
		if err != nil {
			r.fail(errf(CodeGapInvalid, "CoverageGap %s: %v", rec.RecordID(), err))
			continue
		}
		end, err := timestamp(gapBody, "gap_end")
		if err != nil {
			r.fail(errf(CodeGapInvalid, "CoverageGap %s: %v", rec.RecordID(), err))
			continue
		}
		iv := Interval{Start: start, End: end}
		if iv.Empty() {
			r.fail(errf(CodeGapInvalid,
				"CoverageGap %s: gap_end does not follow gap_start", rec.RecordID()))
			continue
		}
		clipped, inside := iv.Clip(r.Window)
		if !inside {
			// CM-016 puts the unknown interval adjacent to the claim it
			// qualifies. A gap wholly outside the window qualifies a different
			// window, and carrying it here would put unknown time into a
			// partition of an interval it does not intersect.
			r.fail(errf(CodeGapOutsideWindow,
				"CoverageGap %s covers %s, which lies wholly outside window %s",
				rec.RecordID(), iv, r.Window))
			continue
		}
		derived = append(derived, clipped)
	}

	r.Gaps = mergeIntervals(derived)
	r.Covered = subtract(r.Window, r.Gaps)
	if err := checkConservation(r.Window, r.Covered, r.Gaps); err != nil {
		r.fail(err.(*Error))
	}

	claimedRaw, ok := body.Get("gaps")
	if !ok {
		r.fail(errf(CodeGapInvalid, "gaps is absent (evidence-spec.md §5.13)"))
		return
	}
	claimed, ok := claimedRaw.([]jcs.Value)
	if !ok {
		r.fail(errf(CodeGapInvalid, "gaps must be an array"))
		return
	}
	if len(b.Gaps) == 0 {
		if len(claimed) > 0 {
			r.unresolved("gaps: the attestation declares gaps but the bundle " +
				"carries no signed CoverageGap record to reproduce them from (CM-015)")
		}
		return
	}
	refs := map[string]bool{}
	shapesKnown := true
	for _, item := range claimed {
		s, ok := item.(string)
		if !ok {
			shapesKnown = false
			continue
		}
		refs[s] = true
	}
	if !shapesKnown {
		r.unresolved("gaps: no requirement states how a gaps[] element is " +
			"encoded, so the declared list could not be compared with the " +
			"signed CoverageGap records")
		return
	}
	for _, rec := range b.Gaps {
		digest, err := rec.CompleteDigest()
		if err == nil && refs[digest] {
			continue
		}
		if refs[rec.RecordID()] {
			continue
		}
		r.fail(errf(CodeGapOmittedFromClaim,
			"signed CoverageGap %s covers part of the window but is not declared "+
				"in gaps[]; CM-014 forbids an unknown interval being absorbed",
			rec.RecordID()))
	}
}

// recheckAssertions closes the AR-003 catalogue over the emitted set.
func recheckAssertions(r *Result, body *jcs.Object) {
	set, err := attestation.ReadAssertions(body)
	if err != nil {
		r.fail(&Error{Code: attestation.Code(err), Msg: err.Error()})
		return
	}
	r.Assertions = set
	for _, note := range set.Undetermined {
		r.unresolved("assertions: " + note)
	}
}
