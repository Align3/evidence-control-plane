package coverage

import (
	"encoding/json"
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
		// ES-018 requires the member; §5.13's body enumeration omits it and no
		// vector carries it. Reported as unresolved rather than as a finding,
		// because the two halves of one section disagree about whether it is
		// required and nothing authoritative breaks the tie.
		r.unresolved("capped_by_class: absent from the record; ES-018 requires it " +
			"but the §5.13 body enumeration omits it and no vector carries it")
		return
	}
	flag, ok := declared.(bool)
	if !ok {
		r.fail(errf(CodeCappedFlagMisreported,
			"capped_by_class must be a boolean (ES-018)"))
		return
	}
	if r.CappedByClassDecided && flag != r.CappedByClass {
		r.fail(errf(CodeCappedFlagMisreported,
			"capped_by_class is %v, but the claimed level %q is below the "+
				"class-admissible %q, so the cap did not bind (CM-008, ES-018)",
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

	// The ratio's *value* is not recomputed, and saying so is the point.
	//
	// coverage_ratio has no definition anywhere in this corpus. ES-017 states
	// when it must be null, CM-009 states which classes emit one, and A-04
	// describes "of the enumerated population of N actions, M were matched to
	// evidence at level L" — but no requirement says the ratio is M/N, nor
	// which of the CM-012 buckets count toward M, nor whether out-of-scope
	// records leave the denominator. A verifier that picked one reading and
	// reported agreement would be reporting agreement with its own guess.
	//
	// Without this line a bundle claiming "1.0" over a population it matched
	// nothing in would reproduce cleanly, which is the overclaim direction and
	// exactly what this package exists to refuse.
	r.unresolved("coverage_ratio: present with value " + s +
		", but no requirement defines the ratio's numerator or denominator, " +
		"so its value cannot be independently recomputed")
}

// validRatioString checks the decimal-string form the only published
// AttestationWindow vector uses ("1.0") and bounds it to [0, 1].
//
// **Specification gap.** No requirement states coverage_ratio's encoding.
// ES-017 says only that it must be null at C4/C5; ES-002 requires quantity
// values to be strings "with an accompanying unit or currency field", and
// §5.13 declares no unit member for this one. The decimal string below is read
// off the vector, which ES-029 makes authoritative — but the vector fixes one
// value, not a grammar, so scale is undetermined: nothing says whether "1.0",
// "1.00" and "1" are the same ratio, which matters the moment two
// implementations compare bundles byte-for-byte under QA-008.
func validRatioString(s string) *Error {
	malformed := errf(CodeRatioMalformed,
		"coverage_ratio %q is not a decimal string in [0, 1]", s)
	if s == "" {
		return malformed
	}
	intPart, fracPart, hasFrac := strings.Cut(s, ".")
	if intPart != "0" && intPart != "1" {
		return malformed
	}
	if hasFrac {
		if fracPart == "" {
			return malformed
		}
		for _, c := range fracPart {
			if c < '0' || c > '9' {
				return malformed
			}
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
		popBody, err := bodyOf(rec)
		if err != nil {
			resolved = false
			continue
		}
		if boolMember(popBody, "result_cap_hit") || !boolMemberDefaultTrue(popBody, "pagination_complete") {
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

func boolMember(obj *jcs.Object, key string) bool {
	raw, _ := obj.Get(key)
	v, _ := raw.(bool)
	return v
}

// boolMemberDefaultTrue treats a missing or non-boolean pagination_complete as
// true so that the caller's `!` turns it into "not known to be complete" only
// when the record actually says false. Record validation already requires the
// member, so this is a total-function guard rather than a policy.
func boolMemberDefaultTrue(obj *jcs.Object, key string) bool {
	raw, ok := obj.Get(key)
	if !ok {
		return true
	}
	v, ok := raw.(bool)
	if !ok {
		return true
	}
	return v
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
	// Only the CM-012 buckets are summed. ES-005 keeps body open, so a member
	// this verifier does not recognise must not be folded into the total: an
	// unrelated integer would inflate the sum and produce a false *rejection*,
	// which is a different defect from the one being looked for but still a
	// verifier reporting something the evidence does not say.
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
	}
	r.unresolved("counts: CM-012 lists six buckets but §5.13 counts enumerates " +
		"five, omitting out-of-scope, so only the inequality is checkable")
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
	for _, refRaw := range refs {
		ref, ok := refRaw.(string)
		if !ok {
			return 0, false
		}
		rec, found := index[ref]
		if !found {
			return 0, false
		}
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
