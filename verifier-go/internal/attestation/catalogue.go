// Package attestation re-checks the claims an AttestationWindow makes, against
// attestation-reliance.md and coverage-methodology.md, independently of the
// Python issuer (AC-011, AG-017). Nothing here is ported; every rule cites the
// requirement it comes from.
package attestation

import "fmt"

// Stable dotted error codes, in the family convention the vectors README fixes
// for canonicalization/signature/chain/continuity. `attestation` is a new
// family: no published vector exercises any rule in this package.
const (
	CodeAssertionOffCatalogue = "assertion.outside_catalogue"
	CodeAssertionInvalid      = "assertion.invalid"
	CodeAssertionsNotArray    = "attestation.assertions_not_array"
	CodeAssertionDuplicated   = "attestation.assertion_duplicated"
)

// Error carries a stable code. Wording is ours; the code is the result.
type Error struct {
	Code string
	Msg  string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func errf(code, format string, args ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Code extracts the dotted code from an error this package produced.
func Code(err error) string {
	if e, ok := err.(*Error); ok {
		return e.Code
	}
	return ""
}

// AssertionID is the closed AR-003 catalogue made into a type.
//
// The point of the unexported field is that AR-003 becomes unrepresentable to
// violate rather than merely checked: outside this package there is no
// expression that produces an AssertionID carrying a code the catalogue does
// not contain. A composite literal cannot set `code`, so the only inhabitants
// with a non-empty code are the ten package-level values below and whatever
// ParseAssertionID returns — and ParseAssertionID consults the same table.
//
// This is deliberately stronger than validating a string at the boundary. A
// validated string is still a string: some later call site accepts one that
// did not come through the validator, and AG-003's rule ("never add an
// assertion the attestation can emit without a requirement and a scenario")
// is then enforced by whoever remembered to call the checker. The catalogue is
// closed by the type system instead.
//
// The zero value is the one remaining inhabitant with an empty code. It is
// deliberately *not* a catalogue member: IsCatalogued reports false and String
// returns "", so a forgotten initialisation cannot masquerade as A-01.
type AssertionID struct{ code string }

// The catalogue of attestation-reliance.md §2. Adding a row here without also
// adding its requirement and its scenario is what AG-003 forbids; the basis
// string is carried so a reviewer can see the citation from the code.
var (
	A01 = AssertionID{"A-01"}
	A02 = AssertionID{"A-02"}
	A03 = AssertionID{"A-03"}
	A04 = AssertionID{"A-04"}
	A05 = AssertionID{"A-05"}
	A06 = AssertionID{"A-06"}
	A07 = AssertionID{"A-07"}
	A08 = AssertionID{"A-08"}
	A09 = AssertionID{"A-09"}
	A10 = AssertionID{"A-10"}
)

// catalogueRow records what each assertion claims and the requirement stating
// it. A-02 and A-09 cite AR-027 and AR-028 rather than the ES-009 and CM-007
// they originally named: EV-25 established that neither original citation
// stated the claim, and re-pointing at an adjacent requirement is the failure
// that story exists to prevent.
type catalogueRow struct {
	id        AssertionID
	assertion string
	basis     string
}

var catalogue = []catalogueRow{
	{A01, "Records within this window form an unbroken, signature-valid chain", "ES-006/021"},
	{A02, "The declared assurance boundary was in force for the window", "AR-027"},
	{A03, "The denominator source was of class C, qualified on date D", "CM-003/004"},
	{A04, "Of the enumerated population of N actions, M were matched to evidence at level L", "CM-008/011"},
	{A05, "The following intervals are unknown, for the stated causes", "CM-014/016"},
	{A06, "Coverage level claimed is the minimum of evidence-supported and class-admissible", "CM-008"},
	{A07, "For P actions requiring human review, review records exist with the recorded properties", "ES-013/014"},
	{A08, "For Q of those, review occurred while the action was still reversible", "ES-014"},
	{A09, "Outcomes for R actions were confirmed against the named authoritative source", "AR-028"},
	{A10, "This computation is reproducible from the referenced bundle by the named verifier version", "CM-013"},
}

var byCode = func() map[string]catalogueRow {
	m := make(map[string]catalogueRow, len(catalogue))
	for _, row := range catalogue {
		m[row.id.code] = row
	}
	return m
}()

// String renders the catalogue code, or "" for the zero value.
func (a AssertionID) String() string { return a.code }

// IsCatalogued reports whether this value names a catalogue row. It is false
// for the zero value, which is the only way to hold an AssertionID that does
// not.
func (a AssertionID) IsCatalogued() bool {
	_, ok := byCode[a.code]
	return ok
}

// Assertion returns the catalogued claim text.
func (a AssertionID) Assertion() string { return byCode[a.code].assertion }

// Basis returns the requirement the catalogue cites for this assertion.
func (a AssertionID) Basis() string { return byCode[a.code].basis }

// ParseAssertionID admits exactly the catalogue. AR-003: an assertion outside
// it may not be emitted, so a bundle claiming one is refused rather than
// reported with an unrecognised assertion carried through.
func ParseAssertionID(s string) (AssertionID, error) {
	row, ok := byCode[s]
	if !ok {
		return AssertionID{}, errf(CodeAssertionOffCatalogue,
			"assertion %q is not in the attestation-reliance.md §2 catalogue; "+
				"AR-003 closes it (AG-003)", s)
	}
	return row.id, nil
}

// Catalogue returns the closed catalogue in document order.
func Catalogue() []AssertionID {
	out := make([]AssertionID, 0, len(catalogue))
	for _, row := range catalogue {
		out = append(out, row.id)
	}
	return out
}
