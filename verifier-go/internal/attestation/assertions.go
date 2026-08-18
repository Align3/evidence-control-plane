package attestation

import (
	"github.com/Align3/evidence-control-plane/verifier-go/internal/jcs"
)

// AssertionSet is the result of reading an AttestationWindow's assertions[].
type AssertionSet struct {
	// IDs are the catalogued assertions the window emits, in the order the
	// record lists them. Every member is catalogued: ReadAssertions refuses
	// rather than returning an uncatalogued one (AR-003).
	IDs []AssertionID
	// Undetermined records assertion elements whose encoding this
	// specification does not fix, so the verifier reports that it could not
	// check them rather than that they were fine. See the note on
	// ReadAssertions.
	Undetermined []string
}

// Has reports whether the set emits an assertion.
func (s AssertionSet) Has(id AssertionID) bool {
	for _, got := range s.IDs {
		if got == id {
			return true
		}
	}
	return false
}

// ReadAssertions extracts and closes the catalogue over an AttestationWindow
// body's assertions[] member (evidence-spec.md §5.13).
//
// **Specification gap, handled rather than guessed.** §5.13 names `assertions[]`
// as a member and AR-004 requires each assertion to carry its own scope and
// count, but nothing in evidence-spec.md, coverage-methodology.md or
// attestation-reliance.md states the encoding of an element, and the only
// published vector carrying an AttestationWindow
// (`verify-customer-and-issuer-signatures`) has `"assertions": []`. There is
// therefore no normative shape to implement.
//
// ES-036 defines the routing member as `assertion_id`. The remaining payload
// schema is not yet normative, so a catalogued object remains undetermined
// after its ID is checked; an off-catalogue ID is a determinate refusal.
func ReadAssertions(body *jcs.Object) (AssertionSet, error) {
	var set AssertionSet
	raw, ok := body.Get("assertions")
	if !ok {
		return set, errf(CodeAssertionsNotArray,
			"AttestationWindow body is missing assertions[] (evidence-spec.md §5.13)")
	}
	items, ok := raw.([]jcs.Value)
	if !ok {
		return set, errf(CodeAssertionsNotArray,
			"AttestationWindow assertions must be an array (evidence-spec.md §5.13)")
	}
	seen := map[string]bool{}
	for i, item := range items {
		value, ok := item.(*jcs.Object)
		if !ok {
			return AssertionSet{}, errf(CodeAssertionInvalid,
				"assertions[%s] must be an object carrying assertion_id", itoa(i))
		}
		raw, present := value.Get("assertion_id")
		code, ok := raw.(string)
		if !present || !ok || code == "" {
			return AssertionSet{}, errf(CodeAssertionInvalid,
				"assertions[%s].assertion_id must be a non-empty string", itoa(i))
		}
		id, err := ParseAssertionID(code)
		if err != nil {
			return AssertionSet{}, err
		}
		// AR-004 gives each assertion its own scope and count. One catalogue
		// row emitted twice is two claims about the same subject, and a
		// relying party reading the second has no way to know which governs.
		if seen[code] {
			return AssertionSet{}, errf(CodeAssertionDuplicated,
				"assertion %s is emitted more than once", code)
		}
		seen[code] = true
		set.IDs = append(set.IDs, id)
		set.Undetermined = append(set.Undetermined,
			"assertion payload "+code+" has no normative scope-and-count schema")
	}
	return set, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
