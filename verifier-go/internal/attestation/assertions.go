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
// Two encodings are read, because both are unambiguous about which catalogue
// row is meant: a bare string naming the ID, and an object carrying an `id`
// string member alongside whatever scope and counts AR-004 requires. Anything
// else is recorded in Undetermined and makes the recomputation unreproducible
// — an honest "I could not check this", never a pass. Inventing a third
// reading would be reconstructing the issuer rather than implementing the
// specification (AG-017).
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
		code, determined := assertionCode(item)
		if !determined {
			set.Undetermined = append(set.Undetermined,
				describeUndetermined(i, item))
			continue
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
	}
	return set, nil
}

// assertionCode reads the catalogue code out of the two determined encodings.
func assertionCode(item jcs.Value) (string, bool) {
	switch v := item.(type) {
	case string:
		return v, true
	case *jcs.Object:
		raw, ok := v.Get("id")
		if !ok {
			return "", false
		}
		s, ok := raw.(string)
		if !ok {
			return "", false
		}
		return s, true
	}
	return "", false
}

func describeUndetermined(index int, item jcs.Value) string {
	switch item.(type) {
	case *jcs.Object:
		return "assertions[" + itoa(index) + "]: object without a string id member"
	case []jcs.Value:
		return "assertions[" + itoa(index) + "]: array"
	case nil:
		return "assertions[" + itoa(index) + "]: null"
	}
	return "assertions[" + itoa(index) + "]: unrecognised encoding"
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
