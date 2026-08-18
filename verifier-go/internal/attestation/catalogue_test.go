package attestation

import (
	"testing"

	"github.com/Align3/evidence-control-plane/verifier-go/internal/jcs"
)

// AR-003 closes the catalogue. The test that matters most here is the one that
// cannot be written: there is no expression in this file, outside the
// catalogue package, that constructs an AssertionID carrying an uncatalogued
// code. `AssertionID{"A-11"}` does not compile from another package because
// `code` is unexported, which is the property the type was chosen for.
func TestCatalogueIsExactlyTheTenRowsOfSection2(t *testing.T) {
	want := []string{"A-01", "A-02", "A-03", "A-04", "A-05", "A-06", "A-07", "A-08", "A-09", "A-10"}
	got := Catalogue()
	if len(got) != len(want) {
		t.Fatalf("catalogue has %d rows, attestation-reliance.md §2 has %d", len(got), len(want))
	}
	for i, id := range got {
		if id.String() != want[i] {
			t.Fatalf("row %d is %q, want %q", i, id, want[i])
		}
		if !id.IsCatalogued() {
			t.Fatalf("%s is not reported as catalogued", id)
		}
		if id.Assertion() == "" || id.Basis() == "" {
			t.Fatalf("%s has no claim text or no basis; AG-003 requires both", id)
		}
	}
}

// A-02 and A-09 cite the requirements EV-25 wrote for them, not the ES-009 and
// CM-007 they originally named. Re-pointing an assertion at an adjacent
// requirement that does not state its claim is the failure that story exists to
// prevent, and it is invisible unless the citation is asserted.
func TestRepairedCitations(t *testing.T) {
	if got := A02.Basis(); got != "AR-027" {
		t.Fatalf("A-02 cites %q, want AR-027 (EV-25)", got)
	}
	if got := A09.Basis(); got != "AR-028" {
		t.Fatalf("A-09 cites %q, want AR-028 (EV-25)", got)
	}
}

func TestParseAssertionIDIsClosed(t *testing.T) {
	for _, bad := range []string{"A-11", "A-0", "A-1", "a-01", "A-01 ", "", "A_01", "OVERALL"} {
		if _, err := ParseAssertionID(bad); Code(err) != CodeAssertionOffCatalogue {
			t.Errorf("ParseAssertionID(%q) was not refused as off-catalogue", bad)
		}
	}
	for _, good := range Catalogue() {
		got, err := ParseAssertionID(good.String())
		if err != nil {
			t.Errorf("ParseAssertionID(%q): %v", good, err)
		}
		if got != good {
			t.Errorf("ParseAssertionID(%q) round-tripped to %q", good, got)
		}
	}
}

// The zero value is the only AssertionID a caller can hold that names no
// catalogue row, so a forgotten initialisation must not read as A-01.
func TestZeroValueIsNotCatalogued(t *testing.T) {
	var id AssertionID
	if id.IsCatalogued() {
		t.Fatal("the zero AssertionID reports as catalogued")
	}
	if id.String() != "" || id.Assertion() != "" || id.Basis() != "" {
		t.Fatalf("the zero AssertionID renders as %q/%q/%q", id, id.Assertion(), id.Basis())
	}
	if (AssertionID{} == A01) {
		t.Fatal("the zero value equals a catalogue member")
	}
}

func readAssertions(t *testing.T, jsonBody string) (AssertionSet, error) {
	t.Helper()
	v, err := jcs.Parse([]byte(jsonBody))
	if err != nil {
		t.Fatal(err)
	}
	return ReadAssertions(v.(*jcs.Object))
}

func TestReadAssertionsRefusesOffCatalogue(t *testing.T) {
	if _, err := readAssertions(t, `{"assertions":["A-01","A-11"]}`); Code(err) != CodeAssertionOffCatalogue {
		t.Fatalf("off-catalogue assertion gave %v", err)
	}
	if _, err := readAssertions(t, `{"assertions":[{"id":"A-99","count":3}]}`); Code(err) != CodeAssertionOffCatalogue {
		t.Fatalf("off-catalogue object assertion gave %v", err)
	}
}

func TestReadAssertionsRefusesDuplicates(t *testing.T) {
	if _, err := readAssertions(t, `{"assertions":["A-05",{"id":"A-05"}]}`); Code(err) != CodeAssertionDuplicated {
		t.Fatalf("duplicate assertion gave %v", err)
	}
}

func TestReadAssertionsRequiresAnArray(t *testing.T) {
	if _, err := readAssertions(t, `{"assertions":{"A-01":true}}`); Code(err) != CodeAssertionsNotArray {
		t.Fatalf("non-array assertions gave %v", err)
	}
	if _, err := readAssertions(t, `{"counts":{}}`); Code(err) != CodeAssertionsNotArray {
		t.Fatalf("missing assertions gave %v", err)
	}
}

// An encoding the specification does not determine is recorded, not accepted
// and not refused: the verifier reports that it could not check, which is a
// different claim from either.
func TestUndeterminedEncodingsAreRecorded(t *testing.T) {
	set, err := readAssertions(t, `{"assertions":[{"scope":"window"},["A-01"],null,{"id":7}]}`)
	if err != nil {
		t.Fatalf("undetermined encodings were refused: %v", err)
	}
	if len(set.IDs) != 0 {
		t.Fatalf("undetermined encodings produced assertions: %v", set.IDs)
	}
	if len(set.Undetermined) != 4 {
		t.Fatalf("recorded %d undetermined encodings, want 4: %v",
			len(set.Undetermined), set.Undetermined)
	}
}

func TestEmptyAssertionListIsAccepted(t *testing.T) {
	// This is the shape the one published AttestationWindow vector carries.
	set, err := readAssertions(t, `{"assertions":[]}`)
	if err != nil {
		t.Fatalf("the vector's empty assertions[] was refused: %v", err)
	}
	if len(set.IDs) != 0 || len(set.Undetermined) != 0 {
		t.Fatal("an empty list produced something")
	}
}

// AR-004 forbids an aggregate score, rating or grade. The closed catalogue is
// what makes that structural rather than a naming convention: there is no row
// for a composite summary, so no encoding of one can be emitted as an
// assertion at all.
func TestNoAggregateScoreRowExists(t *testing.T) {
	for _, bad := range []string{"A-SCORE", "SCORE", "GRADE", "RATING", "A-00"} {
		if _, err := ParseAssertionID(bad); Code(err) != CodeAssertionOffCatalogue {
			t.Fatalf("%q was admitted to the catalogue", bad)
		}
	}
	if _, err := readAssertions(t, `{"assertions":[{"id":"SCORE","value":"87"}]}`); Code(err) != CodeAssertionOffCatalogue {
		t.Fatalf("an aggregate score was accepted as an assertion: %v", err)
	}
}
