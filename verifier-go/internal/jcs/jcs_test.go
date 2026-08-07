package jcs

import (
	"strings"
	"testing"
)

// The published vectors cover the cases the format guarantees. These cover the
// ones a hostile or buggy producer reaches that the corpus does not, and they
// are weighted toward refusal on purpose (AG-007): the dangerous failure here
// is accepting bytes that should not canonicalise, because whatever is signed
// afterwards inherits that acceptance.

func TestRefusals(t *testing.T) {
	cases := []struct {
		name, input, wantCode string
	}{
		{"duplicate member", `{"a":1,"a":2}`, CodeDuplicateMember},
		{"trailing content", `{"a":1} {"b":2}`, CodeMalformed},
		{"leading zero", `{"a":01}`, CodeMalformed},
		{"bare minus", `{"a":-}`, CodeMalformed},
		{"unescaped control", "{\"a\":\"\x01\"}", CodeMalformed},
		{"unterminated string", `{"a":"x`, CodeMalformed},
		{"unterminated object", `{"a":1`, CodeMalformed},
		{"unterminated array", `[1,2`, CodeMalformed},
		{"invalid escape", `{"a":"\q"}`, CodeMalformed},
		{"truncated unicode escape", `{"a":"\u00"}`, CodeMalformed},
		{"bad hex in escape", `{"a":"\u00zz"}`, CodeMalformed},
		{"lone high surrogate", `{"a":"\ud800"}`, CodeLoneSurrogate},
		{"lone low surrogate", `{"a":"\udc00"}`, CodeLoneSurrogate},
		{"high surrogate then plain", `{"a":"\ud800A"}`, CodeLoneSurrogate},
		{"fraction", `{"a":1.0}`, CodeFloatForbidden},
		{"negative fraction", `{"a":-0.5}`, CodeFloatForbidden},
		{"capital exponent", `{"a":1E5}`, CodeFloatForbidden},
		{"NaN", `{"a":NaN}`, CodeFloatForbidden},
		{"Infinity", `{"a":Infinity}`, CodeFloatForbidden},
		{"negative Infinity", `{"a":-Infinity}`, CodeFloatForbidden},
		{"above safe integer", `{"a":9007199254740992}`, CodeIntegerOutOfRange},
		{"below safe integer", `{"a":-9007199254740992}`, CodeIntegerOutOfRange},
		{"far above int64", `{"a":99999999999999999999}`, CodeIntegerOutOfRange},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Canonicalize([]byte(tc.input))
			if err == nil {
				t.Fatalf("expected refusal %s, got acceptance", tc.wantCode)
			}
			e, ok := err.(*Error)
			if !ok {
				t.Fatalf("expected *jcs.Error, got %T", err)
			}
			if e.Code != tc.wantCode {
				t.Fatalf("expected %s, got %s (%v)", tc.wantCode, e.Code, err)
			}
		})
	}
}

func TestInvalidUTF8Refused(t *testing.T) {
	// A raw 0xFF byte cannot appear in UTF-8. Accepting it would mean signing
	// bytes no conformant producer could have written.
	if _, err := Canonicalize([]byte{'{', '"', 'a', '"', ':', '"', 0xFF, '"', '}'}); err == nil {
		t.Fatal("expected invalid UTF-8 to be refused")
	}
}

func TestAcceptances(t *testing.T) {
	cases := []struct{ name, input, want string }{
		{"safe integer bounds", `{"hi":9007199254740991,"lo":-9007199254740991}`,
			`{"hi":9007199254740991,"lo":-9007199254740991}`},
		{"negative zero is an integer", `{"a":-0}`, `{"a":0}`},
		{"empty containers", `{"a":{},"b":[]}`, `{"a":{},"b":[]}`},
		{"nested arrays keep order", `{"a":[[3,1],[2]]}`, `{"a":[[3,1],[2]]}`},
		{"solidus is not escaped", `{"a":"/"}`, `{"a":"/"}`},
		{"escaped solidus is unescaped", `{"a":"\/"}`, `{"a":"/"}`},
		{"non-ASCII passes through", `{"a":"€"}`, "{\"a\":\"€\"}"},
		{"surrogate pair becomes one rune", `{"a":"😀"}`, "{\"a\":\"\U0001F600\"}"},
		{"DEL is not escaped", `{"a":"\u007F"}`, "{\"a\":\"\u007f\"}"},
		{"whitespace is insignificant", "{ \"a\" : 1 , \"b\" : [ 2 ] }", `{"a":1,"b":[2]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Canonicalize([]byte(tc.input))
			if err != nil {
				t.Fatalf("unexpected refusal: %v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("\n  got  %s\n  want %s", got, tc.want)
			}
		})
	}
}

// TestControlEscapesAreLowercaseHex pins the \u00xx form. Upper-case hex would
// produce different bytes for the same input and therefore a different digest.
func TestControlEscapesAreLowercaseHex(t *testing.T) {
	got, err := Canonicalize([]byte(`{"a":"\u001F"}`))
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"a":"\u001f"}`; string(got) != want {
		t.Fatalf("expected lowercase escape\n  got  %s\n  want %s", got, want)
	}
}

// TestUTF16Ordering is the ordering trap. Sorting by UTF-8 bytes puts U+E000
// before U+1F600; RFC 8785 sorts by UTF-16 code unit, which reverses them
// because the astral character's leading surrogate is 0xD83D.
func TestUTF16Ordering(t *testing.T) {
	if !LessUTF16("\U0001F600", "") {
		t.Fatal("U+1F600 must sort before U+E000 under UTF-16 ordering")
	}
	if "\U0001F600" < "" {
		t.Fatal("precondition failed: UTF-8 byte order was expected to disagree here")
	}
	if !LessUTF16("a", "ab") {
		t.Fatal("a prefix must sort before its extension")
	}
	if LessUTF16("b", "a") {
		t.Fatal("ordering is not by code unit")
	}
}

func TestDigestShapes(t *testing.T) {
	canonical := []byte(`{"a":1}`)
	d := Digest(canonical)
	if !strings.HasPrefix(d, "sha256:") || len(d) != len("sha256:")+64 {
		t.Fatalf("ES-003 requires sha256:<64 lowercase hex>, got %q", d)
	}
	if strings.ToLower(d) != d {
		t.Fatalf("digest must be lowercase hex, got %q", d)
	}
	if len(DigestRaw(canonical)) != 32 {
		t.Fatal("DigestRaw must return the bare 32-byte hash")
	}
}

// TestWithoutDoesNotMutate guards the signature-excluded form: building it must
// not disturb the record the caller still needs for the signature-inclusive
// digest (ES-006a).
func TestWithoutDoesNotMutate(t *testing.T) {
	v, err := Parse([]byte(`{"a":1,"signature":{"x":1}}`))
	if err != nil {
		t.Fatal(err)
	}
	obj := v.(*Object)
	stripped := obj.Without("signature")
	if stripped.Has("signature") {
		t.Fatal("Without must remove the member")
	}
	if !obj.Has("signature") {
		t.Fatal("Without must not mutate the original")
	}
}
