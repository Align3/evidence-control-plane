// Package jcs implements RFC 8785 JSON Canonicalization Scheme for the subset
// of JSON that evidence-spec.md §2 permits in a signed record.
//
// Written from evidence-spec.md and tests/vectors/, deliberately without
// reference to the Python writer (AC-011). Sharing a canonicalisation library
// between writer and verifier defeats the purpose of ES-S-007: two
// implementations that agree because they are the same code prove nothing.
//
// This package parses JSON itself rather than using encoding/json. Two reasons,
// both load-bearing:
//
//   - encoding/json silently replaces unpaired surrogates with U+FFFD. ES
//     requires a lone surrogate to be *rejected*, and a replacement would
//     change the bytes that get signed.
//   - ES-002a requires rejecting any number carrying a fraction or exponent,
//     which is a property of the source token, not of the parsed value.
//     Once a token becomes a float64 the distinction is gone.
package jcs

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Error codes shared with the conformance vectors.
const (
	CodeFloatForbidden     = "canonicalization.float_forbidden"
	CodeIntegerOutOfRange  = "canonicalization.integer_out_of_range"
	CodeLoneSurrogate      = "canonicalization.lone_surrogate"
	CodeMalformed          = "canonicalization.malformed"
	CodeDuplicateMember    = "canonicalization.duplicate_member"
	CodeInvalidUTF8        = "canonicalization.invalid_utf8"
	CodeUnsupportedContent = "canonicalization.unsupported_content"
)

// maxSafeInteger is 2^53-1. ES-002a bounds every JSON number to the
// interoperable range -(2^53-1) .. 2^53-1 inclusive.
const maxSafeInteger = 9007199254740991

// Error carries a stable dotted code alongside a human-readable message. The
// vectors agree on the code; the wording is ours (vectors README).
type Error struct {
	Code string
	Msg  string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func errf(code, format string, args ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Value is a parsed JSON value: nil, bool, int64, string, []Value, or *Object.
type Value any

// Object preserves nothing about input order — RFC 8785 sorts members — but
// does record which keys were present so duplicates can be refused.
type Object struct {
	keys   []string
	values map[string]Value
}

func NewObject() *Object {
	return &Object{values: map[string]Value{}}
}

func (o *Object) Set(key string, v Value) {
	if _, seen := o.values[key]; !seen {
		o.keys = append(o.keys, key)
	}
	o.values[key] = v
}

func (o *Object) Get(key string) (Value, bool) {
	v, ok := o.values[key]
	return v, ok
}

// Keys returns member names in input order. Callers that need canonical order
// sort with LessUTF16.
func (o *Object) Keys() []string {
	out := make([]string, len(o.keys))
	copy(out, o.keys)
	return out
}

func (o *Object) Has(key string) bool {
	_, ok := o.values[key]
	return ok
}

func (o *Object) Len() int { return len(o.keys) }

// Delete removes a member, returning a copy. Used to build the
// signature-excluded form for ES-021 without mutating the caller's record.
func (o *Object) Without(key string) *Object {
	out := NewObject()
	for _, k := range o.keys {
		if k == key {
			continue
		}
		out.Set(k, o.values[k])
	}
	return out
}

// Parse decodes JSON under the ES-002a/ES-002b restrictions.
func Parse(data []byte) (Value, error) {
	if !utf8.Valid(data) {
		return nil, errf(CodeInvalidUTF8, "input is not valid UTF-8")
	}
	p := &parser{src: data}
	p.skipWS()
	v, err := p.parseValue()
	if err != nil {
		return nil, err
	}
	p.skipWS()
	if p.pos != len(p.src) {
		return nil, errf(CodeMalformed, "trailing content at byte %d", p.pos)
	}
	return v, nil
}

// Canonicalize parses and re-serialises in RFC 8785 canonical form.
func Canonicalize(data []byte) ([]byte, error) {
	v, err := Parse(data)
	if err != nil {
		return nil, err
	}
	return Serialize(v)
}

// Serialize writes a parsed value in RFC 8785 canonical form.
func Serialize(v Value) ([]byte, error) {
	var b strings.Builder
	if err := writeValue(&b, v); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

// Digest returns the ES-003 digest of canonical bytes: SHA-256, lowercase hex,
// prefixed "sha256:".
func Digest(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// DigestValue canonicalises then digests.
func DigestValue(v Value) (string, error) {
	b, err := Serialize(v)
	if err != nil {
		return "", err
	}
	return Digest(b), nil
}

// ---------- parser ----------

type parser struct {
	src []byte
	pos int
}

func (p *parser) skipWS() {
	for p.pos < len(p.src) {
		switch p.src[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *parser) parseValue() (Value, error) {
	if p.pos >= len(p.src) {
		return nil, errf(CodeMalformed, "unexpected end of input")
	}
	switch c := p.src[p.pos]; {
	case c == '{':
		return p.parseObject()
	case c == '[':
		return p.parseArray()
	case c == '"':
		return p.parseString()
	case c == 't':
		return p.parseLiteral("true", true)
	case c == 'f':
		return p.parseLiteral("false", false)
	case c == 'n':
		return p.parseLiteral("null", nil)
	case c == '-' || (c >= '0' && c <= '9'):
		// "-Infinity" also starts with '-'; parseNumber reports it.
		return p.parseNumber()
	case c == 'N' || c == 'I':
		// NaN / Infinity are not JSON at all, but ES-002a names them
		// explicitly, so they get the float refusal rather than a syntax error.
		return nil, p.nonJSONNumberToken()
	default:
		return nil, errf(CodeMalformed, "unexpected character %q at byte %d", c, p.pos)
	}
}

// nonJSONNumberToken reports NaN/Infinity as ES-002a float refusals.
func (p *parser) nonJSONNumberToken() error {
	rest := p.src[p.pos:]
	for _, tok := range []string{"NaN", "Infinity"} {
		if strings.HasPrefix(string(rest), tok) {
			return errf(CodeFloatForbidden, "%s is not a permitted number (ES-002a)", tok)
		}
	}
	return errf(CodeMalformed, "unexpected character %q at byte %d", p.src[p.pos], p.pos)
}

func (p *parser) parseLiteral(word string, v Value) (Value, error) {
	if !strings.HasPrefix(string(p.src[p.pos:]), word) {
		return nil, errf(CodeMalformed, "invalid literal at byte %d", p.pos)
	}
	p.pos += len(word)
	return v, nil
}

func (p *parser) parseObject() (Value, error) {
	p.pos++ // '{'
	obj := NewObject()
	p.skipWS()
	if p.pos < len(p.src) && p.src[p.pos] == '}' {
		p.pos++
		return obj, nil
	}
	for {
		p.skipWS()
		if p.pos >= len(p.src) || p.src[p.pos] != '"' {
			return nil, errf(CodeMalformed, "expected member name at byte %d", p.pos)
		}
		keyv, err := p.parseString()
		if err != nil {
			return nil, err
		}
		key := keyv.(string)
		if obj.Has(key) {
			// RFC 8785 canonicalises a single value per name; a duplicate has
			// two canonical forms depending on which wins. Refuse rather than pick.
			return nil, errf(CodeDuplicateMember, "duplicate member %q", key)
		}
		p.skipWS()
		if p.pos >= len(p.src) || p.src[p.pos] != ':' {
			return nil, errf(CodeMalformed, "expected ':' at byte %d", p.pos)
		}
		p.pos++
		p.skipWS()
		val, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		obj.Set(key, val)
		p.skipWS()
		if p.pos >= len(p.src) {
			return nil, errf(CodeMalformed, "unterminated object")
		}
		switch p.src[p.pos] {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return obj, nil
		default:
			return nil, errf(CodeMalformed, "expected ',' or '}' at byte %d", p.pos)
		}
	}
}

func (p *parser) parseArray() (Value, error) {
	p.pos++ // '['
	arr := []Value{}
	p.skipWS()
	if p.pos < len(p.src) && p.src[p.pos] == ']' {
		p.pos++
		return arr, nil
	}
	for {
		p.skipWS()
		v, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		arr = append(arr, v)
		p.skipWS()
		if p.pos >= len(p.src) {
			return nil, errf(CodeMalformed, "unterminated array")
		}
		switch p.src[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return arr, nil
		default:
			return nil, errf(CodeMalformed, "expected ',' or ']' at byte %d", p.pos)
		}
	}
}

// parseNumber enforces ES-002a on the *token*: a fraction or exponent is
// refused even when the value would be integral, which is why "1e0" fails.
func (p *parser) parseNumber() (Value, error) {
	if strings.HasPrefix(string(p.src[p.pos:]), "-Infinity") {
		return nil, errf(CodeFloatForbidden, "-Infinity is not a permitted number (ES-002a)")
	}
	start := p.pos
	if p.pos < len(p.src) && p.src[p.pos] == '-' {
		p.pos++
	}
	digitsStart := p.pos
	for p.pos < len(p.src) && p.src[p.pos] >= '0' && p.src[p.pos] <= '9' {
		p.pos++
	}
	if p.pos == digitsStart {
		return nil, errf(CodeMalformed, "expected digits at byte %d", digitsStart)
	}
	// Leading zeros are invalid JSON ("01"); a bare "0" or "-0" is fine.
	if p.src[digitsStart] == '0' && p.pos-digitsStart > 1 {
		return nil, errf(CodeMalformed, "leading zero at byte %d", digitsStart)
	}
	if p.pos < len(p.src) && (p.src[p.pos] == '.') {
		return nil, errf(CodeFloatForbidden,
			"number %q carries a fraction; ES-002a permits integers only", p.tokenFrom(start))
	}
	if p.pos < len(p.src) && (p.src[p.pos] == 'e' || p.src[p.pos] == 'E') {
		return nil, errf(CodeFloatForbidden,
			"number %q carries an exponent; ES-002a permits integers only", p.tokenFrom(start))
	}
	tok := string(p.src[start:p.pos])
	n, err := strconv.ParseInt(tok, 10, 64)
	if err != nil {
		// Out of int64 range is necessarily out of safe-integer range.
		return nil, errf(CodeIntegerOutOfRange,
			"number %s is outside the interoperable range (ES-002a)", tok)
	}
	if n > maxSafeInteger || n < -maxSafeInteger {
		return nil, errf(CodeIntegerOutOfRange,
			"number %s is outside -(2^53-1)..2^53-1 (ES-002a)", tok)
	}
	return n, nil
}

func (p *parser) tokenFrom(start int) string {
	end := p.pos
	for end < len(p.src) {
		c := p.src[end]
		if (c >= '0' && c <= '9') || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-' {
			end++
			continue
		}
		break
	}
	return string(p.src[start:end])
}

func (p *parser) parseString() (Value, error) {
	p.pos++ // opening quote
	var out []rune
	for {
		if p.pos >= len(p.src) {
			return nil, errf(CodeMalformed, "unterminated string")
		}
		c := p.src[p.pos]
		switch {
		case c == '"':
			p.pos++
			return string(out), nil
		case c == '\\':
			p.pos++
			if p.pos >= len(p.src) {
				return nil, errf(CodeMalformed, "unterminated escape")
			}
			esc := p.src[p.pos]
			p.pos++
			switch esc {
			case '"':
				out = append(out, '"')
			case '\\':
				out = append(out, '\\')
			case '/':
				out = append(out, '/')
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'u':
				r, err := p.parseUnicodeEscape()
				if err != nil {
					return nil, err
				}
				out = append(out, r)
			default:
				return nil, errf(CodeMalformed, "invalid escape \\%c", esc)
			}
		case c < 0x20:
			// RFC 8259: control characters must be escaped inside a string.
			return nil, errf(CodeMalformed, "unescaped control character U+%04X", c)
		default:
			r, size := utf8.DecodeRune(p.src[p.pos:])
			if r == utf8.RuneError && size == 1 {
				return nil, errf(CodeInvalidUTF8, "invalid UTF-8 at byte %d", p.pos)
			}
			out = append(out, r)
			p.pos += size
		}
	}
}

// parseUnicodeEscape reads \uXXXX, joining a surrogate pair and refusing an
// unpaired half. ES requires refusal: a replacement character would silently
// change the bytes that were signed.
func (p *parser) parseUnicodeEscape() (rune, error) {
	hi, err := p.readHex4()
	if err != nil {
		return 0, err
	}
	if utf16.IsSurrogate(rune(hi)) {
		// A high surrogate must be followed by \uDC00-\uDFFF.
		if hi >= 0xD800 && hi <= 0xDBFF &&
			p.pos+1 < len(p.src) && p.src[p.pos] == '\\' && p.src[p.pos+1] == 'u' {
			save := p.pos
			p.pos += 2
			lo, err := p.readHex4()
			if err != nil {
				return 0, err
			}
			if lo >= 0xDC00 && lo <= 0xDFFF {
				return utf16.DecodeRune(rune(hi), rune(lo)), nil
			}
			p.pos = save
		}
		return 0, errf(CodeLoneSurrogate,
			"unpaired surrogate U+%04X is not a valid Unicode scalar", hi)
	}
	return rune(hi), nil
}

func (p *parser) readHex4() (int, error) {
	if p.pos+4 > len(p.src) {
		return 0, errf(CodeMalformed, "truncated \\u escape")
	}
	v := 0
	for i := 0; i < 4; i++ {
		c := p.src[p.pos+i]
		var d int
		switch {
		case c >= '0' && c <= '9':
			d = int(c - '0')
		case c >= 'a' && c <= 'f':
			d = int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = int(c-'A') + 10
		default:
			return 0, errf(CodeMalformed, "invalid hex digit %q in \\u escape", c)
		}
		v = v*16 + d
	}
	p.pos += 4
	return v, nil
}

// ---------- serialiser ----------

func writeValue(b *strings.Builder, v Value) error {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case int64:
		b.WriteString(strconv.FormatInt(t, 10))
	case int:
		b.WriteString(strconv.Itoa(t))
	case string:
		writeString(b, t)
	case []Value:
		b.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeValue(b, item); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case *Object:
		keys := t.Keys()
		sort.Slice(keys, func(i, j int) bool { return LessUTF16(keys[i], keys[j]) })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, k)
			b.WriteByte(':')
			val, _ := t.Get(k)
			if err := writeValue(b, val); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return errf(CodeUnsupportedContent, "cannot canonicalise %T", v)
	}
	return nil
}

// writeString applies RFC 8785 §3.2.2.2 escaping: the two mandatory escapes,
// the five short control forms, \u00xx for the remaining C0 controls, and
// literal UTF-8 for everything else. Notably "/" is *not* escaped and
// non-ASCII is *not* escaped.
func writeString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				b.WriteString(fmt.Sprintf(`\u%04x`, r))
				continue
			}
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}

// LessUTF16 orders member names by UTF-16 code unit, which is what RFC 8785
// §3.2.3 requires. This is not the same as Go's byte-wise string comparison:
// U+E000 is three UTF-8 bytes beginning 0xEE and sorts *after* U+1F600, whose
// UTF-8 begins 0xF0 — but whose leading UTF-16 code unit is 0xD83D.
func LessUTF16(a, b string) bool {
	au := utf16.Encode([]rune(a))
	bu := utf16.Encode([]rune(b))
	for i := 0; i < len(au) && i < len(bu); i++ {
		if au[i] != bu[i] {
			return au[i] < bu[i]
		}
	}
	return len(au) < len(bu)
}

// DigestRaw returns the bare SHA-256 of canonical bytes, without the ES-003
// "sha256:" prefix or hex encoding.
//
// This is the Ed25519 signing input for record signatures. ES-021 names
// signed_digest but does not say what sig covers; the normative vectors settle
// it (ES-029), and they sign these 32 bytes rather than the canonical bytes.
func DigestRaw(canonical []byte) []byte {
	sum := sha256.Sum256(canonical)
	return sum[:]
}
