package cjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"os"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"
)

// addVectorSeeds seeds a fuzz target with every input of the shared CJSON
// vectors (testdata/cjson/vectors.json) and their expected outputs.
func addVectorSeeds(f *testing.F) {
	raw, err := os.ReadFile("../testdata/cjson/vectors.json")
	if err != nil {
		f.Fatal(err)
	}
	var vs []vector
	if err := json.Unmarshal(raw, &vs); err != nil {
		f.Fatal(err)
	}
	for _, v := range vs {
		f.Add([]byte(v.In))
		if v.Out != "" {
			f.Add([]byte(v.Out))
		}
	}
}

// refCanonicalize is an independent reference for Canonicalize, built on
// encoding/json's tokenizer: RFC 8785 output (sorted keys, no whitespace,
// minimal string escapes, raw UTF-8) restricted to the Sealed profile
// (integers within +/- 2^53-1, unique ASCII keys, no lone surrogates, at most
// maxDepth+1 nested containers). ok is false for any input the profile
// refuses.
func refCanonicalize(in []byte) (out []byte, ok bool) {
	if !utf8.Valid(in) || !json.Valid(in) || hasLoneSurrogate(in) {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(in))
	dec.UseNumber()
	var buf bytes.Buffer
	if !refValue(dec, &buf, 0) {
		return nil, false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, false
	}
	return buf.Bytes(), true
}

var maxSafe = big.NewInt(MaxSafeInteger)

func refValue(dec *json.Decoder, buf *bytes.Buffer, depth int) bool {
	if depth > maxDepth {
		return false
	}
	tok, err := dec.Token()
	if err != nil {
		return false
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '[':
			buf.WriteByte('[')
			for i := 0; dec.More(); i++ {
				if i > 0 {
					buf.WriteByte(',')
				}
				if !refValue(dec, buf, depth+1) {
					return false
				}
			}
			if _, err := dec.Token(); err != nil {
				return false
			}
			buf.WriteByte(']')
			return true
		case '{':
			members := map[string][]byte{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return false
				}
				k := kt.(string)
				for i := 0; i < len(k); i++ {
					if k[i] >= 0x80 {
						return false
					}
				}
				if _, dup := members[k]; dup {
					return false
				}
				var vb bytes.Buffer
				if !refValue(dec, &vb, depth+1) {
					return false
				}
				members[k] = vb.Bytes()
			}
			if _, err := dec.Token(); err != nil {
				return false
			}
			keys := make([]string, 0, len(members))
			for k := range members {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			buf.WriteByte('{')
			for i, k := range keys {
				if i > 0 {
					buf.WriteByte(',')
				}
				refString(buf, k)
				buf.WriteByte(':')
				buf.Write(members[k])
			}
			buf.WriteByte('}')
			return true
		}
		return false
	case json.Number:
		s := t.String()
		if strings.ContainsAny(s, ".eE") {
			return false
		}
		n, ok := new(big.Int).SetString(s, 10)
		if !ok || new(big.Int).Abs(n).Cmp(maxSafe) > 0 {
			return false
		}
		buf.WriteString(n.String())
		return true
	case string:
		refString(buf, t)
		return true
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
		return true
	case nil:
		buf.WriteString("null")
		return true
	}
	return false
}

// refString writes s as RFC 8785 does: \" \\ \b \f \n \r \t, other controls
// as \u00xx with lowercase hex, everything else unescaped.
func refString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				buf.WriteString(`\u00`)
				buf.WriteByte("0123456789abcdef"[r>>4])
				buf.WriteByte("0123456789abcdef"[r&0xf])
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

// hasLoneSurrogate scans the string literals of a valid JSON document for a
// \u escape of a surrogate that is not a high surrogate directly followed by
// a \u escape of a low one. encoding/json silently turns those into U+FFFD.
func hasLoneSurrogate(in []byte) bool {
	hex4 := func(b []byte) (rune, bool) {
		if len(b) < 4 {
			return 0, false
		}
		var r rune
		for _, c := range b[:4] {
			switch {
			case c >= '0' && c <= '9':
				r = r<<4 | rune(c-'0')
			case c >= 'a' && c <= 'f':
				r = r<<4 | rune(c-'a'+10)
			case c >= 'A' && c <= 'F':
				r = r<<4 | rune(c-'A'+10)
			default:
				return 0, false
			}
		}
		return r, true
	}
	inString := false
	for i := 0; i < len(in); i++ {
		c := in[i]
		if !inString {
			if c == '"' {
				inString = true
			}
			continue
		}
		switch c {
		case '"':
			inString = false
		case '\\':
			if i+1 < len(in) && in[i+1] == 'u' {
				r, ok := hex4(in[i+2:])
				if ok && r >= 0xd800 && r <= 0xdfff {
					if r >= 0xdc00 {
						return true
					}
					j := i + 6
					if j+1 >= len(in) || in[j] != '\\' || in[j+1] != 'u' {
						return true
					}
					r2, ok := hex4(in[j+2:])
					if !ok || r2 < 0xdc00 || r2 > 0xdfff {
						return true
					}
					i = j + 5
					continue
				}
				i += 5
				continue
			}
			i++ // skip the escaped character
		}
	}
	return false
}

// FuzzParseReference: Canonicalize accepts exactly what the reference accepts
// and returns the reference's bytes; Parse then Encode is the same function;
// the output is a fixed point; every refusal carries one of the stable kinds.
func FuzzParseReference(f *testing.F) {
	addVectorSeeds(f)
	for _, s := range []string{
		`{"a":"😀","b":" \u0000\/"}`, `[-0,0,1,-9007199254740991]`, `"\ud800A"`, `"\\ud800"`,
		strings.Repeat("[", 257) + strings.Repeat("]", 257), strings.Repeat("[", 258) + strings.Repeat("]", 258),
		` {"z" : [ ] , "y":{}} `, `{"a":1}` + "\n", `9007199254740991`, `-9007199254740992`, `1E2`, `{"a":1,"a":2}`,
	} {
		f.Add([]byte(s))
	}
	kinds := []string{KindInvalidJSON, KindFloat, KindIntRange, KindDuplicateKey, KindNonASCIIKey, KindInvalidUTF8, KindUnsupported}
	f.Fuzz(func(t *testing.T, in []byte) {
		out, err := Canonicalize(in)
		ref, refOK := refCanonicalize(in)
		if (err == nil) != refOK {
			t.Fatalf("Canonicalize(%q): err %v, reference ok=%v (%q)", in, err, refOK, ref)
		}
		if err != nil {
			var e *Error
			if !errors.As(err, &e) || !strings.Contains(strings.Join(kinds, "|"), e.Kind) || e.Offset < 0 || e.Offset > len(in) {
				t.Fatalf("Canonicalize(%q): error %#v has no stable kind or a bad offset", in, err)
			}
			return
		}
		if !bytes.Equal(out, ref) {
			t.Fatalf("Canonicalize(%q)\n got %q\nwant %q", in, out, ref)
		}
		v, err := Parse(in)
		if err != nil {
			t.Fatalf("Parse refuses what Canonicalize accepted: %v", err)
		}
		enc, err := Encode(v)
		if err != nil || !bytes.Equal(enc, out) {
			t.Fatalf("Encode(Parse(x)) = %q (%v), Canonicalize(x) = %q", enc, err, out)
		}
		again, err := Canonicalize(out)
		if err != nil || !bytes.Equal(again, out) {
			t.Fatalf("not a fixed point: %q -> %q (%v)", out, again, err)
		}
		// Marshal of the parsed tree takes the same path the composer uses.
		m, err := Marshal(v)
		if err != nil || !bytes.Equal(m, out) {
			t.Fatalf("Marshal(Parse(x)) = %q (%v), want %q", m, err, out)
		}
	})
}
