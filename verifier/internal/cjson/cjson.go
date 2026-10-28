// Package cjson re-canonicalizes JSON documents with the Sealed canonical JSON profile (INTERFACES.md section 1).
//
// It is a verifier-local twin of runtime/composer/cjson, which is built concurrently by the composer workstream.
// Both run the shared vectors in runtime/composer/testdata/cjson. Once the composer package is merged, the
// verifier should import it and this package should be deleted (see docs/notes/build-verifier.md).
package cjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"unicode/utf8"
)

// maxSafeInteger is 2^53 - 1, the largest integer allowed in hashed documents.
const maxSafeInteger = 1<<53 - 1

// Errors returned for documents outside the profile.
var (
	ErrInvalidJSON   = errors.New("cjson: invalid JSON")
	ErrFloat         = errors.New("cjson: float not allowed")
	ErrIntegerRange  = errors.New("cjson: integer out of range")
	ErrDuplicateKey  = errors.New("cjson: duplicate key")
	ErrNonASCIIKey   = errors.New("cjson: non-ASCII key")
	ErrInvalidString = errors.New("cjson: invalid UTF-8")
)

// Canonicalize parses one JSON value and returns its canonical encoding.
func Canonicalize(in []byte) ([]byte, error) {
	if !utf8.Valid(in) {
		return nil, ErrInvalidString
	}
	dec := json.NewDecoder(bytes.NewReader(in))
	dec.UseNumber()
	var out bytes.Buffer
	if err := writeValue(dec, &out); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing data", ErrInvalidJSON)
	}
	return out.Bytes(), nil
}

// Marshal encodes v with encoding/json (HTML escaping off) and canonicalizes the result.
func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return Canonicalize(bytes.TrimRight(buf.Bytes(), "\n"))
}

func writeValue(dec *json.Decoder, out *bytes.Buffer) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			return writeObject(dec, out)
		case '[':
			return writeArray(dec, out)
		default:
			return fmt.Errorf("%w: unexpected %q", ErrInvalidJSON, t)
		}
	case string:
		writeString(out, t)
	case json.Number:
		return writeNumber(out, t)
	case bool:
		if t {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case nil:
		out.WriteString("null")
	default:
		return fmt.Errorf("%w: unexpected token %T", ErrInvalidJSON, tok)
	}
	return nil
}

func writeObject(dec *json.Decoder, out *bytes.Buffer) error {
	members := map[string][]byte{}
	var keys []string
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidJSON, err)
		}
		key, ok := tok.(string)
		if !ok {
			return fmt.Errorf("%w: object key is not a string", ErrInvalidJSON)
		}
		for i := 0; i < len(key); i++ {
			if key[i] >= utf8.RuneSelf {
				return fmt.Errorf("%w: %q", ErrNonASCIIKey, key)
			}
		}
		if _, dup := members[key]; dup {
			return fmt.Errorf("%w: %q", ErrDuplicateKey, key)
		}
		var val bytes.Buffer
		if err := writeValue(dec, &val); err != nil {
			return err
		}
		members[key] = val.Bytes()
		keys = append(keys, key)
	}
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}
	sort.Strings(keys)
	out.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			out.WriteByte(',')
		}
		writeString(out, k)
		out.WriteByte(':')
		out.Write(members[k])
	}
	out.WriteByte('}')
	return nil
}

func writeArray(dec *json.Decoder, out *bytes.Buffer) error {
	out.WriteByte('[')
	first := true
	for dec.More() {
		if !first {
			out.WriteByte(',')
		}
		first = false
		if err := writeValue(dec, out); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}
	out.WriteByte(']')
	return nil
}

func writeNumber(out *bytes.Buffer, n json.Number) error {
	s := n.String()
	for _, c := range s {
		if c == '.' || c == 'e' || c == 'E' {
			return fmt.Errorf("%w: %s", ErrFloat, s)
		}
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v > maxSafeInteger || v < -maxSafeInteger {
		return fmt.Errorf("%w: %s", ErrIntegerRange, s)
	}
	out.WriteString(strconv.FormatInt(v, 10))
	return nil
}

const hexDigits = "0123456789abcdef"

func writeString(out *bytes.Buffer, s string) {
	out.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if c < 0x20 {
				out.WriteString(`\u00`)
				out.WriteByte(hexDigits[c>>4])
				out.WriteByte(hexDigits[c&0xf])
			} else {
				out.WriteByte(c)
			}
		}
	}
	out.WriteByte('"')
}
