// Package cjson implements Sealed canonical JSON (INTERFACES.md section 1):
// an RFC 8785 (JCS) profile restricted to integers within +/- 2^53 and ASCII
// object keys, with keys sorted by byte order, no insignificant whitespace,
// raw UTF-8 output and no HTML escaping.
package cjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"unicode/utf8"
)

// MaxSafeInteger is the largest integer magnitude allowed in canonical JSON.
const MaxSafeInteger = 1<<53 - 1

// maxDepth bounds nesting so hostile input cannot exhaust the stack.
const maxDepth = 256

// Error describes why a document is not canonicalizable. Kind is one of the
// stable strings below so callers and test vectors can match on it.
type Error struct {
	Kind   string
	Offset int
	Detail string
}

const (
	KindInvalidJSON  = "invalid JSON"
	KindFloat        = "float"
	KindIntRange     = "integer out of range"
	KindDuplicateKey = "duplicate key"
	KindNonASCIIKey  = "non-ASCII key"
	KindInvalidUTF8  = "invalid UTF-8"
	KindUnsupported  = "unsupported value"
)

func (e *Error) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("cjson: %s at offset %d", e.Kind, e.Offset)
	}
	return fmt.Sprintf("cjson: %s at offset %d: %s", e.Kind, e.Offset, e.Detail)
}

// IsKind reports whether err is a cjson error of the given kind.
func IsKind(err error, kind string) bool {
	var e *Error
	return errors.As(err, &e) && e.Kind == kind
}

// Canonicalize parses a JSON document and returns its canonical encoding.
// It rejects floats, integers outside +/- 2^53, duplicate keys, non-ASCII
// keys, invalid UTF-8, lone surrogates and trailing data.
func Canonicalize(in []byte) ([]byte, error) {
	v, err := Parse(in)
	if err != nil {
		return nil, err
	}
	return Encode(v)
}

// Marshal encodes any Go value that encoding/json can encode, then
// canonicalizes the result. Struct tags are honored. Floats are rejected
// unless they hold an exact integer that encoding/json prints without a
// fraction or exponent.
func Marshal(v any) ([]byte, error) {
	if out, ok, err := encodeFast(v); ok {
		return out, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("cjson: %w", err)
	}
	return Canonicalize(bytes.TrimRight(buf.Bytes(), "\n"))
}

// Value is a parsed canonical-JSON value: nil, bool, int64, string,
// []Value-compatible []any, or map[string]any.
type Value = any

// Encode writes the canonical form of a value tree made of nil, bool,
// int, int64, string, []any and map[string]any.
func Encode(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := encodeValue(&buf, v, 0); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// encodeFast handles the generic value trees the composer builds without a
// round trip through encoding/json. ok is false for other types.
func encodeFast(v any) (out []byte, ok bool, err error) {
	if !isGeneric(v, 0) {
		return nil, false, nil
	}
	out, err = Encode(v)
	return out, true, err
}

func isGeneric(v any, depth int) bool {
	if depth > maxDepth {
		return false
	}
	switch t := v.(type) {
	case nil, bool, int, int64, string:
		return true
	case []any:
		for _, e := range t {
			if !isGeneric(e, depth+1) {
				return false
			}
		}
		return true
	case []string:
		return true
	case map[string]any:
		for _, e := range t {
			if !isGeneric(e, depth+1) {
				return false
			}
		}
		return true
	case map[string]string:
		return true
	}
	return false
}

func encodeValue(buf *bytes.Buffer, v any, depth int) error {
	if depth > maxDepth {
		return &Error{Kind: KindUnsupported, Detail: "nesting too deep"}
	}
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case int:
		return encodeInt(buf, int64(t))
	case int64:
		return encodeInt(buf, t)
	case string:
		return encodeString(buf, t)
	case []string:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encodeString(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encodeValue(buf, e, depth+1); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]string:
		m := make(map[string]any, len(t))
		for k, e := range t {
			m[k] = e
		}
		return encodeObject(buf, m, depth)
	case map[string]any:
		return encodeObject(buf, t, depth)
	default:
		return &Error{Kind: KindUnsupported, Detail: fmt.Sprintf("type %T", v)}
	}
	return nil
}

func encodeObject(buf *bytes.Buffer, m map[string]any, depth int) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		if !isASCII(k) {
			return &Error{Kind: KindNonASCIIKey, Detail: strconv.Quote(k)}
		}
		keys = append(keys, k)
	}
	sort.Strings(keys) // byte order; keys are ASCII so this equals UTF-16 order
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := encodeString(buf, k); err != nil {
			return err
		}
		buf.WriteByte(':')
		if err := encodeValue(buf, m[k], depth+1); err != nil {
			return err
		}
	}
	buf.WriteByte('}')
	return nil
}

func encodeInt(buf *bytes.Buffer, n int64) error {
	if n > MaxSafeInteger || n < -MaxSafeInteger {
		return &Error{Kind: KindIntRange, Detail: strconv.FormatInt(n, 10)}
	}
	buf.WriteString(strconv.FormatInt(n, 10))
	return nil
}

const hexDigits = "0123456789abcdef"

func encodeString(buf *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return &Error{Kind: KindInvalidUTF8}
	}
	buf.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
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
			if c < 0x20 {
				buf.WriteString(`\u00`)
				buf.WriteByte(hexDigits[c>>4])
				buf.WriteByte(hexDigits[c&0xf])
			} else {
				buf.WriteByte(c)
			}
		}
	}
	buf.WriteByte('"')
	return nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
