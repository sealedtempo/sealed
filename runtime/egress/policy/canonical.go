package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"unicode/utf8"
)

// The egress config is measured, so the bytes egress reads must be the
// canonical JSON (INTERFACES section 1) the composer hashed. Re-encoding the
// parsed document and comparing bytes also rejects duplicate keys, floats,
// whitespace and non-canonical escapes in one pass.

const maxSafeInteger = 1<<53 - 1

var integerPattern = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

// decodeTree parses JSON into maps, slices, strings, bools, nil and
// json.Number, rejecting trailing data.
func decodeTree(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("config is not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		return nil, fmt.Errorf("config is not valid JSON: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("config has trailing data after the JSON document")
	}
	return tree, nil
}

// CheckCanonical returns nil when data is exactly the canonical JSON encoding
// of the document it contains.
func CheckCanonical(data []byte) error {
	tree, err := decodeTree(data)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := encodeCanonical(&buf, tree); err != nil {
		return err
	}
	if !bytes.Equal(buf.Bytes(), data) {
		return errors.New("config is not canonical JSON (sorted keys, no whitespace, no duplicate keys, no trailing newline)")
	}
	return nil
}

func encodeCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		buf.WriteString(strconv.FormatBool(t))
	case json.Number:
		s := t.String()
		if !integerPattern.MatchString(s) {
			return fmt.Errorf("number %s is not an integer", s)
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n > maxSafeInteger || n < -maxSafeInteger {
			return fmt.Errorf("number %s is outside +/- 2^53", s)
		}
		buf.WriteString(s)
	case string:
		encodeString(buf, t)
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encodeCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			for i := 0; i < len(k); i++ {
				if k[i] >= utf8.RuneSelf {
					return fmt.Errorf("object key %q is not ASCII", k)
				}
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			encodeString(buf, k)
			buf.WriteByte(':')
			if err := encodeCanonical(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("unexpected JSON value of type %T", v)
	}
	return nil
}

func encodeString(buf *bytes.Buffer, s string) {
	const hex = "0123456789abcdef"
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
				buf.WriteByte(hex[c>>4])
				buf.WriteByte(hex[c&0xf])
			} else {
				buf.WriteByte(c)
			}
		}
	}
	buf.WriteByte('"')
}

// EncodeCanonical returns the canonical JSON encoding of v after a standard
// JSON round trip. Tests and tooling use it to produce configs egress accepts.
func EncodeCanonical(v any) ([]byte, error) {
	var raw bytes.Buffer
	enc := json.NewEncoder(&raw)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	tree, err := decodeTree(bytes.TrimSuffix(raw.Bytes(), []byte("\n")))
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := encodeCanonical(&buf, tree); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
