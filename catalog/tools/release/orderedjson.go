package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// ojValue is a JSON value that keeps object key order and the exact text of scalars, so a file can be
// edited in place and written back with only the edited values changed. Output uses the layout of
// json.MarshalIndent with two spaces and a trailing newline, which is how runtime-images.json and
// extra-images.json are written.
type ojValue struct {
	obj    []ojMember // object members, in order
	arr    []*ojValue
	scalar string // raw JSON text of a string, number, true, false or null
	kind   byte   // 'o', 'a' or 's'
}

type ojMember struct {
	key string // raw JSON text of the key, quotes included
	val *ojValue
}

func parseOrderedJSON(in []byte) (*ojValue, error) {
	p := &ojParser{in: in}
	p.ws()
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.ws()
	if p.pos != len(p.in) {
		return nil, fmt.Errorf("json: trailing data at offset %d", p.pos)
	}
	return v, nil
}

type ojParser struct {
	in  []byte
	pos int
}

func (p *ojParser) ws() {
	for p.pos < len(p.in) {
		switch p.in[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *ojParser) value(depth int) (*ojValue, error) {
	if depth > 64 {
		return nil, fmt.Errorf("json: nesting too deep")
	}
	if p.pos >= len(p.in) {
		return nil, fmt.Errorf("json: unexpected end")
	}
	switch c := p.in[p.pos]; {
	case c == '{':
		p.pos++
		v := &ojValue{kind: 'o'}
		p.ws()
		if p.pos < len(p.in) && p.in[p.pos] == '}' {
			p.pos++
			return v, nil
		}
		for {
			p.ws()
			key, err := p.scalarText()
			if err != nil {
				return nil, err
			}
			if !strings.HasPrefix(key, `"`) {
				return nil, fmt.Errorf("json: object key must be a string at offset %d", p.pos)
			}
			p.ws()
			if p.pos >= len(p.in) || p.in[p.pos] != ':' {
				return nil, fmt.Errorf("json: expected ':' at offset %d", p.pos)
			}
			p.pos++
			p.ws()
			val, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			for _, m := range v.obj {
				if m.key == key {
					return nil, fmt.Errorf("json: duplicate key %s", key)
				}
			}
			v.obj = append(v.obj, ojMember{key: key, val: val})
			p.ws()
			if p.pos < len(p.in) && p.in[p.pos] == ',' {
				p.pos++
				continue
			}
			if p.pos < len(p.in) && p.in[p.pos] == '}' {
				p.pos++
				return v, nil
			}
			return nil, fmt.Errorf("json: expected ',' or '}' at offset %d", p.pos)
		}
	case c == '[':
		p.pos++
		v := &ojValue{kind: 'a'}
		p.ws()
		if p.pos < len(p.in) && p.in[p.pos] == ']' {
			p.pos++
			return v, nil
		}
		for {
			p.ws()
			el, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			v.arr = append(v.arr, el)
			p.ws()
			if p.pos < len(p.in) && p.in[p.pos] == ',' {
				p.pos++
				continue
			}
			if p.pos < len(p.in) && p.in[p.pos] == ']' {
				p.pos++
				return v, nil
			}
			return nil, fmt.Errorf("json: expected ',' or ']' at offset %d", p.pos)
		}
	default:
		s, err := p.scalarText()
		if err != nil {
			return nil, err
		}
		return &ojValue{kind: 's', scalar: s}, nil
	}
}

// scalarText consumes one scalar and returns its raw text, checked with encoding/json.
func (p *ojParser) scalarText() (string, error) {
	start := p.pos
	if p.pos < len(p.in) && p.in[p.pos] == '"' {
		p.pos++
		for p.pos < len(p.in) {
			switch p.in[p.pos] {
			case '\\':
				p.pos += 2
				continue
			case '"':
				p.pos++
				raw := p.in[start:p.pos]
				if !json.Valid(raw) {
					return "", fmt.Errorf("json: invalid string at offset %d", start)
				}
				return string(raw), nil
			}
			p.pos++
		}
		return "", fmt.Errorf("json: unterminated string at offset %d", start)
	}
	for p.pos < len(p.in) && !bytes.ContainsRune([]byte(" \t\r\n,]}:"), rune(p.in[p.pos])) {
		p.pos++
	}
	raw := p.in[start:p.pos]
	var v any
	if len(raw) == 0 || json.Unmarshal(raw, &v) != nil {
		return "", fmt.Errorf("json: invalid value at offset %d", start)
	}
	return string(raw), nil
}

func (v *ojValue) encode() []byte {
	var b bytes.Buffer
	v.write(&b, "")
	b.WriteByte('\n')
	return b.Bytes()
}

func (v *ojValue) write(b *bytes.Buffer, indent string) {
	switch v.kind {
	case 's':
		b.WriteString(v.scalar)
	case 'o':
		if len(v.obj) == 0 {
			b.WriteString("{}")
			return
		}
		b.WriteString("{\n")
		for i, m := range v.obj {
			b.WriteString(indent + "  " + m.key + ": ")
			m.val.write(b, indent+"  ")
			if i < len(v.obj)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		b.WriteString(indent + "}")
	case 'a':
		if len(v.arr) == 0 {
			b.WriteString("[]")
			return
		}
		b.WriteString("[\n")
		for i, el := range v.arr {
			b.WriteString(indent + "  ")
			el.write(b, indent+"  ")
			if i < len(v.arr)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		b.WriteString(indent + "]")
	}
}

func jsonKey(k string) string {
	b, _ := json.Marshal(k)
	return string(b)
}

// get returns the member value for key, or nil.
func (v *ojValue) get(key string) *ojValue {
	if v == nil || v.kind != 'o' {
		return nil
	}
	k := jsonKey(key)
	for _, m := range v.obj {
		if m.key == k {
			return m.val
		}
	}
	return nil
}

// str returns the decoded string of a string scalar.
func (v *ojValue) str() (string, bool) {
	if v == nil || v.kind != 's' || !strings.HasPrefix(v.scalar, `"`) {
		return "", false
	}
	var s string
	if json.Unmarshal([]byte(v.scalar), &s) != nil {
		return "", false
	}
	return s, true
}

// setString sets key to a string value, appending the member when it is missing.
func (v *ojValue) setString(key, value string) {
	enc := &bytes.Buffer{}
	e := json.NewEncoder(enc)
	e.SetEscapeHTML(false)
	_ = e.Encode(value)
	raw := strings.TrimSuffix(enc.String(), "\n")
	if cur := v.get(key); cur != nil {
		*cur = ojValue{kind: 's', scalar: raw}
		return
	}
	v.obj = append(v.obj, ojMember{key: jsonKey(key), val: &ojValue{kind: 's', scalar: raw}})
}

// del removes key and reports whether it was present.
func (v *ojValue) del(key string) bool {
	k := jsonKey(key)
	for i, m := range v.obj {
		if m.key == k {
			v.obj = append(v.obj[:i], v.obj[i+1:]...)
			return true
		}
	}
	return false
}
