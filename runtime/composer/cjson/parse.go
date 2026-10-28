package cjson

import (
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Parse decodes a strict JSON document (RFC 8259) into nil, bool, int64,
// string, []any and map[string]any, applying the canonical-JSON
// restrictions: integers only and within +/- 2^53, unique ASCII keys, valid
// UTF-8 and no lone surrogates.
func Parse(in []byte) (any, error) {
	if !utf8.Valid(in) {
		return nil, &Error{Kind: KindInvalidUTF8, Offset: firstInvalidUTF8(in)}
	}
	p := &parser{in: in}
	p.skipWS()
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.skipWS()
	if p.pos != len(p.in) {
		return nil, p.fail(KindInvalidJSON, "trailing data")
	}
	return v, nil
}

type parser struct {
	in  []byte
	pos int
}

func (p *parser) fail(kind, detail string) error {
	return &Error{Kind: kind, Offset: p.pos, Detail: detail}
}

func (p *parser) skipWS() {
	for p.pos < len(p.in) {
		switch p.in[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *parser) value(depth int) (any, error) {
	if depth > maxDepth {
		return nil, p.fail(KindInvalidJSON, "nesting too deep")
	}
	if p.pos >= len(p.in) {
		return nil, p.fail(KindInvalidJSON, "unexpected end of input")
	}
	switch c := p.in[p.pos]; {
	case c == '{':
		return p.object(depth)
	case c == '[':
		return p.array(depth)
	case c == '"':
		return p.str()
	case c == 't':
		return true, p.literal("true")
	case c == 'f':
		return false, p.literal("false")
	case c == 'n':
		return nil, p.literal("null")
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	default:
		return nil, p.fail(KindInvalidJSON, "unexpected character "+strconv.QuoteRune(rune(c)))
	}
}

func (p *parser) literal(word string) error {
	if !strings.HasPrefix(string(p.in[p.pos:min(len(p.in), p.pos+len(word))]), word) {
		return p.fail(KindInvalidJSON, "invalid literal")
	}
	p.pos += len(word)
	return nil
}

func (p *parser) object(depth int) (any, error) {
	p.pos++ // {
	obj := map[string]any{}
	p.skipWS()
	if p.pos < len(p.in) && p.in[p.pos] == '}' {
		p.pos++
		return obj, nil
	}
	for {
		p.skipWS()
		if p.pos >= len(p.in) || p.in[p.pos] != '"' {
			return nil, p.fail(KindInvalidJSON, "expected object key")
		}
		keyPos := p.pos
		k, err := p.str()
		if err != nil {
			return nil, err
		}
		if !isASCII(k) {
			return nil, &Error{Kind: KindNonASCIIKey, Offset: keyPos, Detail: strconv.Quote(k)}
		}
		if _, dup := obj[k]; dup {
			return nil, &Error{Kind: KindDuplicateKey, Offset: keyPos, Detail: strconv.Quote(k)}
		}
		p.skipWS()
		if p.pos >= len(p.in) || p.in[p.pos] != ':' {
			return nil, p.fail(KindInvalidJSON, "expected ':'")
		}
		p.pos++
		p.skipWS()
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		obj[k] = v
		p.skipWS()
		if p.pos >= len(p.in) {
			return nil, p.fail(KindInvalidJSON, "unterminated object")
		}
		switch p.in[p.pos] {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return obj, nil
		default:
			return nil, p.fail(KindInvalidJSON, "expected ',' or '}'")
		}
	}
}

func (p *parser) array(depth int) (any, error) {
	p.pos++ // [
	arr := []any{}
	p.skipWS()
	if p.pos < len(p.in) && p.in[p.pos] == ']' {
		p.pos++
		return arr, nil
	}
	for {
		p.skipWS()
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		arr = append(arr, v)
		p.skipWS()
		if p.pos >= len(p.in) {
			return nil, p.fail(KindInvalidJSON, "unterminated array")
		}
		switch p.in[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return arr, nil
		default:
			return nil, p.fail(KindInvalidJSON, "expected ',' or ']'")
		}
	}
}

func (p *parser) number() (any, error) {
	start := p.pos
	if p.in[p.pos] == '-' {
		p.pos++
	}
	if p.pos >= len(p.in) {
		return nil, p.fail(KindInvalidJSON, "invalid number")
	}
	switch {
	case p.in[p.pos] == '0':
		p.pos++
	case p.in[p.pos] >= '1' && p.in[p.pos] <= '9':
		for p.pos < len(p.in) && isDigit(p.in[p.pos]) {
			p.pos++
		}
	default:
		return nil, p.fail(KindInvalidJSON, "invalid number")
	}
	isFloat := false
	if p.pos < len(p.in) && p.in[p.pos] == '.' {
		isFloat = true
		p.pos++
		if !p.digits() {
			return nil, p.fail(KindInvalidJSON, "invalid number")
		}
	}
	if p.pos < len(p.in) && (p.in[p.pos] == 'e' || p.in[p.pos] == 'E') {
		isFloat = true
		p.pos++
		if p.pos < len(p.in) && (p.in[p.pos] == '+' || p.in[p.pos] == '-') {
			p.pos++
		}
		if !p.digits() {
			return nil, p.fail(KindInvalidJSON, "invalid number")
		}
	}
	text := string(p.in[start:p.pos])
	if isFloat {
		return nil, &Error{Kind: KindFloat, Offset: start, Detail: text}
	}
	n, err := strconv.ParseInt(text, 10, 64)
	if err != nil || n > MaxSafeInteger || n < -MaxSafeInteger {
		return nil, &Error{Kind: KindIntRange, Offset: start, Detail: text}
	}
	return n, nil
}

func (p *parser) digits() bool {
	start := p.pos
	for p.pos < len(p.in) && isDigit(p.in[p.pos]) {
		p.pos++
	}
	return p.pos > start
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func (p *parser) str() (string, error) {
	p.pos++ // opening quote
	var sb strings.Builder
	for {
		if p.pos >= len(p.in) {
			return "", p.fail(KindInvalidJSON, "unterminated string")
		}
		c := p.in[p.pos]
		switch {
		case c == '"':
			p.pos++
			return sb.String(), nil
		case c == '\\':
			if err := p.escape(&sb); err != nil {
				return "", err
			}
		case c < 0x20:
			return "", p.fail(KindInvalidJSON, "control character in string")
		default:
			sb.WriteByte(c)
			p.pos++
		}
	}
}

func (p *parser) escape(sb *strings.Builder) error {
	p.pos++ // backslash
	if p.pos >= len(p.in) {
		return p.fail(KindInvalidJSON, "unterminated escape")
	}
	c := p.in[p.pos]
	p.pos++
	switch c {
	case '"', '\\', '/':
		sb.WriteByte(c)
	case 'b':
		sb.WriteByte('\b')
	case 'f':
		sb.WriteByte('\f')
	case 'n':
		sb.WriteByte('\n')
	case 'r':
		sb.WriteByte('\r')
	case 't':
		sb.WriteByte('\t')
	case 'u':
		r, err := p.hex4()
		if err != nil {
			return err
		}
		if utf16.IsSurrogate(r) {
			if r >= 0xdc00 || p.pos+1 >= len(p.in) || p.in[p.pos] != '\\' || p.in[p.pos+1] != 'u' {
				return p.fail(KindInvalidJSON, "lone surrogate")
			}
			p.pos += 2
			r2, err := p.hex4()
			if err != nil {
				return err
			}
			if r2 < 0xdc00 || r2 > 0xdfff {
				return p.fail(KindInvalidJSON, "lone surrogate")
			}
			r = utf16.DecodeRune(r, r2)
		}
		sb.WriteRune(r)
	default:
		return p.fail(KindInvalidJSON, "invalid escape")
	}
	return nil
}

func (p *parser) hex4() (rune, error) {
	if p.pos+4 > len(p.in) {
		return 0, p.fail(KindInvalidJSON, "short unicode escape")
	}
	n, err := strconv.ParseUint(string(p.in[p.pos:p.pos+4]), 16, 32)
	if err != nil {
		return 0, p.fail(KindInvalidJSON, "invalid unicode escape")
	}
	p.pos += 4
	return rune(n), nil
}

func firstInvalidUTF8(b []byte) int {
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		if r == utf8.RuneError && size <= 1 {
			return i
		}
		i += size
	}
	return len(b)
}
