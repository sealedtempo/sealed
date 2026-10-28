// Package hexb decodes and encodes the hex byte strings used in Sealed JSON documents.
package hexb

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Decode parses a hex string with an optional 0x prefix. When n >= 0 the result must be exactly n bytes.
func Decode(s string, n int) ([]byte, error) {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}
	if n >= 0 && len(b) != n {
		return nil, fmt.Errorf("want %d bytes, got %d", n, len(b))
	}
	return b, nil
}

// Decode32 parses a 32-byte hex value.
func Decode32(s string) ([32]byte, error) {
	var out [32]byte
	b, err := Decode(s, 32)
	if err != nil {
		return out, err
	}
	copy(out[:], b)
	return out, nil
}

// Decode20 parses a 20-byte hex value (an address).
func Decode20(s string) ([20]byte, error) {
	var out [20]byte
	b, err := Decode(s, 20)
	if err != nil {
		return out, err
	}
	copy(out[:], b)
	return out, nil
}

// Enc returns lowercase hex with a 0x prefix.
func Enc(b []byte) string { return "0x" + hex.EncodeToString(b) }
