package composer

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

// Secret generators (manifest secrets[].generate). sealed secrets set
// --generate uses them when the customer supplies no value; the catalog
// schema lists the same names.
const (
	GenerateNone     = "none"
	GenerateHex32    = "hex32"     // 32 random bytes, 64 lowercase hex characters
	GenerateBase6432 = "base64-32" // 32 random bytes, standard base64 with padding
	GenerateSKHex32  = "sk-hex32"  // "sk-" followed by hex32
	GeneratePassword = "password"  // 24 characters drawn uniformly from [A-Za-z0-9] (D-043)
)

// PasswordLength and PasswordAlphabet define the password generator.
const (
	PasswordLength   = 24
	PasswordAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)

// GenerateSecret returns a new value for a generator from rnd (nil means
// crypto/rand). It fails for "none" and unknown generators.
func GenerateSecret(kind string, rnd io.Reader) (string, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	read := func(n int) ([]byte, error) {
		b := make([]byte, n)
		if _, err := io.ReadFull(rnd, b); err != nil {
			return nil, fmt.Errorf("generate %s: %w", kind, err)
		}
		return b, nil
	}
	switch kind {
	case GenerateHex32, GenerateSKHex32:
		b, err := read(32)
		if err != nil {
			return "", err
		}
		if kind == GenerateSKHex32 {
			return "sk-" + hex.EncodeToString(b), nil
		}
		return hex.EncodeToString(b), nil
	case GenerateBase6432:
		b, err := read(32)
		if err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(b), nil
	case GeneratePassword:
		// Rejection sampling: bytes >= 248 (the largest multiple of 62 below
		// 256) are discarded, so every character is equally likely.
		const limit = 256 - 256%len(PasswordAlphabet)
		out := make([]byte, 0, PasswordLength)
		buf := make([]byte, 32)
		for len(out) < PasswordLength {
			if _, err := io.ReadFull(rnd, buf); err != nil {
				return "", fmt.Errorf("generate %s: %w", kind, err)
			}
			for _, c := range buf {
				if int(c) < limit && len(out) < PasswordLength {
					out = append(out, PasswordAlphabet[int(c)%len(PasswordAlphabet)])
				}
			}
		}
		return string(out), nil
	case GenerateNone:
		return "", fmt.Errorf("secret generator none: the customer must supply the value")
	}
	return "", fmt.Errorf("unknown secret generator %q", kind)
}
