package composer

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/sealed-dev/sealed/catalog/schema"
)

func TestGenerateSecret(t *testing.T) {
	formats := map[string]*regexp.Regexp{
		GenerateHex32:    regexp.MustCompile(`^[0-9a-f]{64}$`),
		GenerateSKHex32:  regexp.MustCompile(`^sk-[0-9a-f]{64}$`),
		GeneratePassword: regexp.MustCompile(`^[A-Za-z0-9]{24}$`),
	}
	for kind, re := range formats {
		a, err := GenerateSecret(kind, nil)
		if err != nil || !re.MatchString(a) {
			t.Errorf("%s: %q %v", kind, a, err)
		}
		if b, _ := GenerateSecret(kind, nil); a == b {
			t.Errorf("%s repeated a value", kind)
		}
	}
	v, err := GenerateSecret(GenerateBase6432, nil)
	if raw, derr := base64.StdEncoding.DecodeString(v); err != nil || derr != nil || len(raw) != 32 {
		t.Errorf("base64-32: %q %v %v", v, err, derr)
	}
	for _, k := range []string{GenerateNone, "passphrase", ""} {
		if _, err := GenerateSecret(k, nil); err == nil {
			t.Errorf("%q generated a value", k)
		}
	}
	if _, err := GenerateSecret(GeneratePassword, bytes.NewReader(make([]byte, 3))); err == nil {
		t.Error("short random source accepted")
	}
}

// TestPasswordIsUniform checks the rejection sampling: bytes from 248 up
// are discarded, the rest map to PasswordAlphabet[b%62], so each character
// comes from exactly four byte values; and a sample from crypto/rand covers
// the alphabet evenly.
func TestPasswordIsUniform(t *testing.T) {
	src := bytes.Repeat([]byte{0xff}, 32) // a whole block of rejected bytes
	block := make([]byte, 32)
	for i := range block {
		block[i] = byte(i + 62) // 62..93 map to the alphabet from its start
	}
	src = append(src, block...)
	p, err := GenerateSecret(GeneratePassword, bytes.NewReader(src))
	if err != nil || p != PasswordAlphabet[:PasswordLength] {
		t.Fatalf("got %q %v, want %q", p, err, PasswordAlphabet[:PasswordLength])
	}
	per := map[byte]int{}
	for b := 0; b < 256-256%len(PasswordAlphabet); b++ {
		per[PasswordAlphabet[b%len(PasswordAlphabet)]]++
	}
	for c, n := range per {
		if n != 4 {
			t.Errorf("%c comes from %d byte values", c, n)
		}
	}
	counts := map[rune]int{}
	const samples = 2000
	for i := 0; i < samples; i++ {
		p, err := GenerateSecret(GeneratePassword, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range p {
			counts[c]++
		}
	}
	expect := float64(samples*PasswordLength) / float64(len(PasswordAlphabet))
	for _, c := range PasswordAlphabet {
		if n := float64(counts[c]); n < expect*0.8 || n > expect*1.2 {
			t.Errorf("%c appeared %v times, expected about %.0f", c, n, expect)
		}
	}
}

// TestSchemaGenerators keeps the schema enum and the Go generators in step.
func TestSchemaGenerators(t *testing.T) {
	var s struct {
		Properties struct {
			Secrets struct {
				Items struct {
					Properties struct {
						Generate struct {
							Enum []string `json:"enum"`
						} `json:"generate"`
					} `json:"properties"`
				} `json:"items"`
			} `json:"secrets"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(schema.ManifestJSON, &s); err != nil {
		t.Fatal(err)
	}
	enum := s.Properties.Secrets.Items.Properties.Generate.Enum
	if strings.Join(enum, ",") != "none,hex32,base64-32,sk-hex32,password" {
		t.Fatalf("schema generators %v", enum)
	}
	for _, k := range enum {
		_, err := GenerateSecret(k, nil)
		if (err == nil) == (k == GenerateNone) {
			t.Errorf("%s: %v", k, err)
		}
	}
}
