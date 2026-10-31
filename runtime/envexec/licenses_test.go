package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDockerfileChecksGoLicenseHashes covers review finding policy-5: the
// sealed-init image ships Go's LICENSE and PATENTS, and the build fails unless
// they are Go 1.27.3's texts byte for byte. The Dockerfile checks the sha256 of
// the GOROOT files it copies to /out/licenses/go/; the hashes must be those of
// the upstream texts in catalog/apps/llm-gateway/LICENSES/, whose git blob ids
// are the ones `gh api repos/golang/go/contents/<file>?ref=go1.27.3` reports.
// The builder must be Go 1.27.3, the version those texts belong to.
func TestDockerfileChecksGoLicenseHashes(t *testing.T) {
	b, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	instrs := instructions(string(b))
	build, final := -1, -1
	for i, in := range instrs {
		if strings.HasPrefix(in, "FROM ") {
			if build < 0 {
				build = i
			}
			final = i
		}
	}
	if build < 0 || final <= build {
		t.Fatalf("want a build stage and a final stage, got %d instructions", len(instrs))
	}
	if !strings.Contains(instrs[build], " golang:1.27.3-") {
		t.Errorf("build stage %q is not Go 1.27.3, the version of the license texts", instrs[build])
	}
	stage := instrs[build+1 : final]
	texts := filepath.Join("..", "..", "catalog", "apps", "llm-gateway", "LICENSES")
	for _, c := range []struct{ arg, text, blob, file string }{
		{"GO_LICENSE_SHA256", "go-1.27.3-LICENSE", "2a7cf70da6e498df9c11ab6a5eaa2ddd7af34da4", "$(go env GOROOT)/LICENSE"},
		{"GO_PATENTS_SHA256", "go-1.27.3-PATENTS", "733099041f84fa1e58611ab2e11af51c1f26d1d2", "$(go env GOROOT)/PATENTS"},
	} {
		data, err := os.ReadFile(filepath.Join(texts, c.text))
		if err != nil {
			t.Fatal(err)
		}
		if got := gitBlob(data); got != c.blob {
			t.Fatalf("%s is git blob %s, golang/go go1.27.3 is %s", c.text, got, c.blob)
		}
		sum := sha256.Sum256(data)
		want := hex.EncodeToString(sum[:])
		check := fmt.Sprintf(`echo "$%s  %s" | sha256sum -c -`, c.arg, c.file)
		declared, checked, copied := -1, -1, false
		for i, in := range stage {
			if in == "ARG "+c.arg+"="+want {
				declared = i
			}
			if !strings.HasPrefix(in, "RUN ") {
				continue
			}
			if strings.Contains(in, check) {
				checked = i
			}
			copied = copied || strings.Contains(in, "cp ") && strings.Contains(in, `"`+c.file+`"`) && strings.Contains(in, " /out/licenses/go/")
		}
		switch {
		case declared < 0:
			t.Errorf("build stage does not declare ARG %s=%s (sha256 of %s)", c.arg, want, c.text)
		case checked < declared:
			t.Errorf("build stage does not run %s after declaring %s", check, c.arg)
		case !copied:
			t.Errorf("build stage does not copy the checked %s into /out/licenses/go/", c.file)
		}
	}
}

// instructions returns the Dockerfile's instructions with continuation lines
// joined and comment lines dropped.
func instructions(text string) []string {
	var out []string
	cur := ""
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if s, ok := strings.CutSuffix(l, `\`); ok {
			cur += strings.TrimSpace(s) + " "
			continue
		}
		out = append(out, cur+l)
		cur = ""
	}
	return out
}

// gitBlob is the git blob id of data, as git hash-object prints it.
func gitBlob(data []byte) string {
	h := sha1.New()
	fmt.Fprintf(h, "blob %d\x00", len(data))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}
