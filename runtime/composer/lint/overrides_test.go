package lint

import (
	"strings"
	"testing"
)

func TestDefaultOverrides(t *testing.T) {
	list, err := DefaultLicenseOverrides()
	if err != nil {
		t.Fatal(err)
	}
	set, err := newOverrideSet(list)
	if err != nil {
		t.Fatal(err)
	}
	// Every package the license audit lists (F4, F5) is covered, at the
	// versions syft reports, with the license the audit found.
	for purl, license := range map[string]string{
		"pkg:npm/map-stream@0.1.0":    "MIT",
		"pkg:npm/pause-stream@0.0.11": "MIT",
		"pkg:golang/github.com/ProjectZKM/Ziren/crates/go-runtime/zkvm_runtime@v0.0.0-20251001021608-1fe7b43fc4d6": "MIT OR Apache-2.0",
		"pkg:golang/github.com/ethereum/go-ethereum@v1.17.10":                                                      "LGPL-3.0-or-later AND BSD-3-Clause AND BSD-2-Clause-Views AND MIT",
		"pkg:pypi/google-crc32c@1.8.0":                                                                             "Apache-2.0",
		"pkg:pypi/aurelio-sdk@0.0.19":                                                                              "MIT",
		"pkg:pypi/llm-sandbox@0.3.39":                                                                              "MIT",
		"pkg:golang/github.com/sealed-dev/sealed":                                                                  "Apache-2.0",
		"pkg:golang/github.com/sealed-dev/sealed@v0.0.0-20261028165302-d4455a891137%2Bdirty":                       "Apache-2.0",
	} {
		o := set.lookup([]string{purl})
		if o == nil || o.License != license {
			t.Errorf("%s: got %+v, want %s", purl, o, license)
		}
	}
	// BSD-2-Clause-Views is allowed through the go-ethereum entry, not globally (F4).
	if EvaluateLicense("BSD-2-Clause-Views").Status != Unknown {
		t.Error("BSD-2-Clause-Views must not be on the global allowlist")
	}
	if o := set.lookup([]string{"pkg:golang/github.com/ethereum/go-ethereum@v1.17.10"}); !o.allow["BSD-2-Clause-Views"] {
		t.Errorf("%+v", o)
	}
	for _, miss := range []string{"pkg:npm/map-stream@0.1.1", "pkg:npm/pause-stream", "pkg:golang/github.com/ethereum/go-ethereum@v1.17.11", "pkg:golang/github.com/sealed-dev/sealed-extra@v1"} {
		if o := set.lookup([]string{miss}); o != nil {
			t.Errorf("%s: unexpected override %s", miss, o.PURL)
		}
	}
}

func TestCanonicalPURL(t *testing.T) {
	cases := []struct{ in, base, version string }{
		{"pkg:npm/%40anthropic-ai/claude-agent-sdk@0.2.9", "pkg:npm/@anthropic-ai/claude-agent-sdk", "0.2.9"},
		{"pkg:npm/@anthropic-ai/claude-agent-sdk", "pkg:npm/@anthropic-ai/claude-agent-sdk", ""},
		{"pkg:deb/debian/git@1%3A2.47.3-0%2Bdeb13u1?arch=amd64&distro=debian-13", "pkg:deb/debian/git", "1:2.47.3-0+deb13u1"},
		{"pkg:pypi/Google_CRC32C@1.8.0", "pkg:pypi/google-crc32c", "1.8.0"},
		{"pkg:pypi/zope.interface@7.0", "pkg:pypi/zope-interface", "7.0"},
		{"pkg:golang/github.com/shirou/gopsutil@v3.21.4-0.20210419000835-c7a38de76ee5%2Bincompatible", "pkg:golang/github.com/shirou/gopsutil", "v3.21.4-0.20210419000835-c7a38de76ee5+incompatible"},
		{"pkg:golang/github.com/ProjectZKM/Ziren/crates/go-runtime/zkvm_runtime@v0.0.0-1#sub", "pkg:golang/github.com/projectzkm/ziren/crates/go-runtime/zkvm_runtime", "v0.0.0-1"},
	}
	for _, c := range cases {
		base, version, ok := canonicalPURL(c.in)
		if !ok || base != c.base || version != c.version {
			t.Errorf("%s: got %q %q %v", c.in, base, version, ok)
		}
	}
	for _, bad := range []string{"", "npm/x@1", "pkg:", "pkg:npm", "pkg:npm/", "pkg:/x@1"} {
		if _, _, ok := canonicalPURL(bad); ok {
			t.Errorf("%q: want invalid", bad)
		}
	}
}

func TestParseLicenseOverrides(t *testing.T) {
	entry := func(extra string) string {
		return "version: 1\noverrides:\n  - purl: pkg:npm/left-pad@1.3.0\n    license: MIT\n    reason: LICENSE file in the 1.3.0 tarball is MIT.\n" +
			"    evidence: https://unpkg.com/left-pad@1.3.0/LICENSE\n    reviewed: 2026-10-28\n" + extra
	}
	if list, err := ParseLicenseOverrides([]byte(entry(""))); err != nil || len(list) != 1 {
		t.Fatalf("valid: %v %v", list, err)
	}
	cases := map[string]string{
		"version":                    strings.Replace(entry(""), "version: 1", "version: 2", 1),
		"unknown key":                entry("    note: x\n"),
		"no version in purl":         strings.Replace(entry(""), "left-pad@1.3.0\n", "left-pad\n", 1),
		"any_version with a version": entry("    any_version: true\n"),
		"not a purl":                 strings.Replace(entry(""), "pkg:npm/left-pad@1.3.0", "npm/left-pad@1.3.0", 1),
		"bad expression":             strings.Replace(entry(""), "license: MIT", "license: MIT AND", 1),
		"banned license":             strings.Replace(entry(""), "license: MIT", "license: SSPL-1.0", 1),
		"unknown license":            strings.Replace(entry(""), "license: MIT", "license: WTFPL", 1),
		"allow banned":               strings.Replace(entry("    allow: [SSPL-1.0]\n"), "license: MIT", "license: MIT AND SSPL-1.0", 1),
		"allow already allowed":      entry("    allow: [MIT]\n"),
		"allow not in expression":    strings.Replace(entry("    allow: [WTFPL]\n"), "license: MIT", "license: MIT AND BSD-2-Clause-Views", 1),
		"short reason":               strings.Replace(entry(""), "reason: LICENSE file in the 1.3.0 tarball is MIT.", "reason: ok", 1),
		"http evidence":              strings.Replace(entry(""), "https://", "http://", 1),
		"bad date":                   strings.Replace(entry(""), "reviewed: 2026-10-28", "reviewed: yesterday", 1),
		"duplicate":                  entry("  - purl: pkg:npm/LEFT-PAD@1.3.0\n    license: MIT\n    reason: LICENSE file in the 1.3.0 tarball is MIT.\n    evidence: https://unpkg.com/left-pad@1.3.0/LICENSE\n    reviewed: 2026-10-28\n"),
		"not yaml":                   "version: [1\n",
	}
	for name, raw := range cases {
		if _, err := ParseLicenseOverrides([]byte(raw)); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	// An allow list makes a reviewed id acceptable for that entry.
	ok := strings.Replace(entry("    allow: [WTFPL]\n"), "license: MIT", "license: MIT AND WTFPL", 1)
	if _, err := ParseLicenseOverrides([]byte(ok)); err != nil {
		t.Fatal(err)
	}
	// any_version needs a versionless purl.
	anyv := strings.Replace(entry("    any_version: true\n"), "left-pad@1.3.0\n", "left-pad\n", 1)
	if _, err := ParseLicenseOverrides([]byte(anyv)); err != nil {
		t.Fatal(err)
	}
}

func TestBrokenOverridesFailTheLint(t *testing.T) {
	dir := copyApp(t, "notes")
	bad := []LicenseOverride{{PURL: "pkg:npm/x", License: "MIT", Reason: "too short", Evidence: "ftp://x", Reviewed: "x"}}
	fs := LintApp(dir, Options{Overrides: bad})
	if codes(fs, Error)[CodeOverrides] != 1 {
		t.Fatalf("%v", fs)
	}
}
