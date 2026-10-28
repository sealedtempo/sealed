package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var testDay = time.Date(2026, 10, 28, 15, 0, 0, 0, time.UTC)

// grypeFixture follows the layout of grype v0.121.0's JSON presenter (grype/presenter/json testdata).
const grypeFixture = `{
 "matches": [
  {"vulnerability": {"id": "CVE-2026-1000", "severity": "Critical", "fix": {"versions": ["3.0.1"], "state": "fixed"}},
   "relatedVulnerabilities": [], "artifact": {"id": "a1", "name": "openssl", "version": "3.0.0", "type": "deb", "purl": "pkg:deb/debian/openssl@3.0.0"}},
  {"vulnerability": {"id": "CVE-2026-1000", "severity": "Critical", "fix": {"versions": ["3.0.1"], "state": "fixed"}},
   "relatedVulnerabilities": [], "artifact": {"id": "a2", "name": "openssl", "version": "3.0.0", "type": "deb", "purl": "pkg:deb/debian/openssl@3.0.0"}},
  {"vulnerability": {"id": "GHSA-2222-3333-4444", "severity": "Critical", "fix": {"versions": [], "state": "not-fixed"}},
   "relatedVulnerabilities": [{"id": "CVE-2026-2000", "severity": "Critical"}], "artifact": {"id": "b", "name": "lodash", "version": "4.17.0", "type": "npm"}},
  {"vulnerability": {"id": "CVE-2026-3000", "severity": "Critical", "fix": {"state": "unknown"}},
   "relatedVulnerabilities": [], "artifact": {"id": "c", "name": "zlib", "version": "1.2", "type": "apk"}},
  {"vulnerability": {"id": "CVE-2026-4000", "severity": "High"}, "relatedVulnerabilities": [], "artifact": {"id": "d", "name": "curl", "version": "8", "type": "deb"}},
  {"vulnerability": {"id": "CVE-2026-5000", "severity": "Negligible"}, "relatedVulnerabilities": [], "artifact": {"id": "e", "name": "bash", "version": "5", "type": "deb"}}
 ],
 "source": {"type": "image"},
 "distro": {"name": "debian", "version": "12"},
 "descriptor": {"name": "grype", "version": "0.121.0", "db": {"status": {"schemaVersion": "v6.1.0"}}}
}`

func waiverFile(t *testing.T, body string) *WaiverFile {
	t.Helper()
	wf, err := ParseWaivers("waivers.yaml", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return wf
}

func TestEvaluate(t *testing.T) {
	rep, err := ParseGrype([]byte(grypeFixture))
	if err != nil {
		t.Fatal(err)
	}
	wf := waiverFile(t, `version: 1
waivers:
  - id: CVE-2026-2000            # the related CVE of the GHSA match
    image: web
    package: lodash
    reason: the vulnerable template function is never called
    expires: 2026-11-30
  - id: CVE-2026-3000
    image: web
    package: zlib
    reason: expired waiver, must stop applying
    expires: 2026-10-27
  - id: CVE-2026-1000
    image: other                  # a different image: does not apply here
    package: openssl
    reason: applies to another image only
    expires: 2026-11-30
  - id: CVE-2026-9999
    image: web
    package: gone
    reason: finding no longer reported
    expires: 2026-11-30
`)
	s := Evaluate(rep, "web", wf, testDay)
	if s.Counts["critical"] != 3 || s.Counts["high"] != 1 || s.Counts["negligible"] != 1 {
		t.Fatalf("counts (duplicates collapse): %v", s.Counts)
	}
	ids := func(fs []ScanFinding) string {
		var out []string
		for _, f := range fs {
			out = append(out, f.ID+"/"+f.Package)
		}
		return strings.Join(out, ",")
	}
	if got := ids(s.Unwaived); got != "CVE-2026-1000/openssl,CVE-2026-3000/zlib" {
		t.Fatalf("unwaived = %s", got)
	}
	if got := ids(s.Accepted); got != "GHSA-2222-3333-4444/lodash" || s.Accepted[0].Note == "" || s.Accepted[0].Expires != "2026-11-30" {
		t.Fatalf("accepted = %s %+v", got, s.Accepted)
	}
	if got := ids(s.ExpiredHits); got != "CVE-2026-3000/zlib" {
		t.Fatalf("expired hits = %s", got)
	}
	if len(s.UnusedWaivers) != 1 || s.UnusedWaivers[0].ID != "CVE-2026-9999" {
		t.Fatalf("unused = %+v", s.UnusedWaivers)
	}
	if s.OK() {
		t.Fatal("gate must fail with unwaived criticals")
	}
	if s.Unwaived[0].Fix != "3.0.1" {
		t.Fatalf("fix versions: %+v", s.Unwaived[0])
	}
	rep2 := s.Report()
	mustContain(t, rep2, "UNWAIVED  critical CVE-2026-1000 openssl 3.0.0, fixed in 3.0.1")
	mustContain(t, rep2, "expired waiver no longer covers CVE-2026-3000 in zlib")

	// The waiver applies through its expiry day and stops the day after.
	last := waiverFile(t, "version: 1\nwaivers:\n  - {id: CVE-2026-1000, image: web, package: openssl, reason: accepted until upstream ships 3.0.1, expires: 2026-10-28}\n  - {id: CVE-2026-3000, image: web, package: zlib, reason: accepted while the fix is tested, expires: 2026-11-01}\n  - {id: GHSA-2222-3333-4444, image: web, package: lodash, reason: the vulnerable code path is unused, expires: 2026-11-01}\n")
	if s := Evaluate(rep, "web", last, testDay); !s.OK() {
		t.Fatalf("all criticals waived on the expiry day: %s", s.Report())
	}
	if s := Evaluate(rep, "web", last, testDay.Add(24*time.Hour)); s.OK() || s.Unwaived[0].ID != "CVE-2026-1000" {
		t.Fatalf("the day after expiry the waiver no longer applies: %s", s.Report())
	}
	// No findings, no waivers file.
	empty, _ := ParseGrype([]byte(`{"matches":[]}`))
	if s := Evaluate(empty, "web", nil, testDay); !s.OK() || s.Counts["critical"] != 0 {
		t.Fatal("empty report passes")
	}
}

func TestParseGrypeRejectsOtherJSON(t *testing.T) {
	if _, err := ParseGrype([]byte(`{"spdxVersion":"SPDX-2.3"}`)); err == nil {
		t.Fatal("an SBOM is not a grype report")
	}
	if _, err := ParseGrype([]byte(`not json`)); err == nil {
		t.Fatal("invalid JSON")
	}
}

func TestParseWaiversFormats(t *testing.T) {
	root := repoRoot(t)
	// Every committed waivers file parses; the scraper's is the canonical format.
	matches, _ := filepath.Glob(filepath.Join(root, CatalogDir, "*", "waivers.yaml"))
	matches = append(matches, filepath.Join(root, RuntimeWaiversFile), filepath.Join(root, CatalogDir, "coding-agent/fallback-opencode/waivers.yaml"))
	for _, p := range matches {
		wf, err := LoadWaivers(p)
		if err != nil {
			t.Errorf("%s: %v", p, err)
			continue
		}
		if strings.Contains(p, "/scraper/") && wf.Legacy {
			t.Errorf("scraper waivers are the canonical format")
		}
	}
	for name, body := range map[string]string{
		"empty":          "",
		"wrong version":  "version: 2\nwaivers: []\n",
		"missing list":   "version: 1\n",
		"unknown key":    "version: 1\nwaivers:\n  - {id: CVE-2026-1, image: a, package: b, reason: long enough reason, expires: 2026-11-01, owner: me}\n",
		"scalar":         "nope\n",
		"top level typo": "version: 1\nwaiver: []\n",
	} {
		if _, err := ParseWaivers("w.yaml", []byte(body)); err == nil {
			t.Errorf("%s: should fail", name)
		}
	}
	legacy := waiverFile(t, "[]\n")
	if !legacy.Legacy || len(legacy.Waivers) != 0 {
		t.Fatal("bare list is the legacy format")
	}
}

func TestValidateWaivers(t *testing.T) {
	wf := waiverFile(t, `version: 1
waivers:
  - {id: CVE-2026-1, image: web, package: a, reason: fine reason here, expires: 2026-11-01}
  - {id: NOT-AN-ID!, image: web, package: a, reason: fine reason here, expires: 2026-11-01}
  - {id: CVE-2026-2, image: db, package: a, reason: fine reason here, expires: 2026-11-01}
  - {id: CVE-2026-3, image: web, package: "", reason: fine reason here, expires: 2026-11-01}
  - {id: CVE-2026-4, image: web, package: a, reason: short, expires: 2026-11-01}
  - {id: CVE-2026-5, image: web, package: a, reason: fine reason here, expires: 2026-13-01}
  - {id: CVE-2026-6, image: web, package: a, reason: fine reason here, expires: 2027-03-01}
  - {id: CVE-2026-1, image: web, package: a, reason: fine reason here, expires: 2026-11-01}
  - {id: GHSA-2222-3333-4444, image: web, package: a, reason: fine reason here, expires: 2026-10-01}
`)
	errs := wf.Validate([]string{"web"}, testDay)
	var all []string
	for _, e := range errs {
		all = append(all, e.Error())
	}
	joined := strings.Join(all, "\n")
	for _, want := range []string{"waivers[1]: id", "waivers[2]: image \"db\"", "waivers[3]: package", "waivers[4]: reason",
		"waivers[5]: expires \"2026-13-01\"", "waivers[6]: expires 2027-03-01 is more than 90 days", "waivers[7]: duplicate"} {
		mustContain(t, joined, want)
	}
	if len(errs) != 7 {
		t.Fatalf("%d errors (an expired waiver is not an error):\n%s", len(errs), joined)
	}
}

func TestWaiversCLI(t *testing.T) {
	root := fixtureRepo(t)
	dir := t.TempDir()
	scan := filepath.Join(dir, "scan.json")
	writeFile(t, scan, grypeFixture)
	wf := filepath.Join(root, CatalogDir, "notes/waivers.yaml")
	summary := filepath.Join(dir, "summary.json")
	var out, errb strings.Builder
	err := run([]string{"waivers", "check", "--root", root, "--file", wf, "--image", "notes-web", "--scan", scan, "--summary", summary, "--today", "2026-10-28"}, &out, &errb)
	if err == nil || !strings.Contains(err.Error(), "3 critical finding(s) without a valid waiver") {
		t.Fatalf("err = %v", err)
	}
	var s ScanSummary
	if err := readJSONFile(summary, &s); err != nil || s.Image != "notes-web" || len(s.Unwaived) != 3 {
		t.Fatalf("summary: %v %+v", err, s)
	}
	writeFile(t, scan, `{"matches":[]}`)
	if err := run([]string{"waivers", "check", "--root", root, "--file", wf, "--image", "notes-web", "--scan", scan}, &out, &errb); err != nil {
		t.Fatal(err)
	}
	// Images of another app are not covered by this file.
	if err := run([]string{"waivers", "check", "--root", root, "--file", wf, "--image", "gateway", "--scan", scan}, &out, &errb); err == nil {
		t.Fatal("notes waivers do not cover the gateway image")
	}
	// The runtime waivers file covers the sidecars and the mirrored caddy image.
	rw := filepath.Join(root, RuntimeWaiversFile)
	for _, img := range []string{"sealed-agent", "caddy"} {
		if err := run([]string{"waivers", "check", "--root", root, "--file", rw, "--image", img, "--scan", scan}, &out, &errb); err != nil {
			t.Fatalf("%s: %v", img, err)
		}
	}
	// lint: every file in the catalog parses and validates; legacy lists produce a warning annotation.
	writeFile(t, filepath.Join(root, CatalogDir, "llm-gateway/waivers.yaml"), "[]\n")
	out.Reset()
	if err := run([]string{"waivers", "lint", "--root", root, "--today", "2026-10-28"}, &out, &errb); err != nil {
		t.Fatal(err)
	}
	mustContain(t, out.String(), "::warning file=catalog/apps/llm-gateway/waivers.yaml,title=waivers-format::")
	writeFile(t, filepath.Join(root, CatalogDir, "notes/waivers.yaml"), "version: 1\nwaivers:\n  - {id: CVE-2026-1, image: nope, package: a, reason: fine reason here, expires: 2026-11-01}\n")
	if err := run([]string{"waivers", "lint", "--root", root, "--today", "2026-10-28"}, &out, &errb); err == nil {
		t.Fatal("a waiver for an unknown image fails lint")
	}
	if err := os.Remove(filepath.Join(root, CatalogDir, "notes/waivers.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"waivers", "lint", "--root", root}, &out, &errb); err == nil {
		t.Fatal("every app needs a waivers.yaml")
	}
}

func TestWaiversLintRealCatalog(t *testing.T) {
	var out, errb strings.Builder
	if err := run([]string{"waivers", "lint", "--root", repoRoot(t)}, &out, &errb); err != nil {
		t.Fatal(err)
	}
}
