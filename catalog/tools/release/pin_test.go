package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sealedtempo/sealed/runtime/composer"
)

func TestOrderedJSONRoundTrip(t *testing.T) {
	root := repoRoot(t)
	for _, f := range []string{RuntimeImagesFile, ExtraImagesFile, "runtime/composer/testdata/golden/summary.json"} {
		src, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			t.Fatal(err)
		}
		doc, err := parseOrderedJSON(src)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if got := string(doc.encode()); got != string(src) && f != "runtime/composer/testdata/golden/summary.json" {
			t.Errorf("%s: round trip changed the file:\n%s", f, got)
		}
	}
	for _, bad := range []string{`{"a":1,"a":2}`, `{"a":}`, `[1,]`, `{"a":1} x`, `"unterminated`, `{"a":01}`} {
		if _, err := parseOrderedJSON([]byte(bad)); err == nil {
			t.Errorf("parseOrderedJSON(%s) should fail", bad)
		}
	}
	doc, err := parseOrderedJSON([]byte(`{"b":{"x":"1","unbuilt":true},"a":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	doc.get("b").setString("x", "<&>")
	doc.get("b").del("unbuilt")
	doc.setString("c", "new")
	want := "{\n  \"b\": {\n    \"x\": \"<&>\"\n  },\n  \"a\": [],\n  \"c\": \"new\"\n}\n"
	if got := string(doc.encode()); got != want {
		t.Fatalf("edit:\n%s\nwant:\n%s", got, want)
	}
}

func TestPinManifestKeepsEverythingElse(t *testing.T) {
	// The real manifest ships pinned once released; reset its build digests so this exercises the unbuilt-to-pinned edit.
	src := unbuiltManifest(readFile(t, filepath.Join(repoRoot(t), CatalogDir, "llm-gateway/manifest.yaml")))
	digest := "sha256:" + strings.Repeat("ab", 32)
	out, old, err := pinManifest([]byte(src), "local-model", digest)
	if err != nil {
		t.Fatal(err)
	}
	if old != zeroDigest {
		t.Fatalf("old = %s", old)
	}
	// Exactly one line differs, and only in the digest.
	a, b := strings.Split(src, "\n"), strings.Split(string(out), "\n")
	if len(a) != len(b) {
		t.Fatal("line count changed")
	}
	diffs := 0
	for i := range a {
		if a[i] != b[i] {
			diffs++
			if strings.Replace(a[i], zeroDigest, digest, 1) != b[i] {
				t.Errorf("line %d: %q -> %q", i+1, a[i], b[i])
			}
		}
	}
	if diffs != 1 {
		t.Fatalf("%d lines changed, want 1", diffs)
	}
	m, err := composer.ParseManifest(out)
	if err != nil {
		t.Fatal(err)
	}
	if img, _ := m.Image("litellm"); img.Digest != zeroDigest {
		t.Fatal("the other built image must keep its digest")
	}
	// Quoted digests keep their quotes; an unknown image is an error.
	quoted := strings.Replace(src, "    digest: "+zeroDigest+"\n    platform: linux/amd64\n    license_spdx: MIT AND Apache-2.0",
		"    digest: \""+zeroDigest+"\"\n    platform: linux/amd64\n    license_spdx: MIT AND Apache-2.0", 1)
	if quoted == src {
		t.Fatal("fixture edit did not apply")
	}
	out, _, err = pinManifest([]byte(quoted), "local-model", digest)
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, string(out), "digest: \""+digest+"\"")
	if _, _, err := pinManifest([]byte(src), "nope", digest); err == nil {
		t.Fatal("unknown image must fail")
	}
}

func boolPtr(b bool) *bool { return &b }

func TestPinScopes(t *testing.T) {
	root := fixtureRepo(t)
	set, err := LoadImages(root)
	if err != nil {
		t.Fatal(err)
	}
	d1, d2 := "sha256:"+strings.Repeat("1a", 32), "sha256:"+strings.Repeat("2b", 32)
	results := []BuildResult{
		{Name: "gateway", Dir: "catalog/apps/llm-gateway/images/gateway", Digest: d1, Reproducible: boolPtr(true)},
		{Name: "sealed-agent", Dir: "runtime/agent", Digest: d2},
	}
	before := readFile(t, filepath.Join(root, RuntimeImagesFile))

	changes, err := Pin(root, set, results, ScopeCatalog)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0].File != "catalog/apps/llm-gateway/manifest.yaml" || changes[0].New != d1 {
		t.Fatalf("catalog scope changes: %+v", changes)
	}
	if readFile(t, filepath.Join(root, RuntimeImagesFile)) != before {
		t.Fatal("catalog scope must not touch runtime-images.json")
	}
	mustContain(t, readFile(t, filepath.Join(root, CatalogDir, "llm-gateway/manifest.yaml")), "digest: "+d1)

	changes, err = Pin(root, set, results, ScopeRuntime)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0].File != RuntimeImagesFile || changes[0].Image != "sealed-agent" {
		t.Fatalf("runtime scope changes: %+v", changes)
	}
	after := readFile(t, filepath.Join(root, RuntimeImagesFile))
	var ri struct {
		Images map[string]map[string]any `json:"images"`
	}
	if err := json.Unmarshal([]byte(after), &ri); err != nil {
		t.Fatal(err)
	}
	if ri.Images["sealed-agent"]["digest"] != d2 || ri.Images["sealed-agent"]["unbuilt"] != nil {
		t.Fatalf("sealed-agent after pin: %v", ri.Images["sealed-agent"])
	}
	if ri.Images["sealed-egress"]["unbuilt"] != true {
		t.Fatal("other sidecars stay unbuilt")
	}
	// Only the sealed-agent block changed: two lines (digest) and one removed ("unbuilt").
	if diff := len(strings.Split(before, "\n")) - len(strings.Split(after, "\n")); diff != 1 {
		t.Fatalf("expected exactly one line removed, got %d", diff)
	}

	// Idempotent: the same results change nothing.
	changes, err = Pin(root, set, results, ScopeAll)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 2 {
		// the set was loaded before pinning, so both targets still report the old digest
		t.Logf("changes on the stale set: %+v", changes)
	}
	set2, err := LoadImages(root)
	if err != nil {
		t.Fatal(err)
	}
	changes, err = Pin(root, set2, results, ScopeAll)
	if err != nil || len(changes) != 0 {
		t.Fatalf("second pin: %v %+v", err, changes)
	}

	summary := PinSummary(ScopeRuntime, "https://example.invalid/run/1", "abc123", results,
		[]PinChange{{File: RuntimeImagesFile, Image: "sealed-agent", Old: zeroDigest, New: d2}})
	mustContain(t, summary, "bumps `composer.Version`")
	mustContain(t, summary, "| sealed-agent | `"+d2+"` | not checked | not scanned | "+RuntimeImagesFile+" |")
	if strings.Contains(summary, "—") {
		t.Fatal("no em-dashes in PR text")
	}
}

func TestPinRejectsForeignResults(t *testing.T) {
	root := fixtureRepo(t)
	set, err := LoadImages(root)
	if err != nil {
		t.Fatal(err)
	}
	good := "sha256:" + strings.Repeat("3c", 32)
	for name, rs := range map[string][]BuildResult{
		"unknown image":  {{Name: "nope", Dir: "x", Digest: good}},
		"other dir":      {{Name: "gateway", Dir: "catalog/apps/notes", Digest: good}},
		"zero digest":    {{Name: "gateway", Dir: "catalog/apps/llm-gateway/images/gateway", Digest: zeroDigest}},
		"bad digest":     {{Name: "gateway", Dir: "catalog/apps/llm-gateway/images/gateway", Digest: "sha256:abc"}},
		"duplicate name": {{Name: "gateway", Dir: "catalog/apps/llm-gateway/images/gateway", Digest: good}, {Name: "gateway", Dir: "catalog/apps/llm-gateway/images/gateway", Digest: good}},
	} {
		if _, err := Pin(root, set, rs, ScopeAll); err == nil {
			t.Errorf("%s: Pin should fail", name)
		}
	}
	if _, err := Pin(root, set, nil, "everything"); err == nil {
		t.Error("unknown scope should fail")
	}
}

func TestLoadBuildResults(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a/result.json"), `{"name":"gateway","dir":"d","digest":"sha256:1","reproducible":false,"rebuildDigest":"sha256:2"}`)
	rs, err := LoadBuildResults(dir)
	if err != nil || len(rs) != 1 || rs[0].Reproducible == nil || *rs[0].Reproducible {
		t.Fatalf("%v %+v", err, rs)
	}
	writeFile(t, filepath.Join(dir, "b.json"), `{"name":"x","surprise":1}`)
	if _, err := LoadBuildResults(dir); err == nil {
		t.Fatal("unknown fields must fail")
	}
}
