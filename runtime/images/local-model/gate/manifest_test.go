package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The pins of runtime/images/local-model/Dockerfile.
var pins = manifestPins{
	Config:   "b72accf9724e93698c57cbd3b1af2d3341b3d05ec2089d86d273d97964853cd2",
	Model:    "85e4a5b7b8ef0e48af0e8658f5aaab9c2324c76c1641493f4d1e25fce54b18b9",
	Template: "eade0a07cac7712787bbce23d12f9306adb4781d873d1df6e16f7840fa37afec",
	License:  "d18a5cc71b84bc4af394a31116bd3932b42241de70c77d2b76d69a314ec8aa12",
	Params:   "0914c7781e001948488d937994217538375b4fd8c1466c5e7a625221abd3ea7a",
}

func goodManifest() map[string]any {
	layer := func(media, digest string, size int) map[string]any {
		return map[string]any{"mediaType": media, "digest": "sha256:" + digest, "size": size}
	}
	return map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.docker.distribution.manifest.v2+json",
		"config":        map[string]any{"mediaType": "application/vnd.docker.container.image.v1+json", "digest": "sha256:" + pins.Config, "size": 487},
		"layers": []any{
			layer(mediaModel, pins.Model, 2497280480),
			layer(mediaTemplate, pins.Template, 1600),
			layer(mediaLicense, pins.License, 11338),
			layer(mediaParams, pins.Params, 119),
		},
	}
}

func writeManifest(t *testing.T, m map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "4b-instruct-2507-q4_K_M")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVerifyManifestAcceptsThePinnedLayout(t *testing.T) {
	path := writeManifest(t, goodManifest())
	raw, _ := os.ReadFile(path)
	sum := sha256.Sum256(raw)
	want := hex.EncodeToString(sum[:])
	got, err := verifyManifest(path, pins)
	if err != nil || got != want {
		t.Fatalf("got %q, %v", got, err)
	}
	withFull := pins
	withFull.ManifestSHA256 = want
	if _, err := verifyManifest(path, withFull); err != nil {
		t.Fatal(err)
	}
	withFull.ManifestSHA256 = strings.Repeat("0", 64)
	if _, err := verifyManifest(path, withFull); err == nil {
		t.Fatal("wrong full manifest digest accepted")
	}
}

func TestVerifyManifestRejectsSwappedRolesAndExtras(t *testing.T) {
	cases := map[string]func(m map[string]any){
		"template and params swapped": func(m map[string]any) {
			layers := m["layers"].([]any)
			a, b := layers[1].(map[string]any), layers[3].(map[string]any)
			a["digest"], b["digest"] = b["digest"], a["digest"]
		},
		"license used as template": func(m map[string]any) {
			m["layers"].([]any)[1].(map[string]any)["digest"] = "sha256:" + pins.License
		},
		"extra adapter layer": func(m map[string]any) {
			m["layers"] = append(m["layers"].([]any), map[string]any{"mediaType": "application/vnd.ollama.image.adapter", "digest": "sha256:" + pins.Model})
		},
		"system prompt layer instead of params": func(m map[string]any) {
			m["layers"].([]any)[3].(map[string]any)["mediaType"] = "application/vnd.ollama.image.system"
		},
		"duplicate model layer": func(m map[string]any) {
			layers := m["layers"].([]any)
			layers[3] = layers[0]
		},
		"wrong config":     func(m map[string]any) { m["config"].(map[string]any)["digest"] = "sha256:" + pins.Model },
		"schema version 1": func(m map[string]any) { m["schemaVersion"] = 1 },
		"missing layer":    func(m map[string]any) { m["layers"] = m["layers"].([]any)[:3] },
	}
	for name, mutate := range cases {
		m := goodManifest()
		mutate(m)
		if _, err := verifyManifest(writeManifest(t, m), pins); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestVerifyManifestRejectsBadInput(t *testing.T) {
	bad := pins
	bad.Model = "85e4a5b7"
	if _, err := verifyManifest(writeManifest(t, goodManifest()), bad); err == nil {
		t.Fatal("short pin accepted")
	}
	path := filepath.Join(t.TempDir(), "m")
	_ = os.WriteFile(path, []byte("not json"), 0o644)
	if _, err := verifyManifest(path, pins); err == nil {
		t.Fatal("non-JSON accepted")
	}
	if _, err := verifyManifest(filepath.Join(t.TempDir(), "missing"), pins); err == nil {
		t.Fatal("missing file accepted")
	}
}

func TestVerifyManifestCommand(t *testing.T) {
	path := writeManifest(t, goodManifest())
	args := []string{"verify-manifest", "-manifest", path, "-config", pins.Config, "-model", pins.Model,
		"-template", pins.Template, "-license", pins.License, "-params", pins.Params}
	var out, errOut bytes.Buffer
	if code := run(args, nil, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if !strings.HasPrefix(out.String(), "manifest sha256:") {
		t.Fatalf("stdout %q", out.String())
	}
	args[len(args)-1] = pins.Template
	if code := run(args, nil, &out, &errOut); code != 1 {
		t.Fatalf("mismatch exit %d", code)
	}
	if code := run([]string{"verify-manifest"}, nil, &out, &errOut); code != 2 {
		t.Fatalf("usage exit %d", code)
	}
}
