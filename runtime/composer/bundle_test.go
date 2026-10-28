package composer

import (
	"archive/tar"
	"bytes"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/sealed-dev/sealed/runtime/composer/cjson"
)

func TestBundleTarIsByteIdenticalAcrossRuns(t *testing.T) {
	a := buildFixture(t, "notes")
	// A copy with different mtimes and permissions must give the same bytes.
	dir := copyFixture(t, "notes")
	old := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			_ = os.Chtimes(p, old, old)
			_ = os.Chmod(p, 0o600)
		}
		return nil
	})
	b, err := BuildBundle(BuildInput{AppDir: dir, Registry: testRegistry})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Tar, b.Tar) || a.Hash != b.Hash {
		t.Fatalf("bundle bytes differ: %s vs %s", a.Hash, b.Hash)
	}
	for i := 0; i < 5; i++ {
		c := buildFixture(t, "notes")
		if !bytes.Equal(a.Tar, c.Tar) {
			t.Fatal("bundle bytes differ between runs")
		}
	}
}

func TestBundleTarFormat(t *testing.T) {
	b := buildFixture(t, "notes")
	tr := tar.NewReader(bytes.NewReader(b.Tar))
	var names []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, hdr.Name)
		if hdr.Format != tar.FormatUSTAR {
			t.Errorf("%s: format %v, want USTAR", hdr.Name, hdr.Format)
		}
		if !hdr.ModTime.Equal(time.Unix(0, 0)) || hdr.Uid != 0 || hdr.Gid != 0 || hdr.Uname != "" || hdr.Gname != "" {
			t.Errorf("%s: non-deterministic metadata %+v", hdr.Name, hdr)
		}
		wantMode := int64(0o644)
		if hdr.Typeflag == tar.TypeDir {
			wantMode = 0o755
		}
		if hdr.Mode != wantMode {
			t.Errorf("%s: mode %o", hdr.Name, hdr.Mode)
		}
	}
	want := []string{
		"LICENSES/", "LICENSES/LICENSE-NOTICE", "LICENSES/MIT.txt", "compose.fragment.yaml", "egress.yaml", "manifest.yaml",
		"sbom/", "sbom/notes-web.spdx.json", "sbom/postgres.spdx.json", "scan/", "scan/notes-web.json", "scan/postgres.json",
	}
	if strings.Join(names, " ") != strings.Join(want, " ") {
		t.Fatalf("entries\n got %v\nwant %v", names, want)
	}
	if !sort.StringsAreSorted(names) {
		t.Fatal("entries not sorted")
	}
	if bytes.Contains(b.Files["LICENSES/LICENSE-NOTICE"], []byte("\r")) {
		t.Fatal("CRLF not normalized")
	}
	if !bytes.HasSuffix(b.Tar, make([]byte, 1024)) || len(b.Tar)%512 != 0 {
		t.Fatal("missing end-of-archive blocks")
	}
}

func TestBundleHashes(t *testing.T) {
	b := buildFixture(t, "notes")
	if b.Hash != SHA256(b.Tar) {
		t.Fatal("bundleHash must be sha256(tar)")
	}
	// egressPolicyHash = sha256(CJSON(egress.yaml parsed)).
	wantEgress := `{"customer_additions_allowed":true,"default_allow":["api.example.com:443"],"notes":"api.example.com serves the notes sync API; customers may add mail hosts","version":1}`
	if b.EgressPolicyHash != SHA256([]byte(wantEgress)) {
		t.Fatalf("egressPolicyHash %s", b.EgressPolicyHash)
	}
	// sbomHash = sha256(CJSON({"<image>": "0x<sha256 hex>"})).
	set := map[string]any{}
	for _, img := range []string{"notes-web", "postgres"} {
		raw, _ := os.ReadFile(filepath.Join(fixtureDir("notes"), "sbom", img+".spdx.json"))
		sum := SHA256(raw)
		set[img] = "0x" + hex.EncodeToString(sum[:])
	}
	canon, _ := cjson.Encode(set)
	if b.SBOMHash != SHA256(canon) {
		t.Fatalf("sbomHash %s", b.SBOMHash)
	}
	if b.ReleaseID != ReleaseID(AppID("notes"), "1.0.0-sealed.1", b.Hash) {
		t.Fatal("releaseId")
	}
	info := b.Info()
	if info.Version != "1.0.0-sealed.1" || info.BundleHash != b.Hash.Hex() || info.ReleaseID != b.ReleaseID.Hex() {
		t.Fatalf("info %+v", info)
	}
	gw := buildFixture(t, "llm-gateway")
	if gw.Version() != "2.3.4" {
		t.Fatalf("version defaults to upstream.version, got %q", gw.Version())
	}
}

func TestBundleResolvesImageRefs(t *testing.T) {
	b := buildFixture(t, "notes")
	img, _ := b.Manifest.Image("postgres")
	if img.Ref != "ghcr.io/sealedtempo/postgres@sha256:266d3c257594e195b309ae9d1805e54c788f1d7b375f56bf6c367aac6c917e7b" {
		t.Fatalf("ref %q", img.Ref)
	}
	if !bytes.Contains(b.Files[ManifestFile], []byte("# Fixture app for composer tests")) {
		t.Fatal("manifest comments should survive the ref rewrite")
	}
	other, err := BuildBundle(BuildInput{AppDir: fixtureDir("notes"), Registry: "ghcr.io/other"})
	if err != nil {
		t.Fatal(err)
	}
	if other.Hash == b.Hash {
		t.Fatal("registry is part of the bundle")
	}
	if _, err := BuildBundle(BuildInput{AppDir: fixtureDir("notes"), Registry: "GHCR.io/Bad Name"}); err == nil {
		t.Fatal("invalid registry must fail")
	}
}

func TestLoadBundleRejectsNonCanonical(t *testing.T) {
	b := buildFixture(t, "notes")
	if _, err := LoadBundle(b.Tar); err != nil {
		t.Fatal(err)
	}
	// Any metadata change (here mtime of the first header) is rejected.
	bad := append([]byte(nil), b.Tar...)
	bad[136] = '1'
	if _, err := LoadBundle(bad); err == nil {
		t.Fatal("non-canonical header accepted")
	}
	// Re-tar with archive/tar defaults (different header encoding) is rejected.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, name := range sortedKeys(b.Files) {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(b.Files[name])), ModTime: time.Unix(1, 0)})
		_, _ = tw.Write(b.Files[name])
	}
	_ = tw.Close()
	if _, err := LoadBundle(buf.Bytes()); err == nil {
		t.Fatal("foreign tar accepted")
	}
	// CRLF content is rejected even in canonical tar form.
	files := map[string][]byte{}
	for k, v := range b.Files {
		files[k] = v
	}
	files[EgressFile] = bytes.ReplaceAll(files[EgressFile], []byte("\n"), []byte("\r\n"))
	crlf, _ := WriteTar(files)
	if _, err := LoadBundle(crlf); err == nil || !strings.Contains(err.Error(), "LF") {
		t.Fatalf("CRLF accepted: %v", err)
	}
	// Unexpected files are rejected.
	files = map[string][]byte{}
	for k, v := range b.Files {
		files[k] = v
	}
	files["extra.sh"] = []byte("#!/bin/sh\n")
	extra, _ := WriteTar(files)
	if _, err := LoadBundle(extra); err == nil {
		t.Fatal("unexpected file accepted")
	}
	// Manifests without resolved refs (catalog sources) are not bundles.
	files = map[string][]byte{}
	for k, v := range b.Files {
		files[k] = v
	}
	src, _ := os.ReadFile(filepath.Join(fixtureDir("notes"), ManifestFile))
	files[ManifestFile] = src
	noRefs, _ := WriteTar(files)
	if _, err := LoadBundle(noRefs); err == nil || !strings.Contains(err.Error(), "ref") {
		t.Fatalf("missing refs accepted: %v", err)
	}
}

func TestWriteTarRejectsBadPaths(t *testing.T) {
	for _, p := range []string{"/abs", "../up", "a/../b", "a//b", "dir/", "", "a\\b", "x\x01"} {
		if _, err := WriteTar(map[string][]byte{p: nil}); err == nil {
			t.Errorf("path %q accepted", p)
		}
	}
	if _, err := WriteTar(map[string][]byte{"a": nil, "a/b": nil}); err == nil {
		t.Error("file/dir clash accepted")
	}
	long := strings.Repeat("d", 60) + "/" + strings.Repeat("e", 60) + "/" + strings.Repeat("f", 90)
	out, err := WriteTar(map[string][]byte{"LICENSES/" + long: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	files, err := ReadTar(out)
	if err != nil || len(files["LICENSES/"+long]) != 1 {
		t.Fatalf("long path round trip: %v", err)
	}
	if _, err := WriteTar(map[string][]byte{"LICENSES/" + strings.Repeat("x", 101): nil}); err == nil {
		t.Error("a path component longer than ustar allows must fail")
	}
}

func TestBundleRequiresSBOM(t *testing.T) {
	dir := copyFixture(t, "notes")
	_ = os.Remove(filepath.Join(dir, "sbom", "postgres.spdx.json"))
	if _, err := BuildBundle(BuildInput{AppDir: dir, Registry: testRegistry}); err == nil || !strings.Contains(err.Error(), "SBOM") {
		t.Fatalf("missing SBOM accepted: %v", err)
	}
	if _, err := BuildBundle(BuildInput{AppDir: dir, Registry: testRegistry, AllowMissingSBOM: true}); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "sbom", "stranger.spdx.json"), []byte("{}"), 0o644)
	if _, err := BuildBundle(BuildInput{AppDir: dir, Registry: testRegistry, AllowMissingSBOM: true}); err == nil {
		t.Fatal("SBOM for an unknown image accepted")
	}
}

func TestNormalizeText(t *testing.T) {
	if got := string(NormalizeText([]byte("a\r\nb\rc\n"))); got != "a\nb\nc\n" {
		t.Fatalf("got %q", got)
	}
	bin := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0}
	if !bytes.Equal(NormalizeText(bin), bin) {
		t.Fatal("binary content must not change")
	}
}
