package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sealed-dev/sealed/runtime/composer"
)

func realDefaults(t *testing.T) Defaults {
	t.Helper()
	d, err := LoadDefaults(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDefaults(t *testing.T) {
	d := realDefaults(t)
	if d.ChainID != 4217 || d.Registry != "ghcr.io/sealedtempo" || d.RepoSlug() != "sealedtempo/sealed" ||
		d.RepoURL() != "https://github.com/sealedtempo/sealed" || d.FeeToken != "0x20c000000000000000000000b9537d11c60e8b50" {
		t.Fatalf("defaults: %+v", d)
	}
}

// The asset URL rule (D-046) must match what the CLI and key broker fetch.
func TestAssetsRule(t *testing.T) {
	d := realDefaults(t)
	a, err := Assets(d, "scraper", "0.1.0", []string{"scraper-runner-playwright", "postgres"})
	if err != nil {
		t.Fatal(err)
	}
	if got := a.URL(a.Bundle); got != "https://github.com/sealedtempo/sealed/releases/download/scraper-v0.1.0/scraper-0.1.0.bundle.tar" {
		t.Fatalf("bundle URL %s", got)
	}
	for asset, want := range map[string]string{
		a.Signature: "scraper-0.1.0.bundle.tar.sig", a.Certificate: "scraper-0.1.0.bundle.tar.crt",
		a.Provenance: "scraper-0.1.0.bundle.tar.intoto.jsonl", a.SigstoreBundle: "scraper-0.1.0.bundle.tar.sigstore.json",
		a.SBOM["postgres"]: "sbom.postgres.spdx.json", a.Scan["postgres"]: "scan.postgres.json",
	} {
		if asset != want {
			t.Errorf("asset %s, want %s", asset, want)
		}
	}
	if len(a.All()) != 10 {
		t.Fatalf("all assets: %v", a.All())
	}
	for _, bad := range []string{"v1.2.3", "V2", "1.0.0+build", "", "-1", strings.Repeat("1", 65), "1/2"} {
		if _, err := Assets(d, "x", bad, nil); err == nil {
			t.Errorf("version %q must be rejected", bad)
		}
	}
	for _, ok := range []string{"1.2.3", "0.1.0-sealed.1", "2026.10.28_1", "valkey9"} {
		if err := CheckReleaseVersion(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
}

func TestPlan(t *testing.T) {
	root := fixtureRepo(t)
	var out, errb strings.Builder
	if err := run([]string{"plan", "--root", root, "--apps", "all"}, &out, &errb); err != nil {
		t.Fatal(err)
	}
	var plan []PlannedRelease
	if err := json.Unmarshal([]byte(out.String()), &plan); err != nil {
		t.Fatal(err)
	}
	if len(plan) != 2 || plan[0].App != "llm-gateway" || plan[1].App != "notes" {
		t.Fatalf("plan: %+v", plan)
	}
	notes := plan[1]
	if notes.Tag != "notes-v1.0.0-sealed.1" || notes.Problem != "" || notes.AppID != composer.AppID("notes").Hex() ||
		notes.Assets.Bundle != "notes-1.0.0-sealed.1.bundle.tar" {
		t.Fatalf("notes: %+v", notes)
	}
	if plan[0].Version != "2.3.4" || plan[0].Problem != "" {
		t.Fatalf("gateway: %+v", plan[0])
	}
	// Unbuilt images and bad versions are problems; --strict turns them into a failure.
	p := filepath.Join(root, CatalogDir, "notes/manifest.yaml")
	writeFile(t, p, strings.Replace(readFile(t, p), "release_version: 1.0.0-sealed.1", "release_version: v1.0.0", 1))
	changed := filepath.Join(t.TempDir(), "changed.txt")
	writeFile(t, changed, "catalog/apps/notes/manifest.yaml\nREADME.md\n")
	out.Reset()
	errb.Reset()
	if err := run([]string{"plan", "--root", root, "--changed", changed}, &out, &errb); err != nil {
		t.Fatal(err)
	}
	mustContain(t, errb.String(), "::warning file=catalog/apps/notes/manifest.yaml,title=release-plan::release version \"v1.0.0\"")
	if err := run([]string{"plan", "--root", root, "--changed", changed, "--strict"}, &out, &errb); err == nil {
		t.Fatal("--strict must fail on a problem")
	}
	if err := run([]string{"plan", "--root", root, "--apps", "nope"}, &out, &errb); err == nil {
		t.Fatal("unknown app")
	}
}

// fixtureBundle builds the notes fixture's bundle with its committed SBOMs and scans.
func fixtureBundle(t *testing.T, root string) (string, *BundleInfo) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "notes-1.0.0-sealed.1.bundle.tar")
	app := filepath.Join(root, CatalogDir, "notes")
	info, err := BuildBundleFile(app, filepath.Join(app, "sbom"), filepath.Join(app, "scan"), "ghcr.io/sealedtempo", out)
	if err != nil {
		t.Fatal(err)
	}
	return out, info
}

func TestBundleAndInfo(t *testing.T) {
	root := fixtureRepo(t)
	path, info := fixtureBundle(t, root)
	again, err := BundleFileInfo(path)
	if err != nil {
		t.Fatal(err)
	}
	if again.BundleHash != info.BundleHash || info.Slug != "notes" || info.Version != "1.0.0-sealed.1" {
		t.Fatalf("info %+v vs %+v", info, again)
	}
	raw, _ := os.ReadFile(path)
	if sum := sha256.Sum256(raw); "0x"+hexs(sum[:]) != info.BundleHash {
		t.Fatal("bundleHash is sha256 of the tar")
	}
	if want := composer.ReleaseID(composer.AppID("notes"), "1.0.0-sealed.1", composer.SHA256(raw)).Hex(); info.ReleaseID != want {
		t.Fatalf("releaseId %s, want %s", info.ReleaseID, want)
	}
	// The CLI subcommand gives the same bytes (deterministic) and refuses a missing scan.
	out2 := filepath.Join(t.TempDir(), "b.tar")
	var so, se strings.Builder
	app := filepath.Join(root, CatalogDir, "notes")
	if err := run([]string{"bundle", "--root", root, "--app", "notes", "--sbom-dir", filepath.Join(app, "sbom"), "--scan-dir", filepath.Join(app, "scan"), "--out", out2}, &so, &se); err != nil {
		t.Fatal(err)
	}
	if readFile(t, out2) != string(raw) {
		t.Fatal("bundle is not reproducible")
	}
	noScan := t.TempDir()
	if err := run([]string{"bundle", "--root", root, "--app", "notes", "--sbom-dir", filepath.Join(app, "sbom"), "--scan-dir", noScan}, &so, &se); err == nil ||
		!strings.Contains(err.Error(), "no scan report") {
		t.Fatalf("missing scan: %v", err)
	}
	// The gateway fixture still has a placeholder digest? It has a fake non-zero one; an unbuilt image fails.
	p := filepath.Join(app, "manifest.yaml")
	writeFile(t, p, strings.Replace(readFile(t, p), "sha256:1111111111111111111111111111111111111111111111111111111111111111", zeroDigest, 1))
	if err := run([]string{"bundle", "--root", root, "--app", "notes", "--sbom-dir", filepath.Join(app, "sbom"), "--scan-dir", filepath.Join(app, "scan")}, &so, &se); err == nil {
		t.Fatal("an unbuilt image must not be bundled for release")
	}
}

func hexs(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}

// fakeSigstoreBundle writes a Sigstore v0.3 bundle (the layout cosign 3 writes) for blob.
func fakeSigstoreBundle(t *testing.T, blob []byte, logIndex string) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sigstore-intermediate"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(10 * time.Minute)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(blob)
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	doc := map[string]any{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": map[string]any{
			"certificate": map[string]string{"rawBytes": base64.StdEncoding.EncodeToString(der)},
			"tlogEntries": []any{map[string]any{"logIndex": logIndex, "integratedTime": "1761667200",
				"logId": map[string]string{"keyId": "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="}}},
		},
		"messageSignature": map[string]any{
			"messageDigest": map[string]string{"algorithm": "SHA2_256", "digest": base64.StdEncoding.EncodeToString(sum[:])},
			"signature":     base64.StdEncoding.EncodeToString(sig),
		},
	}
	raw, _ := json.Marshal(doc)
	return raw, der
}

func TestSigstoreBundle(t *testing.T) {
	blob := []byte("bundle bytes")
	raw, der := fakeSigstoreBundle(t, blob, "123456789")
	parts, err := ParseSigstoreBundle(raw, sha256.Sum256(blob))
	if err != nil {
		t.Fatal(err)
	}
	if parts.Rekor.LogIndex != 123456789 || parts.Rekor.URL != "https://search.sigstore.dev/?logIndex=123456789" || parts.Rekor.IntegratedTime != 1761667200 {
		t.Fatalf("rekor %+v", parts.Rekor)
	}
	blk, _ := pem.Decode(parts.CertificatePEM)
	if blk == nil || blk.Type != "CERTIFICATE" || string(blk.Bytes) != string(der) {
		t.Fatal("certificate PEM")
	}
	if _, err := ParseSigstoreBundle(raw, sha256.Sum256([]byte("other"))); err == nil {
		t.Fatal("a bundle for another blob must be rejected")
	}
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	doc["verificationMaterial"].(map[string]any)["tlogEntries"] = []any{}
	noLog, _ := json.Marshal(doc)
	if _, err := ParseSigstoreBundle(noLog, sha256.Sum256(blob)); err == nil {
		t.Fatal("a signature without a Rekor entry must be rejected")
	}
	// CLI writes .sig and .crt.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "b.tar"), string(blob))
	writeFile(t, filepath.Join(dir, "b.sigstore.json"), string(raw))
	var so, se strings.Builder
	if err := run([]string{"sigstore", "--bundle", filepath.Join(dir, "b.sigstore.json"), "--blob", filepath.Join(dir, "b.tar"),
		"--sig", filepath.Join(dir, "b.sig"), "--crt", filepath.Join(dir, "b.crt")}, &so, &se); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(readFile(t, filepath.Join(dir, "b.sig"))) != parts.SignatureB64 {
		t.Fatal(".sig content")
	}
	mustContain(t, readFile(t, filepath.Join(dir, "b.crt")), "-----BEGIN CERTIFICATE-----")
}

func TestReleaseDocAndNotes(t *testing.T) {
	root := fixtureRepo(t)
	d, err := LoadDefaults(root)
	if err != nil {
		t.Fatal(err)
	}
	bundle, info := fixtureBundle(t, root)
	scans := t.TempDir()
	empty, _ := ParseGrype([]byte(`{"matches":[]}`))
	rep, _ := ParseGrype([]byte(grypeFixture))
	wf := waiverFile(t, "version: 1\nwaivers:\n  - {id: CVE-2026-2000, image: notes-web, package: lodash, reason: the vulnerable code is never reached, expires: 2026-11-30}\n")
	if err := writeJSONFile(filepath.Join(scans, "notes-web.summary.json"), Evaluate(rep, "notes-web", wf, testDay)); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONFile(filepath.Join(scans, "postgres.summary.json"), Evaluate(empty, "postgres", nil, testDay)); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(bundle)
	sb, _ := fakeSigstoreBundle(t, raw, "42")
	sbPath := filepath.Join(t.TempDir(), "sb.json")
	writeFile(t, sbPath, string(sb))
	in := ReleaseInputs{Bundle: bundle, ScanDir: scans, SigstoreBundle: sbPath, Commit: strings.Repeat("c", 40), RunURL: "https://github.com/sealedtempo/sealed/actions/runs/1"}
	doc, err := BuildReleaseDoc(d, in)
	if err != nil {
		t.Fatal(err)
	}
	if doc.BundleHash != info.BundleHash || doc.ReleaseID != info.ReleaseID || doc.Tag != "notes-v1.0.0-sealed.1" || doc.Rekor.LogIndex != 42 ||
		doc.SignerIdentity != "https://github.com/sealedtempo/sealed/.github/workflows/release.yml@refs/heads/main" || len(doc.Images) != 2 ||
		doc.Images[0].Ref != "ghcr.io/sealedtempo/notes-web@sha256:"+strings.Repeat("1", 64) {
		t.Fatalf("doc: %+v", doc)
	}
	notes := doc.Notes(d)
	for _, want := range []string{
		"Pending: the `AppRegistry.publishRelease` transaction has not been sent yet",
		"| bundleHash | `" + info.BundleHash + "`",
		"| notes-web | `ghcr.io/sealedtempo/notes-web@sha256:" + strings.Repeat("1", 64) + "` | MIT | 3 | 1 | 0 | 0 | 1 |",
		"notes-web: critical GHSA-2222-3333-4444 in lodash 4.17.0, waived until 2026-11-30.",
		"Rekor transparency log entry 42: https://search.sigstore.dev/?logIndex=42",
		"cosign verify-blob --bundle notes-1.0.0-sealed.1.bundle.tar.sigstore.json",
		"--certificate-oidc-issuer https://token.actions.githubusercontent.com",
		"slsa-verifier verify-artifact notes-1.0.0-sealed.1.bundle.tar --provenance-path notes-1.0.0-sealed.1.bundle.tar.intoto.jsonl --source-uri github.com/sealedtempo/sealed",
		"cp sbom.postgres.spdx.json sbom/postgres.spdx.json && cp scan.postgres.json scan/postgres.json",
		"gh release download notes-v1.0.0-sealed.1 --repo sealedtempo/sealed",
	} {
		mustContain(t, notes, want)
	}
	if strings.ContainsAny(notes, "—–") {
		t.Fatal("no em-dashes or en-dashes in release notes")
	}

	// With the onchain record the notes carry the tx hash and the explorer link.
	onchain := filepath.Join(t.TempDir(), "onchain.json")
	tx := "0x" + strings.Repeat("ab", 32)
	if err := writeJSONFile(onchain, OnchainRecord{ChainID: 4217, AppRegistry: "0x88c91cacb74ccec3b8a1823977eec42ae3b93b43", TxHash: tx,
		BlockNumber: 46400000, ReleaseID: info.ReleaseID}); err != nil {
		t.Fatal(err)
	}
	in.Onchain = onchain
	doc, err = BuildReleaseDoc(d, in)
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, doc.Notes(d), "transaction [`"+tx+"`](https://explore.tempo.xyz/tx/"+tx+"), block 46400000")

	// A record for another release is refused.
	if err := writeJSONFile(onchain, OnchainRecord{TxHash: tx, ReleaseID: "0x" + strings.Repeat("0", 64)}); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildReleaseDoc(d, in); err == nil {
		t.Fatal("onchain record of another release")
	}

	// CLI round trip: release-doc then notes.
	in.Onchain = ""
	rj := filepath.Join(t.TempDir(), "release.json")
	var so, se strings.Builder
	if err := run([]string{"release-doc", "--root", root, "--bundle", bundle, "--scans", scans, "--sigstore", sbPath, "--commit", in.Commit, "--out", rj}, &so, &se); err != nil {
		t.Fatal(err)
	}
	so.Reset()
	if err := run([]string{"notes", "--root", root, "--release", rj}, &so, &se); err != nil {
		t.Fatal(err)
	}
	mustContain(t, so.String(), "## Verify")
}

func TestTxSummary(t *testing.T) {
	d := realDefaults(t)
	receipt := `{"status":"0x1","transactionHash":"0x` + strings.Repeat("Ab", 32) + `","blockNumber":"0x2c2ac4d","from":"0x690b69aEb657D498090352df89d71F2E21F9d0E1",
	  "to":"0x88C91CAcB74cCeC3b8A1823977EEC42aE3b93b43","gasUsed":"0x29a6c","effectiveGasPrice":"0x4a817c800","type":"0x76"}`
	s, err := SummarizeTx(d, []byte(receipt), 4217, "0x88C91CAcB74cCeC3b8A1823977EEC42aE3b93b43", "0x01", "OPS", "AppRegistry", "publishRelease scraper 0.1.0", 1761667200)
	if err != nil {
		t.Fatal(err)
	}
	// 170604 gas x 20e9 attodollars = 3.41208e15 attodollars = 3412.08 base units -> ceil 3413 (0.003413 USD).
	if s.Record.FeeUnits != "3413" || s.Record.FeeUSD != "0.003413" || s.Record.BlockNumber != 46312525 ||
		s.Record.Explorer != "https://explore.tempo.xyz/tx/0x"+strings.Repeat("ab", 32) {
		t.Fatalf("record %+v", s.Record)
	}
	mustContain(t, s.Ledger, "| 2025-10-28 16:00:00 | OPS 0x690b69aEb657D498090352df89d71F2E21F9d0E1 | AppRegistry 0x88C91CAcB74cCeC3b8A1823977EEC42aE3b93b43 | publishRelease scraper 0.1.0 | [0xabababab…ababab]")
	if _, err := SummarizeTx(d, []byte(strings.Replace(receipt, `"0x1"`, `"0x0"`, 1)), 4217, "", "", "OPS", "AppRegistry", "", 0); err == nil {
		t.Fatal("a reverted receipt must fail")
	}
	if _, err := SummarizeTx(d, []byte(`{"status":"0x1","transactionHash":"0x12"}`), 1, "", "", "", "", "", 0); err == nil {
		t.Fatal("bad hash")
	}
}

func TestKeystoreDecryptsWithCast(t *testing.T) {
	const key = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" // anvil dev key 1 (public)
	t.Setenv("RELEASE_TEST_KEY", key)
	dir := filepath.Join(t.TempDir(), "ks")
	addr, err := WriteKeystore("RELEASE_TEST_KEY", dir)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "0x70997970c51812dc3a010c7d01b50e0d17dc79c8" {
		t.Fatalf("address %s", addr)
	}
	for _, f := range []string{"keystore.json", "password"} {
		st, err := os.Stat(filepath.Join(dir, f))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode: %v %v", f, err, st)
		}
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", st.Mode())
	}
	if strings.Contains(readFile(t, filepath.Join(dir, "keystore.json")), strings.TrimPrefix(key, "0x")) {
		t.Fatal("the keystore must not contain the raw key")
	}
	t.Setenv("RELEASE_TEST_EMPTY", "")
	if _, err := WriteKeystore("RELEASE_TEST_EMPTY", t.TempDir()); err == nil {
		t.Fatal("empty key")
	}
	t.Setenv("RELEASE_TEST_BAD", "0x1234")
	if _, err := WriteKeystore("RELEASE_TEST_BAD", t.TempDir()); err == nil || strings.Contains(err.Error(), "1234") {
		t.Fatalf("bad key must fail without echoing it: %v", err)
	}
	cast, err := exec.LookPath("cast")
	if err != nil {
		t.Skip("cast not installed; keystore decryption by Foundry not checked")
	}
	out, err := exec.Command(cast, "wallet", "address", "--keystore", filepath.Join(dir, "keystore.json"), "--password-file", filepath.Join(dir, "password")).CombinedOutput()
	if err != nil {
		t.Fatalf("cast wallet address: %v: %s", err, out)
	}
	if !strings.EqualFold(strings.TrimSpace(string(out)), addr) {
		t.Fatalf("cast decrypted %s, want %s", out, addr)
	}
}

func TestRegisterCatalogJSON(t *testing.T) {
	d := realDefaults(t)
	apps, err := LoadApps(repoRoot(t), false)
	if err != nil {
		t.Fatal(err)
	}
	cat, err := RegisterCatalog(d, apps, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(cat.Apps) != 6 || len(cat.Images) != 0 {
		t.Fatalf("catalog: %+v", cat)
	}
	for _, a := range cat.Apps {
		if a.Maintainer != "" || a.MaintainerShareBps != 2000 || a.MetadataURI != "https://github.com/sealedtempo/sealed/tree/main/catalog/apps/"+a.Slug {
			t.Errorf("app %+v", a)
		}
	}
	root := fixtureRepo(t)
	fapps, _ := LoadApps(root, false)
	img := filepath.Join(t.TempDir(), "images.json")
	writeFile(t, img, `[{"name":"sealed-os","version":"1"}]`)
	cat, err = RegisterCatalog(d, fapps, []string{"notes"}, img)
	if err != nil {
		t.Fatal(err)
	}
	if len(cat.Apps) != 1 || cat.Apps[0].Maintainer != "0x00000000000000000000000000000000000000a1" || len(cat.Images) != 1 {
		t.Fatalf("fixture catalog: %+v", cat)
	}
	if _, err := RegisterCatalog(d, fapps, []string{"missing"}, ""); err == nil {
		t.Fatal("unknown app")
	}
}

func TestLintGate(t *testing.T) {
	findings := []LintFinding{
		{Severity: "error", App: "scraper", File: "manifest.yaml", Field: "images[0].digest", Code: "unbuilt-image", Message: "zero"},
		{Severity: "error", App: "scraper", File: "sbom/scraper-runner-playwright.spdx.json", Code: "sbom-missing", Message: "no SBOM"},
		{Severity: "error", App: "scraper", File: "sbom/postgres.spdx.json", Code: "sbom-missing", Message: "no SBOM"},
		{Severity: "error", App: "crm", File: "manifest.yaml", Field: "license_exclusions", Code: "license-exclusions", Message: "open core\n100%"},
		{Severity: "warning", App: "crm", Code: "license-election", Message: "elected"},
	}
	unbuilt := map[string][]string{"scraper": {"scraper-runner-playwright"}}
	g, err := LintGate(findings, GateModePR, unbuilt)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Blocking) != 2 || len(g.Deferred) != 2 || len(g.Warnings) != 1 {
		t.Fatalf("pr gate: %+v", g)
	}
	var b strings.Builder
	g.Annotate(&b)
	mustContain(t, b.String(), "::error file=catalog/apps/crm/manifest.yaml,title=license-exclusions::license_exclusions: open core%0A100%25")
	mustContain(t, b.String(), "::notice file=catalog/apps/scraper/manifest.yaml,title=unbuilt-image::")
	g, _ = LintGate(findings, GateModeRelease, unbuilt)
	if len(g.Blocking) != 4 || len(g.Deferred) != 0 {
		t.Fatalf("release gate defers nothing: %+v", g)
	}
	if _, err := LintGate(nil, "lenient", nil); err == nil {
		t.Fatal("unknown mode")
	}
}

// End to end with the real composer lint output.
func TestLintGateWithComposerLint(t *testing.T) {
	root := repoRoot(t)
	cmd := exec.Command("go", "run", "./runtime/composer/cmd/sealed-compose", "lint", "--catalog", "catalog/apps", "--json")
	cmd.Dir = root
	out, err := cmd.Output()
	if len(out) == 0 {
		t.Fatalf("sealed-compose lint produced no output: %v", err)
	}
	f := filepath.Join(t.TempDir(), "lint.json")
	writeFile(t, f, string(out))
	var so, se strings.Builder
	err = run([]string{"lint-gate", "--root", root, "--findings", f, "--mode", GateModePR}, &so, &se)
	// The PR gate defers unbuilt images; whatever else the composer reports blocks.
	list, _ := ParseLintFindings(out)
	g, _ := LintGate(list, GateModePR, unbuiltOf(t, root))
	if (err != nil) != (len(g.Blocking) > 0) {
		t.Fatalf("lint-gate exit %v with %d blocking findings", err, len(g.Blocking))
	}
	for _, b := range g.Blocking {
		if b.Code == "unbuilt-image" {
			t.Fatal("unbuilt images never block a PR")
		}
	}
	if err := run([]string{"lint-gate", "--root", root, "--findings", f, "--mode", GateModeRelease}, &so, &se); err == nil {
		t.Fatal("the release gate fails while images are unbuilt")
	}
}

func unbuiltOf(t *testing.T, root string) map[string][]string {
	apps, err := LoadApps(root, false)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, a := range apps {
		for _, img := range a.Manifest.Images {
			if img.Unbuilt() {
				out[a.ID] = append(out[a.ID], img.Name)
			}
		}
	}
	return out
}

func TestComposeCheck(t *testing.T) {
	root := repoRoot(t)
	apps, err := LoadApps(root, false)
	if err != nil {
		t.Fatal(err)
	}
	stacks := DefaultStacks(apps)
	if last := stacks[len(stacks)-1]; last.Name != "customer-stack" || contains(last.Apps, relayApp) || len(last.Apps) != 5 {
		t.Fatalf("customer stack: %+v", last)
	}
	_, docker := exec.LookPath("docker")
	res, err := ComposeCheck(root, apps, stacks, t.TempDir(), docker == nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range res {
		if o.Error != "" {
			t.Errorf("%s: %s", o.Name, o.Error)
		}
		if o.StackHash == "" || !fileExists(o.ComposeFile) {
			t.Errorf("%s: no output", o.Name)
		}
	}
	// A broken fragment is reported per stack.
	froot := fixtureRepo(t)
	frag := filepath.Join(froot, CatalogDir, "notes/compose.fragment.yaml")
	writeFile(t, frag, readFile(t, frag)+"    privileged: true\n")
	fapps, _ := LoadApps(froot, false)
	res, err = ComposeCheck(froot, fapps, []ComposeStack{{Name: "notes", Apps: []string{"notes"}}}, t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Error == "" {
		t.Fatal("a fragment with privileged: true must fail to compose")
	}
}
