package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/sealedtempo/sealed/runtime/composer"
)

// The release workflow's publish job against GitHub Releases it did not create (supply-1) and the onchain
// signatureURI (G13), in the Actions emulator of workflowsim_test.go with the real contracts on a local
// Tempo node.

const (
	mainWorkflowRef = "sealedtempo/sealed/.github/workflows/release.yml@refs/heads/main"
	mainIdentity    = "https://github.com/" + mainWorkflowRef
	notesTag        = "notes-v1.0.0-sealed.1"
	notesBundle     = "notes-1.0.0-sealed.1.bundle.tar"
)

// releaseSimRig holds what the publish tests share: one chain with notes registered, the fakes, and the
// prebuilt tools the fake go serves.
type releaseSimRig struct {
	t     *testing.T
	c     *chainFixture
	f     *fakeEnv
	wf    simWorkflow
	bins  string
	grype string
}

func newReleaseSimRig(t *testing.T) *releaseSimRig {
	t.Helper()
	if testing.Short() {
		t.Skip("short")
	}
	requireJQ(t)
	requireTools(t, "openssl")
	r := &releaseSimRig{t: t, c: deployContracts(t), f: newFakes(t), bins: t.TempDir()}
	for src, dst := range map[string]string{releaseBin(t): "release", sealedComposeBin(t): "sealed-compose"} {
		if err := copyFile(src, filepath.Join(r.bins, dst)); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(filepath.Join(r.bins, dst), 0o755)
	}
	writeFile(t, filepath.Join(r.f.bin, "go"), fakeGo)
	_ = os.Chmod(filepath.Join(r.f.bin, "go"), 0o755)
	if out, err := exec.Command("cast", "send", r.c.registry, "registerApp(bytes32,string,string,string,address,uint16,string)",
		composer.AppID("notes").Hex(), "notes", "Notes", "MIT", castAddr(t, devMaintainer), "2000", "https://example.invalid/notes",
		"--private-key", devOwner, "--rpc-url", r.c.rpc, "--tempo.fee-token", alphaUSD).CombinedOutput(); err != nil {
		t.Fatalf("registerApp: %v %s", err, out)
	}
	if err := yaml.Unmarshal([]byte(readFile(t, filepath.Join(repoRoot(t), ".github/workflows/release.yml"))), &r.wf); err != nil {
		t.Fatal(err)
	}
	r.grype = filepath.Join(t.TempDir(), "grype.json")
	writeFile(t, r.grype, `{"matches":[],"descriptor":{"name":"grype","version":"0.121.0"}}`)
	return r
}

// sim is the release workflow on a checkout of root, run by workflowRef (GITHUB_WORKFLOW_REF: Fulcio puts
// https://github.com/<workflowRef> in the signing certificate).
func (r *releaseSimRig) sim(root, workflowRef string) *simulator {
	return &simulator{t: r.t, wf: r.wf, workspace: root, temp: r.t.TempDir(), artifacts: r.t.TempDir(),
		path: r.f.bin + ":" + os.Getenv("PATH"),
		baseEnv: append(cleanEnv(), "FAKE_STATE="+r.f.state, "FAKE_LOG="+r.f.log, "FAKE_GO_BINS="+r.bins, "FAKE_GRYPE_REPORT="+r.grype,
			"GITHUB_SHA="+strings.Repeat("e", 40), "GITHUB_WORKFLOW_REF="+workflowRef,
			"EXPECT_CHAIN_ID=31337", "DEPLOYMENTS_FILE="+r.c.deployments, "FEE_TOKEN_ADDRESS="+thetaUSD),
		ctx: map[string]any{
			"github": map[string]any{"event_name": "workflow_dispatch", "token": "fake-token", "repository": "sealedtempo/sealed",
				"server_url": "https://github.com", "run_id": "99", "actor": "sealedtempo", "event": map[string]any{"before": ""}},
			"inputs":  map[string]any{"apps": "notes"},
			"secrets": map[string]any{"TEMPO_RPC_URL": r.c.rpc, "OPS_PRIVATE_KEY": devOps},
			"vars":    map[string]any{"ALLOW_MISSING_SEALED_CLI": "1"},
		},
	}
}

// planOne runs the plan job and returns its only matrix entry.
func planOne(t *testing.T, sim *simulator) map[string]any {
	t.Helper()
	plan := sim.runJob("plan", nil)
	var m struct {
		Include []map[string]any `json:"include"`
	}
	if err := json.Unmarshal([]byte(toStr(plan["matrix"])), &m); err != nil || plan["count"] != "1" || len(m.Include) != 1 {
		t.Fatalf("plan: %v %v", plan, err)
	}
	sim.ctx["needs"] = map[string]any{"plan": map[string]any{"outputs": plan}}
	return m.Include[0]
}

// buildRelease runs build, subjects and the emulated provenance for entry and returns the bundle's sha256.
func buildRelease(t *testing.T, sim *simulator, entry map[string]any) string {
	t.Helper()
	sim.runJob("build", entry)
	subjects := sim.runJob("subjects", nil)
	writeFile(t, filepath.Join(sim.artifacts, "bundles.intoto.jsonl", "bundles.intoto.jsonl"), `{"payloadType":"application/vnd.in-toto+json","subjects":"`+toStr(subjects["hashes"])+`"}`)
	needs := sim.ctx["needs"].(map[string]any)
	needs["build"] = map[string]any{"outputs": map[string]any{}}
	needs["provenance"] = map[string]any{"outputs": map[string]any{"provenance-name": "bundles.intoto.jsonl"}}
	return composer.SHA256([]byte(readFile(t, filepath.Join(sim.artifacts, "release-notes", "dist", notesBundle)))).Hex()
}

// plant publishes a GitHub Release for notesTag with every asset another build produced, the way a token
// with contents:write can while the publish job waits for its reviewers.
func (r *releaseSimRig) plant(t *testing.T, from *simulator, author string) {
	t.Helper()
	dist := filepath.Join(from.artifacts, "release-notes", "dist")
	dir := filepath.Join(r.f.state, "gh", notesTag)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	copyTree(t, dist, filepath.Join(dir, "assets"))
	writeFile(t, filepath.Join(dir, "notes"), "looks normal")
	writeFile(t, filepath.Join(dir, "author"), author+"\n")
}

func (r *releaseSimRig) onchainRelease(t *testing.T) (id, rel string) {
	t.Helper()
	id = castOut(t, "call", r.c.registry, "releaseByVersion(bytes32,string)(bytes32)", composer.AppID("notes").Hex(), "1.0.0-sealed.1", "--rpc-url", r.c.rpc)
	if id == "0x"+strings.Repeat("0", 64) {
		return id, ""
	}
	rel = castOut(t, "call", r.c.registry, "getRelease(bytes32)((bytes32,bytes32,bytes32,bytes32,uint8,uint64,string,string,string))", id, "--rpc-url", r.c.rpc)
	return id, rel
}

// evilTree is the fixture with a wider egress allowlist, a tree CI never reviewed.
func evilTree(t *testing.T) string {
	t.Helper()
	root := withScripts(t, fixtureRepo(t))
	writeFile(t, filepath.Join(root, CatalogDir, "notes", "egress.yaml"),
		"version: 1\ndefault_allow: [\"api.example.com:443\", \"exfil.attacker.example:443\"]\ncustomer_additions_allowed: true\nnotes: \"x\"\n")
	return root
}

// supply-1 (ported from the verifier's TestSupply1PrePublishedReleaseWins, inverted): a GitHub Release
// planted under the tag before publish runs must stop the job before the OPS key is used, whoever the
// author is, and getRelease stays absent. The plan reports it as published-not-onchain (or fails on its
// author). Once it is gone, the job publishes CI's bundle with the .sigstore.json signatureURI (G13), and
// a re-run whose own bundle is already published still passes.
func TestReleasePublishRefusesPlantedRelease(t *testing.T) {
	r := newReleaseSimRig(t)
	root := withScripts(t, fixtureRepo(t))
	sim := r.sim(root, mainWorkflowRef)
	entry := planOne(t, sim)
	ciHash := buildRelease(t, sim, entry)

	// A run of the release workflow on another branch (github-actions[bot], a valid signature for the
	// branch identity) builds notes from a tree with a wider egress allowlist and publishes it under the tag.
	branch := r.sim(evilTree(t), "sealedtempo/sealed/.github/workflows/release.yml@refs/heads/evil")
	branch.ctx["needs"] = sim.ctx["needs"]
	evilHash := buildRelease(t, branch, entry)
	if evilHash == ciHash {
		t.Fatal("the planted bundle must differ from CI's")
	}
	r.plant(t, branch, "github-actions[bot]")

	_, err := sim.runJobErr("publish", entry)
	if err == nil {
		t.Fatalf("BUG supply-1: publish accepted a planted release (bundle %s; CI built %s)", evilHash, ciHash)
	}
	mustContain(t, err.Error(), "serves bundle "+evilHash+", not the bundle this run built ("+ciHash+")")
	mustContain(t, err.Error(), "is not signed by "+mainIdentity)
	if id, rel := r.onchainRelease(t); rel != "" {
		t.Fatalf("BUG supply-1: release %s is onchain after a refused publish: %s", id, rel)
	}
	// The plan flags it as a release the publish job must verify, not a normal plan.
	if e := planOne(t, r.sim(root, mainWorkflowRef)); e["githubRelease"] != "published-not-onchain" {
		t.Fatalf("plan of a release published on GitHub only: %v", e)
	}

	// The same planted release created by a person (or a token other than the workflow's) fails at the
	// GitHub Release step, and the plan refuses it too.
	r.plant(t, branch, "mallory")
	if _, err = sim.runJobErr("publish", entry); err == nil || !strings.Contains(err.Error(), "created by mallory, not by the release workflow (github-actions[bot])") {
		t.Fatalf("publish of a release created by another account: %v", err)
	}
	if _, err = r.sim(root, mainWorkflowRef).runJobErr("plan", nil); err == nil || !strings.Contains(err.Error(), "title=release-not-ci::GitHub Release "+notesTag+" (published) was created by mallory") {
		t.Fatalf("plan of a release created by another account: %v", err)
	}
	if _, rel := r.onchainRelease(t); rel != "" {
		t.Fatalf("onchain after a refused publish: %s", rel)
	}

	// Once the planted release is deleted, the job publishes CI's own bundle.
	if err := os.RemoveAll(filepath.Join(r.f.state, "gh", notesTag)); err != nil {
		t.Fatal(err)
	}
	sim.runJob("publish", entry)
	id, rel := r.onchainRelease(t)
	if !strings.Contains(rel, strings.TrimPrefix(ciHash, "0x")) {
		t.Fatalf("onchain %s: %s, want bundle %s", id, rel, ciHash)
	}
	// G13: signatureURI is the Sigstore bundle, which cosign 3 verifies with --bundle.
	base := "https://github.com/sealedtempo/sealed/releases/download/" + notesTag + "/" + notesBundle
	if !strings.HasSuffix(strings.TrimSpace(rel), `"`+base+`.intoto.jsonl", "`+base+`.sigstore.json")`) {
		t.Fatalf("provenanceURI and signatureURI: %s", rel)
	}
	var doc ReleaseDoc
	if err := readJSONFile(filepath.Join(r.f.state, "gh", notesTag, "assets", "notes-1.0.0-sealed.1.release.json"), &doc); err != nil {
		t.Fatal(err)
	}
	firstTx := doc.Onchain.TxHash

	// A re-run whose own bundle is already published passes without a new transaction, on the sha256
	// check alone.
	seen := len(r.f.calls(t))
	if _, err := sim.runJobErr("publish", entry); err != nil {
		t.Fatalf("re-run: %v", err)
	}
	if err := readJSONFile(filepath.Join(r.f.state, "gh", notesTag, "assets", "notes-1.0.0-sealed.1.release.json"), &doc); err != nil ||
		doc.Onchain.TxHash != firstTx || !doc.Onchain.AlreadyPublished {
		t.Fatalf("re-run: %+v %v", doc.Onchain, err)
	}
	if strings.Contains(r.f.calls(t)[seen:], "/public/"+notesBundle+".sigstore.json") {
		t.Fatal("a release serving this run's own bundle needs no signature lookup")
	}
}

// supply-1, the other accepted case: an existing release whose bundle is not this run's build (for
// example a full re-run after a non-reproducible build) is still used when release.yml on main signed it.
func TestReleasePublishAcceptsReleaseSignedOnMain(t *testing.T) {
	r := newReleaseSimRig(t)
	root := withScripts(t, fixtureRepo(t))
	sim := r.sim(root, mainWorkflowRef)
	entry := planOne(t, sim)
	ciHash := buildRelease(t, sim, entry)

	earlier := r.sim(evilTree(t), mainWorkflowRef)
	earlier.ctx["needs"] = sim.ctx["needs"]
	earlierHash := buildRelease(t, earlier, entry)
	r.plant(t, earlier, "github-actions[bot]")

	sim.runJob("publish", entry)
	_, rel := r.onchainRelease(t)
	if !strings.Contains(rel, strings.TrimPrefix(earlierHash, "0x")) || strings.Contains(rel, strings.TrimPrefix(ciHash, "0x")) {
		t.Fatalf("onchain: %s, want the published bundle %s", rel, earlierHash)
	}
	mustContain(t, r.f.calls(t), "/public/"+notesBundle+".sigstore.json --certificate-identity "+mainIdentity+
		" --certificate-oidc-issuer https://token.actions.githubusercontent.com")
}
