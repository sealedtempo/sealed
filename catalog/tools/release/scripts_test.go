package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sealed-dev/sealed/runtime/composer"
)

// Tests of scripts/release against a local Tempo node (anvil --network tempo) with the real contracts,
// deployed by contracts/script/Deploy.s.sol. Only anvil's public dev keys are used.
// SEALED_REQUIRE_ANVIL=1 turns a missing anvil, forge, cast or contracts/dependencies into a failure.

const (
	devOwner      = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" // dev 0
	devOps        = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" // dev 1
	devOracle     = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a" // dev 2
	devCustomer   = "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6" // dev 3
	devMaintainer = "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a" // dev 4
	devTreasury   = "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba" // dev 5
	pathUSD       = "0x20c0000000000000000000000000000000000000"
	alphaUSD      = "0x20c0000000000000000000000000000000000001"
	// The scripts' FEE_TOKEN in these tests. anvil's genesis prefers AlphaUSD for dev 0 and BetaUSD for
	// dev 1, so ThetaUSD makes both scripts send setUserToken.
	thetaUSD = "0x20c0000000000000000000000000000000000003"
	feeManager    = "0xfeec000000000000000000000000000000000000"
)

func skipOrFail(t *testing.T, reason string) {
	t.Helper()
	if os.Getenv("SEALED_REQUIRE_ANVIL") == "1" {
		t.Fatalf("SEALED_REQUIRE_ANVIL=1 but %s", reason)
	}
	t.Skip(reason)
}

func requireTools(t *testing.T, tools ...string) {
	t.Helper()
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			skipOrFail(t, tool+" not installed")
		}
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// startAnvil runs anvil --network tempo (chain 31337 unless chainID is set) and returns its URL.
func startAnvil(t *testing.T, chainID int) string {
	t.Helper()
	port := freePort(t)
	args := []string{"--network", "tempo", "--hardfork", "T4", "--port", fmt.Sprint(port), "--gas-limit", "500000000", "--silent"}
	if chainID != 0 {
		args = append(args, "--chain-id", fmt.Sprint(chainID))
	}
	cmd := exec.Command("anvil", args...)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	url := fmt.Sprintf("http://127.0.0.1:%d", port)
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if out, err := exec.Command("cast", "chain-id", "--rpc-url", url).Output(); err == nil && len(bytes.TrimSpace(out)) > 0 {
			return url
		}
	}
	t.Fatal("anvil did not start")
	return ""
}

func castOut(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("cast", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("cast %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return strings.ToLower(strings.TrimSpace(string(out)))
}

func castAddr(t *testing.T, key string) string {
	return castOut(t, "wallet", "address", "--private-key", key)
}

var (
	toolOnce sync.Once
	toolBin  string
	toolErr  error
)

// releaseBin builds the release tool once per test process.
func releaseBin(t *testing.T) string {
	t.Helper()
	toolOnce.Do(func() {
		dir, err := os.MkdirTemp("", "sealed-release-test")
		if err != nil {
			toolErr = err
			return
		}
		toolBin = filepath.Join(dir, "sealed-release")
		cmd := exec.Command("go", "build", "-o", toolBin, ".")
		out, err := cmd.CombinedOutput()
		if err != nil {
			toolErr = fmt.Errorf("go build: %v: %s", err, out)
		}
	})
	if toolErr != nil {
		t.Fatal(toolErr)
	}
	return toolBin
}

// contractsWorkdir copies the contracts sources (not the tests) into a temp dir and links the Soldeer
// dependencies, so forge writes its cache, broadcasts and deployments there instead of the repository.
func contractsWorkdir(t *testing.T) string {
	t.Helper()
	real := filepath.Join(repoRoot(t), "contracts")
	deps := filepath.Join(real, "dependencies")
	if !dirExists(deps) {
		skipOrFail(t, "contracts/dependencies is missing (run `make -C contracts deps`)")
	}
	dir := t.TempDir()
	for _, sub := range []string{"src", "script", "catalog"} {
		copyTree(t, filepath.Join(real, sub), filepath.Join(dir, sub))
	}
	for _, f := range []string{"foundry.toml", "remappings.txt", "soldeer.lock"} {
		if err := copyFile(filepath.Join(real, f), filepath.Join(dir, f)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "deployments"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(deps, filepath.Join(dir, "dependencies")); err != nil {
		t.Fatal(err)
	}
	return dir
}

type chainFixture struct {
	rpc, contracts, deployments, registry string
}

func deployContracts(t *testing.T) *chainFixture {
	t.Helper()
	requireTools(t, "anvil", "forge", "cast", "jq")
	work := contractsWorkdir(t)
	rpc := startAnvil(t, 0)
	cmd := exec.Command("forge", "script", "script/Deploy.s.sol:Deploy", "--rpc-url", rpc, "--broadcast", "--slow", "--tempo.fee-token", alphaUSD)
	cmd.Dir = work
	cmd.Env = append(cleanEnv(), "OWNER_PRIVATE_KEY="+devOwner, "OPS_ADDRESS="+castAddr(t, devOps), "ORACLE_ADDRESS="+castAddr(t, devOracle),
		"TREASURY_ADDRESS="+castAddr(t, devTreasury), "FEE_TOKEN_ADDRESS="+pathUSD, "DEPLOYMENTS_NETWORK=local",
		"DEPLOYMENTS_FILE=deployments/test-release.json")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("deploy: %v\n%s", err, out)
	}
	dep := filepath.Join(work, "deployments/test-release.json")
	var d struct {
		Contracts map[string]struct {
			Address string `json:"address"`
		} `json:"contracts"`
	}
	if err := readJSONFile(dep, &d); err != nil {
		t.Fatal(err)
	}
	return &chainFixture{rpc: rpc, contracts: work, deployments: dep, registry: strings.ToLower(d.Contracts["AppRegistry"].Address)}
}

// cleanEnv is the test process environment without anything that could point a script at a real
// network or key: the scripts get exactly what each test passes.
func cleanEnv() []string {
	var out []string
	for _, kv := range os.Environ() {
		k := kv[:strings.IndexByte(kv, '=')]
		switch {
		case strings.HasSuffix(k, "_PRIVATE_KEY"), strings.HasPrefix(k, "TEMPO_"), strings.HasPrefix(k, "ETH_"),
			k == "SEALED_ENV", k == "CI", k == "GITHUB_ACTIONS", k == "DEPLOYMENTS_FILE", k == "FEE_TOKEN_ADDRESS",
			k == "EXPECT_CHAIN_ID", k == "MAINTAINER_DEFAULT_ADDRESS", k == "DRY_RUN", k == "FOUNDRY_PROFILE":
			continue
		}
		out = append(out, kv)
	}
	return out
}

type scriptResult struct {
	code   int
	output string // stdout and stderr
}

func runScript(t *testing.T, script string, env []string, stdin string, args ...string) scriptResult {
	t.Helper()
	cmd := exec.Command("bash", append([]string{filepath.Join(repoRoot(t), "scripts/release", script)}, args...)...)
	cmd.Env = append(cleanEnv(), env...)
	cmd.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{devOwner, devOps, devCustomer} {
		if strings.Contains(out.String(), strings.TrimPrefix(k, "0x")) {
			t.Fatalf("%s printed a private key:\n%s", script, out.String())
		}
	}
	return scriptResult{code, out.String()}
}

func TestRegisterAppsOnAnvil(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	c := deployContracts(t)
	envFile := filepath.Join(t.TempDir(), "test.env")
	maintainer := castAddr(t, devMaintainer)
	writeFile(t, envFile, "# test env\nOWNER_PRIVATE_KEY=\""+devOwner+"\"\nMAINTAINER_DEFAULT_ADDRESS="+maintainer+"\nOTHER=$(echo should-not-run)\n")
	owner := castAddr(t, devOwner)
	base := []string{"SEALED_ENV=" + envFile, "TEMPO_RPC_URL=" + c.rpc, "EXPECT_CHAIN_ID=31337", "CONTRACTS_DIR=" + c.contracts,
		"DEPLOYMENTS_FILE=" + c.deployments, "FEE_TOKEN_ADDRESS=" + thetaUSD, "SEALED_RELEASE_BIN=" + releaseBin(t)}
	prefBefore := castOut(t, "call", feeManager, "userTokens(address)(address)", owner, "--rpc-url", c.rpc)
	if prefBefore == thetaUSD {
		t.Fatal("test needs OWNER to start with another fee token preference")
	}

	// Dry run: plan and simulation only.
	r := runScript(t, "register-apps.sh", base, "")
	if r.code != 0 {
		t.Fatalf("dry run: %d\n%s", r.code, r.output)
	}
	for _, want := range []string{"scraper              no", "inference-relay      no", maintainer + " (default)", "dry run: nothing sent",
		"a real run sends setUserToken(" + thetaUSD + ")"} {
		mustContain(t, r.output, want)
	}
	if castOut(t, "call", c.registry, "appCount()(uint256)", "--rpc-url", c.rpc) != "0" {
		t.Fatal("a dry run must not register anything")
	}
	if castOut(t, "call", feeManager, "userTokens(address)(address)", owner, "--rpc-url", c.rpc) != prefBefore {
		t.Fatal("a dry run must not change the fee token preference")
	}
	if matches, _ := filepath.Glob(filepath.Join(c.contracts, "catalog/.register-apps.*.json")); len(matches) != 0 {
		t.Fatalf("generated catalog left behind: %v", matches)
	}

	// Broadcast needs the chain id typed in, unless --yes.
	r = runScript(t, "register-apps.sh", base, "1\n", "--apps", "scraper,llm-gateway", "--broadcast")
	if r.code == 0 || !strings.Contains(r.output, "not confirmed; nothing sent") {
		t.Fatalf("wrong confirmation: %d\n%s", r.code, r.output)
	}
	r = runScript(t, "register-apps.sh", base, "31337\n", "--apps", "scraper,llm-gateway", "--broadcast")
	if r.code != 0 {
		t.Fatalf("broadcast: %d\n%s", r.code, r.output)
	}
	mustContain(t, r.output, "ok   scraper registered")
	mustContain(t, r.output, "ok   llm-gateway registered")
	mustContain(t, r.output, "| OWNER "+owner)
	mustContain(t, r.output, "registerApp scraper")
	if got := castOut(t, "call", feeManager, "userTokens(address)(address)", owner, "--rpc-url", c.rpc); got != thetaUSD {
		t.Fatalf("OWNER fee token preference %s, want %s (D-038)", got, thetaUSD)
	}
	app := castOut(t, "call", c.registry, "getApp(bytes32)((string,string,string,string,address,uint16,uint64))", composer.AppID("scraper").Hex(), "--rpc-url", c.rpc)
	for _, want := range []string{`"scraper"`, `"apache-2.0"`, maintainer, "2000", "https://github.com/sealedtempo/sealed/tree/main/catalog/apps/scraper"} {
		mustContain(t, app, want)
	}

	// Re-running registers only what is missing.
	r = runScript(t, "register-apps.sh", base, "", "--apps", "scraper,llm-gateway", "--broadcast", "--yes")
	if r.code != 0 || !strings.Contains(r.output, "nothing to register") {
		t.Fatalf("rerun: %d\n%s", r.code, r.output)
	}

	// Refusals: a key that does not own AppRegistry, and CI against a non-local chain.
	other := filepath.Join(t.TempDir(), "other.env")
	writeFile(t, other, "OWNER_PRIVATE_KEY="+devCustomer+"\n")
	r = runScript(t, "register-apps.sh", append(base, "SEALED_ENV="+other), "")
	if r.code != 3 || !strings.Contains(r.output, "but AppRegistry is owned by "+owner) {
		t.Fatalf("non-owner: %d\n%s", r.code, r.output)
	}
	r = runScript(t, "register-apps.sh", append(base, "GITHUB_ACTIONS=true"), "")
	if r.code != 0 {
		t.Fatalf("CI against a local chain is allowed (tests): %d\n%s", r.code, r.output)
	}
	mainnetLike := startAnvil(t, 4217)
	r = runScript(t, "register-apps.sh", append(base, "GITHUB_ACTIONS=true", "TEMPO_RPC_URL="+mainnetLike, "EXPECT_CHAIN_ID=4217"), "")
	if r.code == 0 || !strings.Contains(r.output, "runs only on the OWNER's machine, never in CI") {
		t.Fatalf("CI on chain 4217 must be refused: %d\n%s", r.code, r.output)
	}
	r = runScript(t, "register-apps.sh", append(base, "EXPECT_CHAIN_ID=4217"), "")
	if r.code == 0 || !strings.Contains(r.output, "serves chain 31337, expected 4217") {
		t.Fatalf("chain mismatch: %d\n%s", r.code, r.output)
	}
}

func releaseInfo(t *testing.T, slug, version, content string) string {
	t.Helper()
	bh := composer.SHA256([]byte(content))
	appID := composer.AppID(slug)
	info := map[string]any{"appId": appID.Hex(), "slug": slug, "version": version, "bundleHash": bh.Hex(),
		"egressPolicyHash": composer.SHA256([]byte("egress " + content)).Hex(), "sbomHash": composer.SHA256([]byte("sbom " + content)).Hex(),
		"releaseId": composer.ReleaseID(appID, version, bh).Hex()}
	p := filepath.Join(t.TempDir(), "info.json")
	raw, _ := json.Marshal(info)
	writeFile(t, p, string(raw))
	return p
}

func TestPublishReleaseOnAnvil(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	c := deployContracts(t)
	// OWNER registers scraper only (cast, the way register-apps does it through forge).
	out, err := exec.Command("cast", "send", c.registry, "registerApp(bytes32,string,string,string,address,uint16,string)",
		composer.AppID("scraper").Hex(), "scraper", "Scraper", "Apache-2.0", castAddr(t, devMaintainer), "2000", "https://example.invalid/scraper",
		"--private-key", devOwner, "--rpc-url", c.rpc, "--tempo.fee-token", alphaUSD).CombinedOutput()
	if err != nil {
		t.Fatalf("registerApp: %v %s", err, out)
	}
	ops := castAddr(t, devOps)
	base := []string{"OPS_PRIVATE_KEY=" + devOps, "TEMPO_RPC_URL=" + c.rpc, "EXPECT_CHAIN_ID=31337", "DEPLOYMENTS_FILE=" + c.deployments,
		"FEE_TOKEN_ADDRESS=" + thetaUSD, "SEALED_RELEASE_BIN=" + releaseBin(t)}
	uris := []string{"--provenance-uri", "https://github.com/sealedtempo/sealed/releases/download/scraper-v0.1.0/scraper-0.1.0.bundle.tar.intoto.jsonl",
		"--signature-uri", "https://github.com/sealedtempo/sealed/releases/download/scraper-v0.1.0/scraper-0.1.0.bundle.tar.sig"}
	info := releaseInfo(t, "scraper", "0.1.0", "bundle one")
	result := filepath.Join(t.TempDir(), "result.json")
	args := func(infoPath string, extra ...string) []string {
		return append(append([]string{"--info", infoPath, "--out", result}, uris...), extra...)
	}

	// Refused: an app that is not registered.
	r := runScript(t, "publish-release.sh", base, "", args(releaseInfo(t, "crm", "1.0.0", "crm bundle"))...)
	if r.code != 3 || !strings.Contains(r.output, "app crm") || !strings.Contains(r.output, "is not registered") {
		t.Fatalf("unregistered: %d\n%s", r.code, r.output)
	}
	// Refused: a key without REGISTRAR_ROLE.
	r = runScript(t, "publish-release.sh", append(base, "OPS_PRIVATE_KEY="+devCustomer), "", args(info)...)
	if r.code != 3 || !strings.Contains(r.output, "does not hold REGISTRAR_ROLE") {
		t.Fatalf("no role: %d\n%s", r.code, r.output)
	}
	// Usage errors: inconsistent info, non-https URIs.
	bad := releaseInfo(t, "scraper", "0.1.0", "bundle one")
	writeFile(t, bad, strings.Replace(readFile(t, bad), `"version":"0.1.0"`, `"version":"0.1.1"`, 1))
	if r = runScript(t, "publish-release.sh", base, "", args(bad)...); r.code != 2 || !strings.Contains(r.output, "releaseId is not keccak256") {
		t.Fatalf("bad info: %d\n%s", r.code, r.output)
	}
	if r = runScript(t, "publish-release.sh", base, "", "--info", info, "--provenance-uri", "http://x", "--signature-uri", "https://x"); r.code != 2 {
		t.Fatalf("http URI: %d\n%s", r.code, r.output)
	}
	// Wrong chain.
	if r = runScript(t, "publish-release.sh", append(base, "EXPECT_CHAIN_ID=4217"), "", args(info)...); r.code == 0 {
		t.Fatalf("chain mismatch must fail:\n%s", r.output)
	}

	// Dry run: checks and simulation, nothing sent, fee token preference untouched.
	prefBefore := castOut(t, "call", feeManager, "userTokens(address)(address)", ops, "--rpc-url", c.rpc)
	if prefBefore == thetaUSD {
		t.Fatal("test needs OPS to start with another fee token preference")
	}
	r = runScript(t, "publish-release.sh", base, "", args(info, "--dry-run")...)
	if r.code != 0 || !strings.Contains(r.output, "ok   simulation returns releaseId") || !strings.Contains(r.output, "dry run: publishRelease not sent") {
		t.Fatalf("dry run: %d\n%s", r.code, r.output)
	}
	if castOut(t, "call", c.registry, "releaseCount(bytes32)(uint256)", composer.AppID("scraper").Hex(), "--rpc-url", c.rpc) != "0" ||
		castOut(t, "call", feeManager, "userTokens(address)(address)", ops, "--rpc-url", c.rpc) != prefBefore {
		t.Fatal("dry run sent something")
	}

	// Publish: fee token preference first (D-038), then publishRelease.
	r = runScript(t, "publish-release.sh", base, "", args(info)...)
	if r.code != 0 {
		t.Fatalf("publish: %d\n%s", r.code, r.output)
	}
	mustContain(t, r.output, "send setUserToken("+thetaUSD+") for "+ops)
	mustContain(t, r.output, "ok   published scraper 0.1.0")
	mustContain(t, r.output, "| OPS "+ops)
	if got := castOut(t, "call", feeManager, "userTokens(address)(address)", ops, "--rpc-url", c.rpc); got != thetaUSD {
		t.Fatalf("OPS fee token preference %s", got)
	}
	var rec OnchainRecord
	if err := readJSONFile(result, &rec); err != nil {
		t.Fatal(err)
	}
	var inf struct {
		ReleaseID string `json:"releaseId"`
	}
	_ = readJSONFile(info, &inf)
	if rec.ReleaseID != inf.ReleaseID || !txHashRe.MatchString(rec.TxHash) || rec.ChainID != 31337 || rec.From != ops || rec.AlreadyPublished || rec.AppRegistry != c.registry {
		t.Fatalf("record %+v", rec)
	}
	if got := castOut(t, "call", c.registry, "releaseByVersion(bytes32,string)(bytes32)", composer.AppID("scraper").Hex(), "0.1.0", "--rpc-url", c.rpc); got != inf.ReleaseID {
		t.Fatalf("releaseByVersion %s", got)
	}
	rel := castOut(t, "call", c.registry, "getRelease(bytes32)((bytes32,bytes32,bytes32,bytes32,uint8,uint64,string,string,string))", inf.ReleaseID, "--rpc-url", c.rpc)
	mustContain(t, rel, strings.ToLower(uris[1]))
	mustContain(t, rel, strings.ToLower(uris[3]))
	receipt := castOut(t, "receipt", rec.TxHash, "--json", "--rpc-url", c.rpc)
	if !strings.Contains(receipt, `"type":"0x76"`) {
		t.Fatalf("publishRelease must be a Tempo transaction with an explicit fee token (D-035): %s", receipt)
	}

	// Re-run: already published, same transaction, nothing sent.
	firstTx := rec.TxHash
	r = runScript(t, "publish-release.sh", base, "", args(info)...)
	if r.code != 0 || !strings.Contains(r.output, "is already published as") || strings.Contains(r.output, "send setUserToken") {
		t.Fatalf("rerun: %d\n%s", r.code, r.output)
	}
	if err := readJSONFile(result, &rec); err != nil || rec.TxHash != firstTx || !rec.AlreadyPublished {
		t.Fatalf("rerun record %+v %v", rec, err)
	}

	// Conflicts: the same version with another bundle, the same bundle under another version.
	r = runScript(t, "publish-release.sh", base, "", args(releaseInfo(t, "scraper", "0.1.0", "bundle two"))...)
	if r.code != 3 || !strings.Contains(r.output, "already published as release") {
		t.Fatalf("version conflict: %d\n%s", r.code, r.output)
	}
	r = runScript(t, "publish-release.sh", base, "", args(releaseInfo(t, "scraper", "0.1.1", "bundle one"))...)
	if r.code != 3 || !strings.Contains(r.output, "under another version") {
		t.Fatalf("bundle conflict: %d\n%s", r.code, r.output)
	}
}
