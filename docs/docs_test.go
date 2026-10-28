// Package docs_test checks that the public docs name what the code does: the composer version and golden stackHash,
// the key broker's reason codes and key tags, the verifier's checks, the in-VM network layout, the agent's local API
// and exact health fields, the payer's error types, the access-key selectors, and that every Go test the threat model
// and the README cite exists. The docs carry no em-dashes.
package docs_test

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	keybroker "github.com/sealed-dev/sealed/key-broker"
	"github.com/sealed-dev/sealed/runtime/composer"
	"github.com/sealed-dev/sealed/runtime/egress/policy"
	verify "github.com/sealed-dev/sealed/verifier"
	"github.com/sealed-dev/sealed/verifier/attest"
)

// root is the repository root, relative to this package directory (go test runs in it).
const root = ".."

func read(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// section returns INTERFACES.md section n ("## n. ..." up to the next "## ").
func section(t *testing.T, doc string, n string) string {
	t.Helper()
	start := strings.Index(doc, "\n## "+n+". ")
	if start < 0 {
		t.Fatalf("INTERFACES.md has no section %s", n)
	}
	rest := doc[start+1:]
	if end := strings.Index(rest[3:], "\n## "); end >= 0 {
		return rest[:end+3]
	}
	return rest
}

func mustContain(t *testing.T, where, text string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(text, w) {
			t.Errorf("%s does not mention %q", where, w)
		}
	}
}

func TestNoEmDashes(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(root, "docs", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, filepath.Join(root, "README.md"))
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if strings.ContainsRune(line, '—') {
				t.Errorf("%s:%d has an em-dash", filepath.Base(f), i+1)
			}
		}
	}
}

// TestTablesAreWellFormed: every row of a Markdown table has as many cells as its header. GitHub splits cells on
// every unescaped `|`, also inside code spans, so `||` in a formula must be written `\|\|` in a table.
func TestTablesAreWellFormed(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(root, "docs", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, filepath.Join(root, "README.md"))
	sep := regexp.MustCompile(`^\|[-| :]+\|$`)
	pipes := func(l string) int { return strings.Count(strings.ReplaceAll(l, `\|`, ""), "|") }
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(b), "\n")
		for i := 0; i+1 < len(lines); i++ {
			if !strings.HasPrefix(lines[i], "|") || !sep.MatchString(lines[i+1]) {
				continue
			}
			want := pipes(lines[i])
			j := i + 2
			for ; j < len(lines) && strings.HasPrefix(lines[j], "|"); j++ {
				if got := pipes(lines[j]); got != want {
					t.Errorf("%s:%d: %d cell separators, the header has %d (escape | inside cells as \\|)", filepath.Base(f), j+1, got, want)
				}
			}
			i = j
		}
	}
}

func TestInterfacesComposerVersionAndGolden(t *testing.T) {
	doc := read(t, "docs/INTERFACES.md")
	for _, m := range regexp.MustCompile(`"composerVersion": "([^"]+)"`).FindAllStringSubmatch(doc, -1) {
		if m[1] != composer.Version {
			t.Errorf("INTERFACES.md shows composerVersion %q, the composer is %s", m[1], composer.Version)
		}
	}
	mustContain(t, "INTERFACES.md section 5", section(t, doc, "5"), "`"+composer.Version+"`", "`https`", composer.RelayAttestPath)
	var sum struct {
		ComposerVersion string `json:"composerVersion"`
		StackHash       string `json:"stackHash"`
	}
	if err := json.Unmarshal([]byte(read(t, "runtime/composer/testdata/golden/summary.json")), &sum); err != nil {
		t.Fatal(err)
	}
	mustContain(t, "INTERFACES.md section 6", section(t, doc, "6"), "composer "+sum.ComposerVersion+": stackHash `"+sum.StackHash+"`")
}

func TestInterfacesNetworks(t *testing.T) {
	doc := read(t, "docs/INTERFACES.md")
	s6 := section(t, doc, "6")
	mustContain(t, "INTERFACES.md section 6", s6, composer.AppsSubnet, composer.EdgeSubnet, composer.VerifierSubnet, composer.VerifierdIP, `"net.ipv4.ip_forward": "0"`)
	for _, r := range composer.VMRanges {
		mustContain(t, "INTERFACES.md section 5", section(t, doc, "5"), r)
	}
	for _, p := range policy.VMInternalPrefixes {
		mustContain(t, "INTERFACES.md section 12", section(t, doc, "12"), p)
	}
	s12 := section(t, doc, "12")
	mustContain(t, "INTERFACES.md section 12", s12, composer.PayerVerifierIP, composer.VerifierdIP, "sealed-mpp-payer--verifier", "sealed-agent--app-<appId>", "ip-vm-internal")
	s14 := section(t, doc, "14")
	mustContain(t, "INTERFACES.md section 14", s14, composer.EgressVerifierIP, composer.PayerVerifierIP, composer.VerifierdIP,
		"SEALED_VERIFIERD_ALLOWED_CLIENTS="+composer.PayerVerifierIP, "stop_grace_period: "+composer.PayerStopGracePeriod, "share_with")
	arch := read(t, "docs/ARCHITECTURE.md")
	for _, sub := range []string{composer.AppsSubnet, composer.EdgeSubnet, composer.VerifierSubnet} {
		mustContain(t, "ARCHITECTURE.md", arch, "| `"+sub+"`")
	}
	if strings.Contains(arch, "verifierd: apps .6") || strings.Contains(arch, "verifierd `.6`)") {
		t.Error("ARCHITECTURE.md still puts sealed-verifierd on the apps network; it is on the verifier network only (D-061)")
	}
}

func TestInterfacesKeyBroker(t *testing.T) {
	s9 := section(t, read(t, "docs/INTERFACES.md"), "9")
	reasons := append([]string{}, keybroker.DenialReasons...)
	reasons = append(reasons, keybroker.ReasonBadRequest, keybroker.ReasonUnavailable, keybroker.ReasonSecretMissing,
		keybroker.ReasonSecretInvalid, keybroker.ReasonLogFailed, keybroker.ReasonChainStale, keybroker.ReasonRateLimited, keybroker.ReasonInternal)
	for _, r := range reasons {
		mustContain(t, "INTERFACES.md section 9", s9, "`"+r+"`")
	}
	mustContain(t, "INTERFACES.md section 9", s9, keybroker.DiskKeyTag, keybroker.SignerSeedTag, "share_with",
		"2 MiB", "5 minute lifetime")
	if keybroker.DefaultMaxBodyBytes != 2<<20 {
		t.Errorf("the broker's body limit is %d bytes; INTERFACES.md section 9 says 2 MiB", keybroker.DefaultMaxBodyBytes)
	}
	if keybroker.NonceLifetime != 5*time.Minute {
		t.Errorf("the nonce lifetime is %s; INTERFACES.md section 9 says 5 minutes", keybroker.NonceLifetime)
	}
	if strings.Contains(s9, "sealed/disk/v1") || strings.Contains(s9, "sealed/signer/v1") {
		t.Error("INTERFACES.md section 9 still names the v1 key tags (D-058 replaced them)")
	}
}

func TestInterfacesReportDataAndVerifier(t *testing.T) {
	doc := read(t, "docs/INTERFACES.md")
	mustContain(t, "INTERFACES.md section 3", section(t, doc, "3"), attest.TagKeyRelease, attest.TagEvidence, attest.TagLiveAttest)
	s8 := section(t, doc, "8")
	for _, c := range []string{
		verify.CheckBundle, verify.CheckChain, verify.CheckQuoteHash, verify.CheckQuote, verify.CheckTDAttributes,
		verify.CheckImageMeasurements, verify.CheckImageApproved, verify.CheckEventLogHash, verify.CheckRTMR3,
		verify.CheckComposeHash, verify.CheckConfigHash, verify.CheckConfigBinding, verify.CheckDeploymentID,
		verify.CheckReportData, verify.CheckFreshness, verify.CheckReleasesActive, verify.CheckStackRecompute,
		verify.CheckStackApproved, verify.CheckApprovalReleases, verify.CheckOnchainRecord, verify.CheckExpectedCustomer,
		verify.CheckExpectedApps, verify.CheckLiveFetch, verify.CheckTLSBinding,
	} {
		mustContain(t, "INTERFACES.md section 8", s8, "`"+c+"`")
	}
	mustContain(t, "INTERFACES.md section 8", s8, "chain_stale", verify.ModeLiveSubmitted)
	if verify.DefaultMaxChainHeadAge != 60*time.Second || verify.MaxChainHeadAgeLimit != 300*time.Second {
		t.Error("the verifier's head age bounds changed; INTERFACES.md section 8 says 60 s, at most 300 s")
	}
}

// quoted returns the quoted strings of src between the first start marker and the following end marker.
func quoted(t *testing.T, src, start, end string) []string {
	t.Helper()
	i := strings.Index(src, start)
	if i < 0 {
		t.Fatalf("marker %q not found", start)
	}
	block := src[i+len(start):]
	if j := strings.Index(block, end); j >= 0 {
		block = block[:j]
	}
	var out []string
	for _, m := range regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(block, -1) {
		out = append(out, m[1])
	}
	if len(out) == 0 {
		t.Fatalf("no strings after %q", start)
	}
	return out
}

func TestInterfacesAgentAPIAndHealth(t *testing.T) {
	doc := read(t, "docs/INTERFACES.md")
	s10, s11 := section(t, doc, "10"), section(t, doc, "11")
	server := read(t, "runtime/agent/src/server.ts")
	routes := regexp.MustCompile(`case "(?:GET|POST) (/[^"]*)"`).FindAllStringSubmatch(server, -1)
	if len(routes) < 8 {
		t.Fatalf("found only %d agent routes in server.ts", len(routes))
	}
	for _, r := range routes {
		mustContain(t, "INTERFACES.md section 11", s11, "`"+r[1])
	}
	if strings.Contains(server, `"bearer"`) {
		mustContain(t, "INTERFACES.md section 11", s11, "bearer=1")
	}
	for _, f := range quoted(t, read(t, "runtime/agent/src/healthReport.ts"), "EXACT_PAYMENT_FIELDS: ReadonlySet<string> = new Set([", "]);") {
		mustContain(t, "INTERFACES.md section 10", s10, "`"+f+"`")
	}
	mustContain(t, "INTERFACES.md section 10", s10, "/v1/deployments/:id/usage-reports", "x-sealed-signature", "sealed/usage-reports/v1", `"reattest":true`, "409")
}

func TestInterfacesPayerRelayAndAccessKey(t *testing.T) {
	doc := read(t, "docs/INTERFACES.md")
	s15 := section(t, doc, "15")
	payer := read(t, "runtime/mpp-payer/src/server.ts")
	types := map[string]bool{}
	for _, m := range regexp.MustCompile(`error\(\d{3}, '([a-z_]+)'|type: '([a-z_]+)'`).FindAllStringSubmatch(payer, -1) {
		types[m[1]+m[2]] = true
	}
	if len(types) < 8 {
		t.Fatalf("found only %d payer error types", len(types))
	}
	for ty := range types {
		mustContain(t, "INTERFACES.md section 15", s15, "`"+ty+"`")
	}
	relay := read(t, "runtime/relay/src/server.ts")
	for _, m := range regexp.MustCompile(`notCharged\(\d{3}, '([a-z_]+)'|errorResponse\(502, '(charge_failed)'`).FindAllStringSubmatch(relay, -1) {
		mustContain(t, "INTERFACES.md section 15", s15, "`"+m[1]+m[2]+"`")
	}
	mustContain(t, "INTERFACES.md section 15", s15, "charged: false", "spend-state.json", "channels.json", "session-store.json", "SEALED-INPUT", "SEALED-EDGE")
	s10 := section(t, doc, "10")
	sels := regexp.MustCompile(`"(0x[0-9a-f]{8})"`).FindAllStringSubmatch(read(t, "packages/core/src/accessKey.ts"), -1)
	if len(sels) != 8 {
		t.Fatalf("found %d access-key selectors, want 8 (D-054)", len(sels))
	}
	for _, m := range sels {
		mustContain(t, "INTERFACES.md section 10", s10, m[1])
	}
	mustContain(t, "INTERFACES.md section 10", s10, "buildAccessKeyAuthorization", "D-054a", "InvalidCallScope")
}

// TestCitedTestsExist checks that every Go test the threat model, the architecture doc and the README cite by name
// exists, so a renamed or removed test cannot leave the docs pointing at nothing.
func TestCitedTestsExist(t *testing.T) {
	have := map[string]bool{}
	decl := regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9_]+)\(`)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", "dependencies", ".git", "tmp", "out", "dist":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range decl.FindAllStringSubmatch(string(b), -1) {
			have[m[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	cite := regexp.MustCompile("`(Test[A-Z][A-Za-z0-9_]*)`")
	for _, f := range []string{"docs/THREAT_MODEL.md", "docs/ARCHITECTURE.md", "docs/VERIFY.md", "README.md"} {
		for _, m := range cite.FindAllStringSubmatch(read(t, f), -1) {
			if !have[m[1]] {
				t.Errorf("%s cites %s, which no Go test declares", f, m[1])
			}
		}
	}
	tm := read(t, "docs/THREAT_MODEL.md")
	if strings.Contains(tm, "(hardening)") {
		t.Error("THREAT_MODEL.md still marks tests as (hardening) placeholders; name the merged tests")
	}
}

// TestXFAMIsNotClaimedPinned: the key broker records XFAM and does not compare it with a pinned value
// (key-broker/pcs.go tdConfig.check; D-070 is open), and the verifier only reports it. The docs must not say
// otherwise. When XFAM pinning lands, change this test with the docs.
func TestXFAMIsNotClaimedPinned(t *testing.T) {
	stale := []string{
		"TD_ATTRIBUTES and XFAM equal the values pinned",
		"so both are pinned per image",
		"both pinned per image",
		"TD_ATTRIBUTES and XFAM against an approved",
		"pinned TD attributes",
		"so they are pinned per image",
	}
	for _, f := range []string{"docs/THREAT_MODEL.md", "docs/VERIFY.md", "docs/ARCHITECTURE.md", "docs/INTERFACES.md", "README.md"} {
		text := read(t, f)
		for _, s := range stale {
			if strings.Contains(text, s) {
				t.Errorf("%s claims XFAM is pinned (%q); the code records it only (D-070 open)", f, s)
			}
		}
	}
	if !strings.Contains(read(t, "key-broker/pcs.go"), "not pinned (deferred)") {
		t.Error("key-broker/pcs.go no longer says XFAM is not pinned; if it is pinned now, update the docs and this test")
	}
}
