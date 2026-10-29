// Package docs_test checks that the public docs name what the code does: the composer version and golden stackHash,
// the key broker's reason codes and key tags, the verifier's checks, the in-VM network layout, the agent's local API
// and exact health fields, the payer's error types, the access-key selectors, and that every Go test the threat model
// and the README cite exists. The docs carry no em-dashes.
package docs_test

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	keybroker "github.com/sealedtempo/sealed/key-broker"
	"github.com/sealedtempo/sealed/runtime/caddy"
	"github.com/sealedtempo/sealed/runtime/composer"
	"github.com/sealedtempo/sealed/runtime/egress/policy"
	verify "github.com/sealedtempo/sealed/verifier"
	"github.com/sealedtempo/sealed/verifier/attest"
	"github.com/sealedtempo/sealed/verifier/httpapi"
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

// trackedFiles lists the repository's tracked files, relative to root, from `git ls-files`. In a tree without git
// metadata (an exported copy) it falls back to every file outside the dependency, build and cache directories.
func trackedFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	if out, err := exec.Command("git", "-C", root, "ls-files", "-z").Output(); err == nil && len(out) > 0 {
		for _, f := range strings.Split(string(out), "\x00") {
			if f != "" {
				files = append(files, filepath.FromSlash(f))
			}
		}
		return files
	}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", "dependencies", ".git", "tmp", "out", "dist", "cache", "broadcast", ".terraform", "__pycache__":
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, path)
		files = append(files, rel)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// textOf returns a tracked file's bytes, or nil when it is not a text file to check: missing from the work tree,
// not a regular file, over 8 MiB, or binary (a NUL byte in its first 8000 bytes, git's own test).
func textOf(t *testing.T, rel string) []byte {
	t.Helper()
	path := filepath.Join(root, rel)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Size() > 8<<20 {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.IndexByte(b[:min(len(b), 8000)], 0) >= 0 {
		return nil
	}
	return b
}

func hasSegment(rel, seg string) bool {
	for _, s := range strings.Split(filepath.ToSlash(rel), "/") {
		if s == seg {
			return true
		}
	}
	return false
}

// upstream reports a file whose text is not ours: an SPDX document (syft output) or an upstream license text under
// a LICENSES directory.
func upstream(rel string) bool {
	base := filepath.Base(rel)
	return strings.HasSuffix(base, ".spdx.json") || strings.HasSuffix(base, ".spdx") || hasSegment(rel, "LICENSES")
}

var testSource = regexp.MustCompile(`(_test\.go|_test\.py|\.test\.[cm]?[jt]s)$|(^|/)test_[^/]*\.py$`)

// detectorWords marks a line that searches for a string or lists banned ones.
var detectorWords = regexp.MustCompile(`(?i)contains|index|includes|match|search|banned|forbidden`)

// detector reports whether line, from a test source file, is a detector for needle: needle appears only inside quoted
// literals, and the line searches for it or lists it as banned. Detectors in this file use escapes or split strings.
func detector(rel, line, needle string) bool {
	if !testSource.MatchString(filepath.ToSlash(rel)) || !detectorWords.MatchString(line) {
		return false
	}
	quoted := make([]bool, len(line))
	var q byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		quoted[i] = q != 0
		switch {
		case q != 0 && q != '`' && c == '\\' && i+1 < len(line):
			quoted[i+1] = true
			i++
		case q != 0 && c == q:
			q = 0
		case q == 0 && (c == '"' || c == '\'' || c == '`'):
			q = c
		}
	}
	found := false
	for off := 0; ; {
		j := strings.Index(line[off:], needle)
		if j < 0 {
			return found
		}
		if !quoted[off+j] {
			return false
		}
		found = true
		off += j + len(needle)
	}
}

// TestNoEmDashes: no tracked text file carries an em-dash (BUILD_SPEC 1.2 rule 12; review policy-7), not only the
// docs. Binaries, SPDX documents, upstream license texts and testdata are skipped, and a test may name the character in
// a detector.
func TestNoEmDashes(t *testing.T) {
	const dash = "\u2014"
	files := trackedFiles(t)
	seen := map[string]bool{}
	for _, rel := range files {
		if upstream(rel) || hasSegment(rel, "testdata") {
			continue
		}
		b := textOf(t, rel)
		if b == nil {
			continue
		}
		seen[filepath.ToSlash(rel)] = true
		if !bytes.Contains(b, []byte(dash)) {
			continue
		}
		for i, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, dash) && !detector(rel, line, dash) {
				t.Errorf("%s:%d has an em-dash", filepath.ToSlash(rel), i+1)
			}
		}
	}
	for _, want := range []string{"README.md", "docs/THREAT_MODEL.md", "docs/docs_test.go", "runtime/caddy/payment-needed.html", "catalog/apps/crm/README.md"} {
		if !seen[want] {
			t.Errorf("the scan did not read %s; the tracked file list is wrong", want)
		}
	}
}

// bannedPhrases are the product phrases BUILD_SPEC 1.2 rule 12 forbids, split so that this file is not a match.
var bannedPhrases = []string{
	"no " + "breaches",
	"unbreak" + "able",
	"zero-knowledge proof that data was never " + "exposed",
	"zero knowledge proof that data was never " + "exposed",
}

var spaces = regexp.MustCompile(`\s+`)

// TestBannedPhrases: no tracked text file uses a phrase BUILD_SPEC 1.2 rule 12 bans (review policy-7), in any case and
// also across a line break. Binaries, SPDX documents and upstream license texts are skipped; a test may name a phrase
// in a detector.
func TestBannedPhrases(t *testing.T) {
	for _, rel := range trackedFiles(t) {
		if upstream(rel) {
			continue
		}
		b := textOf(t, rel)
		if b == nil {
			continue
		}
		text := strings.ToLower(string(b))
		lines := strings.Split(text, "\n")
		flat := spaces.ReplaceAllString(text, " ")
		for _, p := range bannedPhrases {
			if !strings.Contains(flat, p) {
				continue
			}
			onLines := 0
			for i, line := range lines {
				if n := strings.Count(line, p); n > 0 {
					onLines += n
					if !detector(rel, line, p) {
						t.Errorf("%s:%d says %q (BUILD_SPEC 1.2 rule 12)", filepath.ToSlash(rel), i+1, p)
					}
				}
			}
			if strings.Count(flat, p) > onLines {
				t.Errorf("%s says %q across a line break (BUILD_SPEC 1.2 rule 12)", filepath.ToSlash(rel), p)
			}
		}
	}
}

// TestNoThirdPartyAuditClaim: every review of this code so far was done by AI review agents, and no external audit
// has been done (review policy-2). No tracked Markdown file may present a review as an audit or as independent:
// "independent audit", "independent auditor", "independent review", "auditor", "audited" or "audited by", and
// "third-party audit", "external audit" or "security audit" unless negated ("not a third-party audit", "no external
// audit"). "license audit" and test paths such as `test/audit/` stay allowed.
func TestNoThirdPartyAuditClaim(t *testing.T) {
	claim := regexp.MustCompile(`(?i)\bindependent (audit|review)\w*|\bauditors?\b|\baudited\b|\b(third[- ]party|external|security) audit\w*`)
	negated := regexp.MustCompile(`(?i)\b(not an?|no|never an?|without an?)\s+$`)
	license := regexp.MustCompile(`(?i)license[- ]$`)
	checked := 0
	for _, rel := range trackedFiles(t) {
		if filepath.Ext(rel) != ".md" || upstream(rel) {
			continue
		}
		b := textOf(t, rel)
		if b == nil {
			continue
		}
		checked++
		text := spaces.ReplaceAllString(string(b), " ")
		for _, loc := range claim.FindAllStringIndex(text, -1) {
			m := strings.ToLower(text[loc[0]:loc[1]])
			before := text[max(0, loc[0]-16):loc[0]]
			switch {
			case strings.HasPrefix(m, "audited") && license.MatchString(before):
				continue
			case strings.HasPrefix(m, "third") || strings.HasPrefix(m, "external") || strings.HasPrefix(m, "security"):
				if negated.MatchString(before) {
					continue
				}
			}
			t.Errorf("%s says %q (...%s...): the reviews were AI agent reviews, not an audit", filepath.ToSlash(rel), text[loc[0]:loc[1]],
				text[max(0, loc[0]-40):min(len(text), loc[1]+40)])
		}
	}
	if checked < 10 {
		t.Fatalf("checked only %d Markdown files", checked)
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

// TestReleaseTagRuleDocumented: the release tag drops a leading v before a digit (composer.TagVersion), so the docs
// must give the tag as <appId>-v<tagVersion> and must not promise a <id>-vv... tag or a v-prefixed bundle directory.
func TestReleaseTagRuleDocumented(t *testing.T) {
	if got := composer.ReleaseTag("coding-agent", "v1.58.2"); got != "coding-agent-v1.58.2" {
		t.Fatalf("ReleaseTag(coding-agent, v1.58.2) = %s; update the docs with the rule", got)
	}
	s7 := section(t, read(t, "docs/INTERFACES.md"), "7")
	mustContain(t, "INTERFACES.md section 7", s7, "| tag | `<appId>-v<tagVersion>` |", "`<base>/<appId>-v<tagVersion>/<appId>-<version>.bundle.tar`",
		"`TagVersion`", "`coding-agent-v1.58.2`", "`vnext`")
	for _, f := range []string{"docs/INTERFACES.md", "docs/MAINTAINERS.md", "docs/VERIFY.md", "README.md"} {
		text := read(t, f)
		for _, stale := range []string{"-vv...", "<id>-v<version>", "<app>-v<version>/", "<appId>-v<version>/", "refuses a leading `v`"} {
			if strings.Contains(text, stale) {
				t.Errorf("%s still says %q; the tag is <appId>-v<tagVersion> (composer.TagVersion)", f, stale)
			}
		}
	}
	mustContain(t, "MAINTAINERS.md", read(t, "docs/MAINTAINERS.md"), "<id>-v<tagVersion>")
}

// TestBearerGateDocumented: composer 1.4.0's bearer-passthrough handles ask the gate's bearer mode; the docs must say
// so and must not keep the old "does not ask the gate" residual.
func TestBearerGateDocumented(t *testing.T) {
	tmpl := read(t, "runtime/caddy/Caddyfile.tmpl")
	if !strings.Contains(tmpl, "GateBearerQuery") || caddy.GateBearerQuery != "bearer=1" {
		t.Fatal("the Caddy template no longer asks the gate's bearer mode; update the docs and this test")
	}
	s14 := section(t, read(t, "docs/INTERFACES.md"), "14")
	mustContain(t, "INTERFACES.md section 14", s14, "uri /v1/gate?route=<route>&"+caddy.GateBearerQuery)
	for _, f := range []string{"docs/INTERFACES.md", "docs/THREAT_MODEL.md", "docs/ARCHITECTURE.md"} {
		text := read(t, f)
		for _, stale := range []string{"does not ask the gate", "does not call it yet", "go straight to the app", "skip the bootstrap hold"} {
			if strings.Contains(text, stale) {
				t.Errorf("%s still says %q; bearer requests wait for the gate's bearer mode (review C-6)", f, stale)
			}
		}
	}
}

// TestPayerStateDocumented: the payer's state directory is a data-disk bind made private by envexec.
func TestPayerStateDocumented(t *testing.T) {
	doc := read(t, "docs/INTERFACES.md")
	mustContain(t, "INTERFACES.md section 14", section(t, doc, "14"), composer.PayerStateDir, "/mnt/sealed-data/_mpp-payer/state", `"private"`, `user: "1000:1000"`)
	mustContain(t, "INTERFACES.md section 15", section(t, doc, "15"), "/mnt/sealed-data/_mpp-payer/state", "envexec private")
	if strings.Contains(doc, "no persistent mount") || strings.Contains(doc, "mounts no persistent volume") {
		t.Error("INTERFACES.md still says the payer has no persistent mount")
	}
}

// TestVerifierdLimitsDocumented: sealed-verifierd reads at most httpapi.MaxBodyBytes and reports its composer version
// and body limit on /healthz; the platform api routes in front of it accept no more.
func TestVerifierdLimitsDocumented(t *testing.T) {
	if httpapi.MaxBodyBytes != 8<<20 {
		t.Fatalf("sealed-verifierd's body limit is %d bytes; the docs say 8 MiB", httpapi.MaxBodyBytes)
	}
	s10 := section(t, read(t, "docs/INTERFACES.md"), "10")
	mustContain(t, "INTERFACES.md section 10", s10, "composerVersion, liveFetch, maxBodyBytes}", `"code":"body_too_large"`, "8388608",
		"evidence bundle (at most 8 MiB")
	if strings.Contains(s10, "16 MiB") {
		t.Error("INTERFACES.md section 10 still names 16 MiB; the api and Caddy take sealed-verifierd's 8 MiB")
	}
}

// TestBrokerBootstrapEnvDocumented: the bootstrap's optional broker variables and the Cloud Run concurrency in
// key_broker.tf appear in INTERFACES.md section 16.
func TestBrokerBootstrapEnvDocumented(t *testing.T) {
	s16 := section(t, read(t, "docs/INTERFACES.md"), "16")
	for _, name := range quoted(t, read(t, "key-broker/cmd/key-broker/main.go"), "var bootstrapOptionalEnv = []string{", "}") {
		mustContain(t, "INTERFACES.md section 16", s16, "`"+name+"`")
	}
	m := regexp.MustCompile(`max_instance_request_concurrency\s*=\s*([0-9]+)`).FindStringSubmatch(read(t, "infra/terraform/customer-bootstrap/key_broker.tf"))
	if m == nil {
		t.Fatal("key_broker.tf sets no max_instance_request_concurrency")
	}
	mustContain(t, "INTERFACES.md section 16", s16, "request concurrency "+m[1])
}

// TestPlatformSideFailuresDocumented: every settlement reason the agent defers under D-073 is named in section 11.
func TestPlatformSideFailuresDocumented(t *testing.T) {
	s11 := section(t, read(t, "docs/INTERFACES.md"), "11")
	reasons := quoted(t, read(t, "runtime/agent/src/payments/settler.ts"), "PLATFORM_SIDE_FAILURES: ReadonlySet<string> = new Set([", "]);")
	if len(reasons) < 3 {
		t.Fatalf("found %d platform-side reasons", len(reasons))
	}
	for _, r := range reasons {
		mustContain(t, "INTERFACES.md section 11", s11, "`"+r+"`")
	}
	mustContain(t, "INTERFACES.md section 11", s11, "`rpc_error`", "`deferredSince`")
}

// TestRepositoryNamedSealedtempo: the Go module, the registry, the release asset base and every first-party repo
// reference name the published repository, sealedtempo/sealed. The placeholder owner of the build (D-005, D-028)
// must not come back in any tracked text file.
func TestRepositoryNamedSealedtempo(t *testing.T) {
	if !strings.HasPrefix(read(t, "go.mod"), "module github.com/sealedtempo/sealed\n") {
		t.Error("go.mod does not name the module github.com/sealedtempo/sealed")
	}
	defaults := read(t, "config/defaults.yaml")
	mustContain(t, "config/defaults.yaml", defaults, "registry: ghcr.io/sealedtempo\n", "release_asset_base: https://github.com/sealedtempo/sealed/releases/download\n")
	for _, app := range []string{"scraper", "inference-relay"} {
		mustContain(t, "catalog/apps/"+app+"/manifest.yaml", read(t, "catalog/apps/"+app+"/manifest.yaml"), "repo: https://github.com/sealedtempo/sealed\n")
	}
	placeholder := "sealed" + "-dev"
	text := map[string]bool{".go": true, ".ts": true, ".mjs": true, ".js": true, ".json": true, ".yaml": true, ".yml": true, ".md": true,
		".py": true, ".sh": true, ".tf": true, ".hcl": true, ".toml": true, ".txt": true, ".sol": true, ".example": true, "": true}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", "dependencies", ".git", "tmp", "out", "dist", "cache", "broadcast", ".terraform", "__pycache__":
				return filepath.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(path)
		if !text[ext] && !strings.HasPrefix(d.Name(), "Dockerfile") {
			return nil
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > 8<<20 {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(b), placeholder) {
			rel, _ := filepath.Rel(root, path)
			t.Errorf("%s names %s; the repository and registry are sealedtempo", rel, placeholder)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
