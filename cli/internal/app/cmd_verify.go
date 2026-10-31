package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/sealedtempo/sealed/cli/internal/bundles"
	"github.com/sealedtempo/sealed/cli/internal/registry"
	verify "github.com/sealedtempo/sealed/verifier"
	"github.com/sealedtempo/sealed/verifier/attest"
	"github.com/sealedtempo/sealed/verifier/chain"
)

var aliasRe = regexp.MustCompile(`^dep_[0-9A-Za-z]{8}$`)

// AliasResolver turns a dep_ alias into the full deploymentId (D-032). The answer is only a pointer: every check
// then runs against the chain with that id.
type AliasResolver interface {
	Resolve(ctx context.Context, alias string) ([32]byte, error)
}

// apiResolver asks the platform api (POST /v1/verify {deploymentId: alias}, open to anyone).
type apiResolver struct {
	base string
	http *http.Client
}

func (a *apiResolver) Resolve(ctx context.Context, alias string) ([32]byte, error) {
	body, _ := json.Marshal(map[string]string{"deploymentId": alias})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(a.base, "/")+"/v1/verify", bytes.NewReader(body))
	if err != nil {
		return [32]byte{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpOrDefault(a.http).Do(req)
	if err != nil {
		return [32]byte{}, fmt.Errorf("resolve %s: %w", alias, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out struct {
		Result       string `json:"result"`
		DeploymentID string `json:"deploymentId"`
		Alias        string `json:"alias"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(raw, &out) != nil {
		return [32]byte{}, fmt.Errorf("resolve %s: the platform api answered HTTP %d", alias, resp.StatusCode)
	}
	if out.Result == "not_found" || out.DeploymentID == "" {
		return [32]byte{}, fmt.Errorf("the platform api does not know %s", alias)
	}
	if out.Alias != "" && out.Alias != alias {
		return [32]byte{}, fmt.Errorf("the platform api resolved %s as %s", alias, out.Alias)
	}
	return registry.ParseHash32(strings.ToLower(out.DeploymentID))
}

func httpOrDefault(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return &http.Client{Timeout: 60 * time.Second}
}

// fetchEvidence downloads the deployment's evidence bundle from the platform api. It is verified like a file:
// the platform is not trusted for any check.
func fetchEvidence(ctx context.Context, c *http.Client, base, id, apiKey string) ([]byte, error) {
	u := strings.TrimRight(base, "/") + "/v1/deployments/" + url.PathEscape(id) + "/evidence"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := httpOrDefault(c).Do(req)
	if err != nil {
		return nil, fmt.Errorf("download evidence: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download evidence: HTTP %d from the platform api (pass --evidence <file> instead)", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 32<<20))
}

// VerifyDeps lets tests replace the quote verifier.
var newQuoteVerifier = func(defaults []byte, allowSimulated bool, cacheDir string) (*attest.Verifier, error) {
	policy, err := attest.TCBPolicyFromDefaults(defaults)
	if err != nil {
		return nil, err
	}
	xfam, err := attest.XFAMAllowlistFromDefaults(defaults)
	if err != nil {
		return nil, err
	}
	getter, err := attest.NewCachingGetter(attest.CacheOptions{Dir: cacheDir})
	if err != nil {
		return nil, err
	}
	return attest.NewVerifier(attest.VerifierOptions{AllowSimulated: allowSimulated, Getter: getter, TCBPolicy: policy, AllowedXFAM: xfam})
}

func runVerify(ctx context.Context, args []string, e *Env) error {
	fs := newFlags("sealed verify", e)
	var c commonFlags
	c.register(fs)
	var deployment, evidence, live, api, expectCustomer, expectApps, reportOut, collateralCache string
	var maxAge, liveTimeout time.Duration
	var allowSim, insecureTLS, livePrivate bool
	fs.StringVar(&deployment, "deployment", "", "0x deploymentId, or a dep_ alias the platform api resolves (required)")
	fs.StringVar(&evidence, "evidence", "", "sealed-evidence/v1 file (default: downloaded from --api when --live is not given)")
	fs.StringVar(&live, "live", "", "attest URL to check live (fresh nonce, TLS key binding)")
	fs.StringVar(&api, "api", "", "platform api URL, for dep_ aliases and evidence downloads (SEALED_PLATFORM_API)")
	fs.StringVar(&expectCustomer, "expect-customer", "", "fail unless the deployment belongs to this wallet")
	fs.StringVar(&expectApps, "expect-apps", "", "comma-separated app ids that must be in the stack")
	fs.StringVar(&reportOut, "report", "", "also write the JSON report to this file")
	fs.StringVar(&collateralCache, "collateral-cache", "", "directory for cached Intel PCS collateral (default the user cache dir)")
	fs.DurationVar(&maxAge, "max-age", 0, "fail when the evidence is older than this (for example 26h)")
	fs.DurationVar(&liveTimeout, "live-timeout", 30*time.Second, "timeout of the live /attest round trip")
	fs.BoolVar(&allowSim, "dev-allow-simulated", false, "DEV ONLY (SEALED_DEV_SIM=1): accept dev simulator quotes; reports say simulated")
	fs.BoolVar(&insecureTLS, "dev-insecure-live-tls", false, "DEV ONLY (SEALED_DEV_SIM=1): skip WebPKI checks of the attest certificate (the key binding is still checked)")
	fs.BoolVar(&livePrivate, "dev-live-allow-private", false, "DEV ONLY (SEALED_DEV_SIM=1): allow loopback and private attest addresses")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 || deployment == "" {
		return usagef("usage: sealed verify --deployment <0x id | dep_ alias> [--evidence <file>] [--live <attest url>] [--json]")
	}
	if (allowSim || insecureTLS || livePrivate) && e.getenv("SEALED_DEV_SIM") != "1" {
		return usagef("the --dev-* flags need SEALED_DEV_SIM=1 and are never valid for a production check")
	}
	if api == "" {
		api = e.getenv("SEALED_PLATFORM_API")
	}
	s, err := c.settings(e)
	if err != nil {
		return err
	}
	if s.Derived {
		// A deployments file for another chain is enough: its chain id and registries are what every check uses.
		e.errorf("Checking on chain %d (%s) with the registries of the deployments file, through %s.\n", s.ChainID, s.Defaults.Chain.Name, chain.RedactURL(s.RPCURL))
	}

	// The deployment to check.
	var id [32]byte
	switch {
	case strings.HasPrefix(deployment, "0x"):
		if id, err = registry.ParseHash32(strings.ToLower(deployment)); err != nil {
			return usagef("--deployment: %s", err)
		}
	case aliasRe.MatchString(deployment):
		if api == "" {
			return usagef("--deployment %s is an alias: pass --api <platform api> to resolve it, or the full 0x deploymentId", deployment)
		}
		if id, err = (&apiResolver{base: api, http: e.httpClient()}).Resolve(ctx, deployment); err != nil {
			return err
		}
		e.errorf("%s resolves to 0x%x (checked against the chain below)\n", deployment, id)
	default:
		return usagef("--deployment must be a 0x deploymentId or a dep_ alias")
	}
	idHex := fmt.Sprintf("0x%x", id)

	var evidenceRaw []byte
	switch {
	case evidence != "":
		if evidenceRaw, err = os.ReadFile(evidence); err != nil {
			return err
		}
	case live == "":
		if api == "" {
			return usagef("pass --evidence <file>, --live <attest url>, or --api to download the evidence")
		}
		if evidenceRaw, err = fetchEvidence(ctx, e.httpClient(), api, idHex, e.getenv("SEALED_API_KEY")); err != nil {
			return err
		}
	}

	if collateralCache == "" {
		if dir, err := os.UserCacheDir(); err == nil {
			collateralCache = filepath.Join(dir, "sealed", "pcs")
		}
	}
	quotes, err := newQuoteVerifier(s.DefaultsRaw, allowSim, collateralCache)
	if err != nil {
		return err
	}
	reader, err := e.chain(ctx, s)
	if err != nil {
		return err
	}
	var chainReader verify.ChainReader = reader
	if rc, ok := reader.(*registry.Client); ok {
		chainReader = rc.Chain() // pins every read of a verification to one block
	}
	deps := verify.Deps{Quotes: quotes, Chain: chainReader, Composer: &bundles.Composer{Fetcher: c.fetcher(e, s)}, Now: e.now}
	opts := verify.Options{ChainID: s.ChainID, RequireOnchainRecord: true, MaxEvidenceAge: maxAge, ExpectedDeploymentID: &id,
		AcceptSimulated: allowSim}
	if expectCustomer != "" {
		if !common.IsHexAddress(expectCustomer) {
			return usagef("--expect-customer is not an address")
		}
		a := common.HexToAddress(expectCustomer)
		opts.ExpectedCustomer = &a
	}
	for _, a := range strings.Split(expectApps, ",") {
		if a = strings.TrimSpace(a); a != "" {
			opts.ExpectedAppIDs = append(opts.ExpectedAppIDs, a)
		}
	}

	type named struct {
		name string
		rep  *verify.Report
	}
	var reports []named
	if evidenceRaw != nil {
		rep, err := verify.VerifyEvidenceJSON(ctx, evidenceRaw, deps, opts)
		if err != nil {
			return err
		}
		reports = append(reports, named{"evidence", rep})
	}
	if live != "" {
		rep, err := verify.VerifyLive(ctx, live, deps, verify.LiveOptions{
			Options: opts, Timeout: liveTimeout, InsecureSkipTLSVerify: insecureTLS, AllowPrivateAddresses: livePrivate,
		})
		if err != nil {
			return err
		}
		reports = append(reports, named{"live", rep})
	}

	ok := true
	doc := map[string]any{"deploymentId": idHex}
	for _, r := range reports {
		ok = ok && r.rep.OK
		doc[r.name] = r.rep
	}
	doc["ok"] = ok
	if reportOut != "" {
		b, _ := json.MarshalIndent(doc, "", "  ")
		if err := os.WriteFile(reportOut, append(b, '\n'), 0o644); err != nil {
			return err
		}
	}
	if c.json {
		if err := writeJSON(e.Stdout, doc); err != nil {
			return err
		}
	} else {
		for i, r := range reports {
			if i > 0 {
				e.printf("\n")
			}
			e.printf("== %s check of %s\n", r.name, idHex)
			if err := r.rep.WriteText(e.Stdout); err != nil {
				return err
			}
			if r.rep.Simulated {
				e.printf("SIMULATED: this quote came from the dev simulator and proves nothing about real hardware.\n")
			}
		}
		if ok {
			e.printf("\nOK: every check passed against Tempo chain %d at the blocks shown.\n", s.ChainID)
		}
	}
	if !ok {
		var failed []string
		for _, r := range reports {
			for _, f := range r.rep.Failed() {
				failed = append(failed, r.name+"/"+f)
			}
		}
		return &exitError{code: ExitFailed, msg: "verification failed: " + strings.Join(failed, ", ")}
	}
	return nil
}
