// Command key-broker serves the Sealed key broker on Cloud Run in the customer's project (spec 5.7, INTERFACES.md
// section 9). Everything it trusts is set by the customer at bootstrap through flags or environment variables: the
// customer address, the Tempo RPC and registry addresses, the catalog release base, the KMS key and the project.
// The environment names are exactly the ones the bootstrap Terraform sets (infra/terraform/customer-bootstrap,
// key_broker.tf); any other SEALED_* or TEMPO_* variable stops the production build, so a misspelled or renamed
// setting can never fall back silently to a default.
//
// The production image is built without build tags. Simulated quotes and the local fakes of Secret Manager, KMS and
// Cloud Logging exist only in a dev build (-tags sealeddev) and only with SEALED_DEV_SIM=1.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"runtime/debug"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common"

	keybroker "github.com/sealed-dev/sealed/key-broker"
	"github.com/sealed-dev/sealed/key-broker/gcp"
	"github.com/sealed-dev/sealed/verifier/attest"
	"github.com/sealed-dev/sealed/verifier/chain"
)

// devSimEnv must be "1" for any dev option of a dev build.
const devSimEnv = "SEALED_DEV_SIM"

// Mainnet defaults (contracts/deployments/tempo-mainnet.json, config/defaults.yaml; a test checks they agree).
const (
	defaultChainID            = 4217
	defaultRPC                = "https://rpc.tempo.xyz"
	defaultPlatformRegistry   = "0x18AB956ea44757587896dfD25632FB3e89F7002d"
	defaultAppRegistry        = "0x88C91CAcB74cCeC3b8A1823977EEC42aE3b93b43"
	defaultDeploymentRegistry = "0x254eFB9d1809A95Ec6d233cC57b3a10849bd2C8E"
	defaultFeeSplitter        = "0x3D288c0756c3F26Da0f41257D688bAB3dB3d94AD"
	defaultFeeToken           = "0x20C000000000000000000000b9537d11c60E8b50"
	defaultReleaseAssetBase   = "https://github.com/sealedtempo/sealed/releases/download"
	defaultRegion             = "us-central1"
	// defaultMemoryLimit is the Go soft memory limit when GOMEMLIMIT is not set, below Cloud Run's 512 MiB (D-066).
	defaultMemoryLimit = 384 << 20
)

// bootstrapEnv are the variables the customer bootstrap sets (ws/cli infra/terraform/customer-bootstrap/key_broker.tf).
var bootstrapEnv = []string{
	"SEALED_CUSTOMER_ADDRESS", "SEALED_GCP_PROJECT", "SEALED_GCP_PROJECT_NUMBER", "SEALED_SECRET_PREFIX",
	"SEALED_KMS_KEY_VERSION", "TEMPO_RPC_URL", "TEMPO_CHAIN_ID", "SEALED_PLATFORM_REGISTRY", "SEALED_APP_REGISTRY",
	"SEALED_DEPLOYMENT_REGISTRY", "SEALED_RELEASE_ASSET_BASE",
}

// optionalEnv are tunables with safe defaults that the bootstrap does not set.
var optionalEnv = []string{
	"SEALED_GCP_REGION", "SEALED_DECISION_LOG_ID", "SEALED_TCB_ALLOWED", "SEALED_TCB_ADVISORIES", "SEALED_MAX_IN_FLIGHT",
	"SEALED_NONCE_CAPACITY", "SEALED_FEE_SPLITTER", "SEALED_FEE_TOKEN", "SEALED_SECRETMANAGER_ENDPOINT",
	"SEALED_KMS_ENDPOINT", "SEALED_LOGGING_ENDPOINT", devSimEnv,
}

// renamedEnv are the names an earlier broker read; the bootstrap never set them.
var renamedEnv = map[string]string{
	"SEALED_CUSTOMER":  "SEALED_CUSTOMER_ADDRESS",
	"SEALED_TEMPO_RPC": "TEMPO_RPC_URL",
	"SEALED_CHAIN_ID":  "TEMPO_CHAIN_ID",
	"SEALED_KMS_KEY":   "SEALED_KMS_KEY_VERSION (the full cryptoKeyVersions name)",
}

// checkEnv refuses SEALED_* and TEMPO_* variables outside the contract. A dev build with SEALED_DEV_SIM=1 only warns,
// so a developer's shell environment does not stop local runs.
func checkEnv(env map[string]string) (warnings []string, err error) {
	var bad []string
	for k := range env {
		if !strings.HasPrefix(k, "SEALED_") && !strings.HasPrefix(k, "TEMPO_") {
			continue
		}
		if slices.Contains(bootstrapEnv, k) || slices.Contains(optionalEnv, k) {
			continue
		}
		if to, ok := renamedEnv[k]; ok {
			bad = append(bad, fmt.Sprintf("%s is not read; the bootstrap sets %s", k, to))
		} else {
			bad = append(bad, fmt.Sprintf("%s is not a key broker setting", k))
		}
	}
	if len(bad) == 0 {
		return nil, nil
	}
	sort.Strings(bad)
	if devBuild && env[devSimEnv] == "1" {
		return bad, nil
	}
	return nil, fmt.Errorf("unknown environment: %s", strings.Join(bad, "; "))
}

var (
	projectNumberRe = regexp.MustCompile(`^[0-9]{1,20}$`)
	keyVersionRe    = regexp.MustCompile(`^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+/cryptoKeyVersions/[1-9][0-9]*$`)
)

// checkEndpoint requires https, or http to a loopback address (local fakes and nodes): whoever answers the RPC
// decides every approval, and the Google API endpoints receive the broker's OAuth token (F8).
func checkEndpoint(name, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return fmt.Errorf("%s %s is not an http(s) URL without credentials", name, chain.RedactURL(raw))
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
			return nil
		}
		return fmt.Errorf("%s %s must be https (plain http only to a loopback address)", name, chain.RedactURL(raw))
	}
	return fmt.Errorf("%s %s is not an http(s) URL", name, chain.RedactURL(raw))
}

type config struct {
	Listen        string
	Customer      common.Address
	ChainID       uint64
	RPCURL        string
	Addrs         chain.Addresses
	FeeSplitter   common.Address
	FeeToken      common.Address
	AllowedImages [][32]byte
	ReleaseBase   string
	Project       string
	ProjectNumber string
	Region        string // empty: the metadata server's region on Cloud Run, else defaultRegion
	KMSKey        string // full cryptoKeyVersion name
	LogID         string
	TCBPolicy     attest.TCBPolicy
	MaxInFlight   int
	NonceCapacity int
	NonceJournal  string
	ClientRate    float64
	MaxHeadAge    time.Duration
	CollateralTTL time.Duration
	// API endpoint overrides (for example restricted.googleapis.com VIPs); empty means the public endpoints.
	SecretManagerEndpoint, KMSEndpoint, LoggingEndpoint string
	// envWarnings are unknown variables a dev build tolerated.
	envWarnings []string

	dev devOptions
}

// devOptions are only registered in dev builds (dev_on.go).
type devOptions struct {
	AllowSimulated bool
	SecretsFile    string
	KMSKeyFile     string
	DecisionLog    string
}

func (d devOptions) any() bool {
	return d.AllowSimulated || d.SecretsFile != "" || d.KMSKeyFile != "" || d.DecisionLog != ""
}

func main() {
	log := newLogger(os.Stdout)
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(defaultMemoryLimit)
	}
	if err := run(context.Background(), os.Args[1:], environ(os.Environ()), log); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		log.Error("key-broker", "err", err)
		os.Exit(1)
	}
}

// newLogger writes JSON lines with Cloud Logging's field names, so Cloud Run parses severity and message.
func newLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if len(groups) > 0 {
			return a
		}
		switch a.Key {
		case slog.LevelKey:
			lvl, _ := a.Value.Any().(slog.Level)
			sev := map[slog.Level]string{slog.LevelDebug: "DEBUG", slog.LevelInfo: "INFO", slog.LevelWarn: "WARNING", slog.LevelError: "ERROR"}[lvl]
			if sev == "" {
				sev = "DEFAULT"
			}
			return slog.String("severity", sev)
		case slog.MessageKey:
			return slog.String("message", a.Value.String())
		}
		return a
	}}))
}

// environ turns os.Environ() into a map.
func environ(kv []string) map[string]string {
	m := map[string]string{}
	for _, e := range kv {
		k, v, _ := strings.Cut(e, "=")
		m[k] = v
	}
	return m
}

func envOr(env map[string]string, key, def string) string {
	if v := env[key]; v != "" {
		return v
	}
	return def
}

func loadConfig(args []string, env map[string]string, out io.Writer) (*config, error) {
	fs := flag.NewFlagSet("key-broker", flag.ContinueOnError)
	fs.SetOutput(out)
	c := &config{}
	port := envOr(env, "PORT", "8080")
	var customer, platformReg, appReg, depReg, feeSplitter, feeToken, allowedImages, kmsKey, tcbAllowed, tcbAdvisories string
	var chainID, maxInFlight, nonceCap string
	fs.StringVar(&c.Listen, "listen", ":"+port, "listen address ($PORT, set by Cloud Run)")
	fs.StringVar(&customer, "customer", env["SEALED_CUSTOMER_ADDRESS"], "the customer's Tempo address ($SEALED_CUSTOMER_ADDRESS, required)")
	fs.StringVar(&c.RPCURL, "tempo-rpc", envOr(env, "TEMPO_RPC_URL", defaultRPC), "Tempo JSON-RPC URL, https ($TEMPO_RPC_URL)")
	fs.StringVar(&chainID, "chain-id", envOr(env, "TEMPO_CHAIN_ID", strconv.Itoa(defaultChainID)), "Tempo chain id; 4217 outside dev builds ($TEMPO_CHAIN_ID)")
	fs.StringVar(&platformReg, "platform-registry", envOr(env, "SEALED_PLATFORM_REGISTRY", defaultPlatformRegistry), "PlatformRegistry address ($SEALED_PLATFORM_REGISTRY)")
	fs.StringVar(&appReg, "app-registry", envOr(env, "SEALED_APP_REGISTRY", defaultAppRegistry), "AppRegistry address ($SEALED_APP_REGISTRY)")
	fs.StringVar(&depReg, "deployment-registry", envOr(env, "SEALED_DEPLOYMENT_REGISTRY", defaultDeploymentRegistry), "DeploymentRegistry address ($SEALED_DEPLOYMENT_REGISTRY)")
	fs.StringVar(&feeSplitter, "fee-splitter", envOr(env, "SEALED_FEE_SPLITTER", defaultFeeSplitter), "FeeSplitter address config.contracts.feeSplitter must name ($SEALED_FEE_SPLITTER)")
	fs.StringVar(&feeToken, "fee-token", envOr(env, "SEALED_FEE_TOKEN", defaultFeeToken), "fee token config.feeToken must name ($SEALED_FEE_TOKEN)")
	fs.StringVar(&allowedImages, "allowed-images", "", "if set, the only imageIds (comma separated) released to, on top of PlatformRegistry approval")
	fs.StringVar(&c.ReleaseBase, "release-asset-base", envOr(env, "SEALED_RELEASE_ASSET_BASE", defaultReleaseAssetBase), "catalog release asset base URL ($SEALED_RELEASE_ASSET_BASE)")
	fs.StringVar(&c.Project, "project", env["SEALED_GCP_PROJECT"], "customer GCP project id for Secret Manager and Cloud Logging ($SEALED_GCP_PROJECT)")
	fs.StringVar(&c.ProjectNumber, "project-number", env["SEALED_GCP_PROJECT_NUMBER"], "customer GCP project number, recorded only ($SEALED_GCP_PROJECT_NUMBER)")
	fs.StringVar(&c.Region, "region", env["SEALED_GCP_REGION"], "Cloud Run region for the log resource; default the metadata server's ($SEALED_GCP_REGION)")
	fs.StringVar(&kmsKey, "kms-key-version", env["SEALED_KMS_KEY_VERSION"], "Cloud KMS HMAC_SHA256 key version: projects/../cryptoKeys/../cryptoKeyVersions/N ($SEALED_KMS_KEY_VERSION)")
	fs.StringVar(&c.LogID, "decision-log-id", envOr(env, "SEALED_DECISION_LOG_ID", gcp.DefaultDecisionLogID), "Cloud Logging log id for decisions ($SEALED_DECISION_LOG_ID)")
	fs.StringVar(&tcbAllowed, "tcb-allowed", envOr(env, "SEALED_TCB_ALLOWED", "UpToDate,SWHardeningNeeded"), "allowed Intel TCB statuses ($SEALED_TCB_ALLOWED)")
	fs.StringVar(&tcbAdvisories, "tcb-advisories", env["SEALED_TCB_ADVISORIES"], "if set, the only Intel advisory ids accepted on a non-UpToDate level ($SEALED_TCB_ADVISORIES)")
	fs.StringVar(&maxInFlight, "max-in-flight", envOr(env, "SEALED_MAX_IN_FLIGHT", strconv.Itoa(keybroker.DefaultMaxInFlight)), "concurrent releases before 429 ($SEALED_MAX_IN_FLIGHT)")
	fs.StringVar(&nonceCap, "nonce-capacity", envOr(env, "SEALED_NONCE_CAPACITY", strconv.Itoa(keybroker.DefaultNonceCapacity)), "live nonces kept ($SEALED_NONCE_CAPACITY)")
	fs.StringVar(&c.NonceJournal, "nonce-journal", "", "file that keeps live nonces across restarts; only useful on durable storage")
	fs.Float64Var(&c.ClientRate, "client-rate", keybroker.DefaultClientRate, "release requests per second per client address (nonces: 4x); negative turns the limit off")
	fs.DurationVar(&c.MaxHeadAge, "chain-max-head-age", keybroker.DefaultMaxHeadAge, "oldest Tempo head block accepted, at most 5m (D-060)")
	fs.DurationVar(&c.CollateralTTL, "collateral-ttl", time.Hour, "Intel PCS collateral cache lifetime")
	c.SecretManagerEndpoint = env["SEALED_SECRETMANAGER_ENDPOINT"]
	c.KMSEndpoint = env["SEALED_KMS_ENDPOINT"]
	c.LoggingEndpoint = env["SEALED_LOGGING_ENDPOINT"]
	registerDevFlags(fs, &c.dev)
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected arguments %q", fs.Args())
	}
	devRun := devBuild && env[devSimEnv] == "1"
	var err error
	if c.envWarnings, err = checkEnv(env); err != nil {
		return nil, err
	}

	if c.dev.any() && env[devSimEnv] != "1" {
		return nil, fmt.Errorf("dev options need %s=1", devSimEnv)
	}
	if !common.IsHexAddress(customer) || common.HexToAddress(customer) == (common.Address{}) {
		return nil, fmt.Errorf("--customer (SEALED_CUSTOMER_ADDRESS) must be the customer's Tempo address, got %q", customer)
	}
	c.Customer = common.HexToAddress(customer)
	if c.ChainID, err = strconv.ParseUint(chainID, 10, 64); err != nil || c.ChainID == 0 {
		return nil, fmt.Errorf("--chain-id (TEMPO_CHAIN_ID) %q is not a chain id", chainID)
	}
	if c.ChainID != keybroker.MainnetChainID && !devRun {
		return nil, fmt.Errorf("--chain-id (TEMPO_CHAIN_ID) %d: this key broker serves Tempo mainnet (4217); other chains need a dev build with %s=1 (D-060)", c.ChainID, devSimEnv)
	}
	for _, a := range []struct {
		name, val string
		dst       *common.Address
	}{{"platform-registry", platformReg, &c.Addrs.PlatformRegistry}, {"app-registry", appReg, &c.Addrs.AppRegistry},
		{"deployment-registry", depReg, &c.Addrs.DeploymentRegistry}, {"fee-splitter", feeSplitter, &c.FeeSplitter}, {"fee-token", feeToken, &c.FeeToken}} {
		if !common.IsHexAddress(a.val) || common.HexToAddress(a.val) == (common.Address{}) {
			return nil, fmt.Errorf("--%s %q is not an address", a.name, a.val)
		}
		*a.dst = common.HexToAddress(a.val)
	}
	for _, id := range splitList(allowedImages) {
		b := common.FromHex(id)
		if !strings.HasPrefix(id, "0x") || len(b) != 32 {
			return nil, fmt.Errorf("--allowed-images: %q is not a 32-byte imageId", id)
		}
		c.AllowedImages = append(c.AllowedImages, [32]byte(b))
	}
	if err := checkEndpoint("--tempo-rpc (TEMPO_RPC_URL)", c.RPCURL); err != nil {
		return nil, err
	}
	for _, e := range []struct{ name, val string }{
		{"SEALED_SECRETMANAGER_ENDPOINT", c.SecretManagerEndpoint}, {"SEALED_KMS_ENDPOINT", c.KMSEndpoint}, {"SEALED_LOGGING_ENDPOINT", c.LoggingEndpoint},
	} {
		if e.val != "" {
			if err := checkEndpoint(e.name, e.val); err != nil {
				return nil, err
			}
		}
	}
	if _, err := keybroker.BundleURL(c.ReleaseBase, "probe-app", "0"); err != nil {
		return nil, fmt.Errorf("--release-asset-base: %w", err)
	}
	if !strings.HasPrefix(c.ReleaseBase, "https://") && !devRun {
		return nil, fmt.Errorf("--release-asset-base must be https")
	}
	if p := env["SEALED_SECRET_PREFIX"]; p != "" && p != keybroker.SecretPrefix {
		return nil, fmt.Errorf("SEALED_SECRET_PREFIX %q: the broker reads secrets named %s* only (its IAM condition)", p, keybroker.SecretPrefix)
	}
	if c.ProjectNumber != "" && !projectNumberRe.MatchString(c.ProjectNumber) {
		return nil, fmt.Errorf("--project-number (SEALED_GCP_PROJECT_NUMBER) %q is not a project number", c.ProjectNumber)
	}
	c.TCBPolicy = attest.TCBPolicy{AllowedStatuses: splitList(tcbAllowed), AllowedAdvisoryIDs: splitList(tcbAdvisories)}
	if err := c.TCBPolicy.Validate(); err != nil {
		return nil, err
	}
	if c.MaxInFlight, err = strconv.Atoi(maxInFlight); err != nil || c.MaxInFlight < 1 {
		return nil, fmt.Errorf("--max-in-flight %q", maxInFlight)
	}
	if c.NonceCapacity, err = strconv.Atoi(nonceCap); err != nil || c.NonceCapacity < 16 {
		return nil, fmt.Errorf("--nonce-capacity %q (at least 16)", nonceCap)
	}
	if c.MaxHeadAge < time.Second || c.MaxHeadAge > keybroker.MaxMaxHeadAge {
		return nil, fmt.Errorf("--chain-max-head-age %s must be between 1s and %s", c.MaxHeadAge, keybroker.MaxMaxHeadAge)
	}
	needProject := c.dev.SecretsFile == "" || c.dev.DecisionLog == ""
	if needProject && c.Project == "" {
		return nil, errors.New("--project (SEALED_GCP_PROJECT) is required for Secret Manager and Cloud Logging")
	}
	if c.dev.KMSKeyFile == "" {
		if !keyVersionRe.MatchString(kmsKey) {
			return nil, fmt.Errorf("--kms-key-version (SEALED_KMS_KEY_VERSION) %q must be a cryptoKeyVersions resource name", kmsKey)
		}
		c.KMSKey = kmsKey
	}
	return c, nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// app is the wired broker.
type app struct {
	broker  *keybroker.Broker
	handler http.Handler
	closers []func() error
}

func newApp(ctx context.Context, c *config, getenv func(string) string, log *slog.Logger) (*app, error) {
	a := &app{}
	allowSim := devBuild && c.dev.AllowSimulated && getenv(devSimEnv) == "1"
	tokens := &gcp.MetadataTokenSource{Host: getenv("GCE_METADATA_HOST")}
	for _, w := range c.envWarnings {
		log.Warn("DEV MODE: environment variable ignored", "detail", w)
	}

	// Collateral fetches are bounded and probed, so a PCS outage answers 503 (F6); the PCK gate keeps made-up
	// platforms from triggering any fetch.
	getter, err := attest.NewCachingGetter(attest.CacheOptions{TTL: c.CollateralTTL, FetchTimeout: 20 * time.Second})
	if err != nil {
		return nil, err
	}
	inner, err := attest.NewVerifier(attest.VerifierOptions{AllowSimulated: allowSim, Getter: keybroker.CollateralProbe{Inner: getter}, TCBPolicy: c.TCBPolicy})
	if err != nil {
		return nil, err
	}
	quotes, err := keybroker.NewPCKGate(inner)
	if err != nil {
		return nil, err
	}
	rpcChain, reader, err := keybroker.DialChain(ctx, c.RPCURL, c.Addrs)
	if err != nil {
		return nil, err
	}
	bundles, err := keybroker.NewHTTPBundleSource(keybroker.HTTPBundleSourceOptions{Base: c.ReleaseBase})
	if err != nil {
		return nil, err
	}
	var nonces *keybroker.NonceStore
	if c.NonceJournal != "" {
		if nonces, err = keybroker.OpenNonceStore(keybroker.NonceOptions{Capacity: c.NonceCapacity, Journal: c.NonceJournal}); err != nil {
			return nil, err
		}
		a.closers = append(a.closers, nonces.Close)
	} else {
		nonces = keybroker.NewNonceStore(keybroker.NonceOptions{Capacity: c.NonceCapacity})
	}

	var secrets keybroker.SecretStore
	if c.dev.SecretsFile != "" {
		if secrets, err = keybroker.LoadSecretsFile(c.dev.SecretsFile); err != nil {
			return nil, err
		}
		log.Warn("DEV MODE: secrets come from a local file, not Secret Manager", "file", c.dev.SecretsFile)
	} else {
		sm, err := gcp.NewSecretManager(c.Project, tokens)
		if err != nil {
			return nil, err
		}
		sm.Endpoint = c.SecretManagerEndpoint
		secrets = sm
	}
	var mac keybroker.MACSigner
	if c.dev.KMSKeyFile != "" {
		if mac, err = keybroker.LoadOrCreateFileHMAC(c.dev.KMSKeyFile); err != nil {
			return nil, err
		}
		log.Warn("DEV MODE: diskKey and signerSeed come from a file-backed HMAC key, not Cloud KMS", "file", c.dev.KMSKeyFile)
	} else {
		k, err := gcp.NewKMSMAC(c.KMSKey, tokens)
		if err != nil {
			return nil, err
		}
		k.Endpoint = c.KMSEndpoint
		mac = k
	}
	var dlog keybroker.DecisionLog
	if c.dev.DecisionLog != "" {
		f, err := keybroker.OpenJSONLinesLog(c.dev.DecisionLog)
		if err != nil {
			return nil, err
		}
		a.closers = append(a.closers, f.Close)
		dlog = f
		log.Warn("DEV MODE: decisions go to a local JSON-lines file, not Cloud Logging", "file", c.dev.DecisionLog)
	} else {
		region := c.Region
		if region == "" && getenv("K_SERVICE") != "" {
			rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			region, err = gcp.MetadataRegion(rctx, getenv("GCE_METADATA_HOST"), nil)
			cancel()
			if err != nil {
				log.Warn("could not read the region from the metadata server; the log resource uses the default", "err", err, "region", defaultRegion)
			}
		}
		if region == "" {
			region = defaultRegion
		}
		c.Region = region
		sink, err := gcp.NewLoggingSink(c.Project, c.LogID, gcp.CloudRunResource(c.Project, region, getenv), tokens)
		if err != nil {
			return nil, err
		}
		sink.Endpoint = c.LoggingEndpoint
		dlog = sink
	}
	if allowSim {
		log.Warn("DEV MODE: simulated quotes are accepted; every decision is flagged simulated", "env", devSimEnv)
	}

	a.broker, err = keybroker.New(keybroker.Config{Customer: c.Customer, ChainID: c.ChainID, Contracts: c.Addrs, FeeSplitter: c.FeeSplitter,
		FeeToken: c.FeeToken, AllowedImages: c.AllowedImages, MaxHeadAge: c.MaxHeadAge, AllowSimulated: allowSim},
		keybroker.Deps{Nonces: nonces, Quotes: quotes, Chain: rpcChain, Bundles: bundles, Secrets: secrets, MAC: mac, Log: dlog, OpLog: log})
	if err != nil {
		return nil, err
	}
	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	switch id, err := reader.ChainID(checkCtx); {
	case err != nil:
		log.Warn("Tempo RPC not reachable at startup; releases answer 503 until it is", "err", err)
	case id != c.ChainID:
		return nil, fmt.Errorf("the Tempo RPC %s serves chain %d, expected %d", chain.RedactURL(c.RPCURL), id, c.ChainID)
	}
	a.handler = a.broker.Handler(keybroker.ServerOptions{MaxInFlight: c.MaxInFlight, ClientRate: c.ClientRate})
	return a, nil
}

func run(ctx context.Context, args []string, env map[string]string, log *slog.Logger) error {
	c, err := loadConfig(args, env, os.Stderr)
	if err != nil {
		return err
	}
	getenv := func(k string) string { return env[k] }
	a, err := newApp(ctx, c, getenv, log)
	if err != nil {
		return err
	}
	defer func() {
		for _, f := range a.closers {
			_ = f()
		}
	}()
	hs := &http.Server{
		Addr:              c.Listen,
		Handler:           a.handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      3 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    32 << 10,
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- hs.ListenAndServe() }()
	log.Info("key broker listening", "addr", c.Listen, "customer", strings.ToLower(c.Customer.Hex()), "chainId", c.ChainID,
		"rpc", chain.RedactURL(c.RPCURL), "releaseAssetBase", c.ReleaseBase, "kmsKey", c.KMSKey, "project", c.Project,
		"projectNumber", c.ProjectNumber, "region", c.Region, "registries", c.Addrs, "feeSplitter", c.FeeSplitter, "feeToken", c.FeeToken,
		"tcbAllowed", c.TCBPolicy.AllowedStatuses, "maxHeadAge", c.MaxHeadAge.String(), "devBuild", devBuild,
		"allowSimulated", a.broker.Config().AllowSimulated)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err = hs.Shutdown(shutdown)
	if cerr := a.broker.Close(shutdown); cerr != nil {
		log.Warn("decision log not flushed before shutdown", "err", cerr)
	}
	return err
}
