// Command key-broker serves the Sealed key broker on Cloud Run in the customer's project (spec 5.7, INTERFACES.md
// section 9). Everything it trusts is set by the customer at bootstrap through flags or environment variables: the
// customer address, the Tempo RPC and registry addresses, the catalog release base, the KMS key and the project.
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
	"net/http"
	"net/url"
	"os"
	"os/signal"
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
	defaultReleaseAssetBase   = "https://github.com/sealedtempo/sealed/releases/download"
	defaultRegion             = "us-central1"
)

type config struct {
	Listen        string
	Customer      common.Address
	ChainID       uint64
	RPCURL        string
	Addrs         chain.Addresses
	ReleaseBase   string
	Project       string
	Region        string
	KMSKey        string // full cryptoKeyVersion name
	LogID         string
	TCBPolicy     attest.TCBPolicy
	MaxInFlight   int
	NonceCapacity int
	CollateralTTL time.Duration
	// API endpoint overrides (for example restricted.googleapis.com VIPs); empty means the public endpoints.
	SecretManagerEndpoint, KMSEndpoint, LoggingEndpoint string

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
	if err := run(context.Background(), os.Args[1:], os.Getenv, log); err != nil {
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

func envOr(getenv func(string) string, key, def string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return def
}

func loadConfig(args []string, getenv func(string) string, out io.Writer) (*config, error) {
	fs := flag.NewFlagSet("key-broker", flag.ContinueOnError)
	fs.SetOutput(out)
	c := &config{}
	port := envOr(getenv, "PORT", "8080")
	var customer, platformReg, appReg, depReg, kmsKey, kmsVersion, tcbAllowed, tcbAdvisories string
	var chainID, maxInFlight, nonceCap string
	fs.StringVar(&c.Listen, "listen", ":"+port, "listen address ($PORT, set by Cloud Run)")
	// Environment names are the ones infra/terraform/customer-bootstrap sets on the Cloud Run service.
	fs.StringVar(&customer, "customer", getenv("SEALED_CUSTOMER_ADDRESS"), "the customer's Tempo address ($SEALED_CUSTOMER_ADDRESS, required)")
	fs.StringVar(&c.RPCURL, "tempo-rpc", envOr(getenv, "TEMPO_RPC_URL", defaultRPC), "Tempo JSON-RPC URL ($TEMPO_RPC_URL)")
	fs.StringVar(&chainID, "chain-id", envOr(getenv, "TEMPO_CHAIN_ID", strconv.Itoa(defaultChainID)), "Tempo chain id ($TEMPO_CHAIN_ID)")
	fs.StringVar(&platformReg, "platform-registry", envOr(getenv, "SEALED_PLATFORM_REGISTRY", defaultPlatformRegistry), "PlatformRegistry address ($SEALED_PLATFORM_REGISTRY)")
	fs.StringVar(&appReg, "app-registry", envOr(getenv, "SEALED_APP_REGISTRY", defaultAppRegistry), "AppRegistry address ($SEALED_APP_REGISTRY)")
	fs.StringVar(&depReg, "deployment-registry", envOr(getenv, "SEALED_DEPLOYMENT_REGISTRY", defaultDeploymentRegistry), "DeploymentRegistry address ($SEALED_DEPLOYMENT_REGISTRY)")
	fs.StringVar(&c.ReleaseBase, "release-asset-base", envOr(getenv, "SEALED_RELEASE_ASSET_BASE", defaultReleaseAssetBase), "catalog release asset base URL ($SEALED_RELEASE_ASSET_BASE)")
	fs.StringVar(&c.Project, "project", getenv("SEALED_GCP_PROJECT"), "customer GCP project id for Secret Manager and Cloud Logging ($SEALED_GCP_PROJECT)")
	fs.StringVar(&c.Region, "region", envOr(getenv, "SEALED_GCP_REGION", defaultRegion), "Cloud Run region, for the log resource ($SEALED_GCP_REGION)")
	fs.StringVar(&kmsKey, "kms-key", getenv("SEALED_KMS_KEY_VERSION"), "Cloud KMS HMAC_SHA256 key: a cryptoKeyVersions resource name, or a cryptoKeys name with --kms-key-version ($SEALED_KMS_KEY_VERSION, which the bootstrap pins to cryptoKeyVersions/1)")
	fs.StringVar(&kmsVersion, "kms-key-version", "1", "key version when --kms-key names a cryptoKey")
	fs.StringVar(&c.LogID, "decision-log-id", envOr(getenv, "SEALED_DECISION_LOG_ID", gcp.DefaultDecisionLogID), "Cloud Logging log id for decisions ($SEALED_DECISION_LOG_ID)")
	fs.StringVar(&tcbAllowed, "tcb-allowed", envOr(getenv, "SEALED_TCB_ALLOWED", "UpToDate,SWHardeningNeeded"), "allowed Intel TCB statuses ($SEALED_TCB_ALLOWED)")
	fs.StringVar(&tcbAdvisories, "tcb-advisories", getenv("SEALED_TCB_ADVISORIES"), "if set, the only Intel advisory ids accepted on a non-UpToDate level ($SEALED_TCB_ADVISORIES)")
	fs.StringVar(&maxInFlight, "max-in-flight", envOr(getenv, "SEALED_MAX_IN_FLIGHT", "8"), "concurrent releases before 429 ($SEALED_MAX_IN_FLIGHT)")
	fs.StringVar(&nonceCap, "nonce-capacity", envOr(getenv, "SEALED_NONCE_CAPACITY", strconv.Itoa(keybroker.DefaultNonceCapacity)), "live nonces kept ($SEALED_NONCE_CAPACITY)")
	fs.DurationVar(&c.CollateralTTL, "collateral-ttl", time.Hour, "Intel PCS collateral cache lifetime")
	c.SecretManagerEndpoint = getenv("SEALED_SECRETMANAGER_ENDPOINT")
	c.KMSEndpoint = getenv("SEALED_KMS_ENDPOINT")
	c.LoggingEndpoint = getenv("SEALED_LOGGING_ENDPOINT")
	registerDevFlags(fs, &c.dev)
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected arguments %q", fs.Args())
	}

	// The bootstrap names the Secret Manager prefix its IAM condition allows; the broker reads only that prefix.
	if p := getenv("SEALED_SECRET_PREFIX"); p != "" && p != keybroker.SecretPrefix {
		return nil, fmt.Errorf("SEALED_SECRET_PREFIX %q: the key broker reads secrets named %s<app>-<NAME> only", p, keybroker.SecretPrefix)
	}
	if c.dev.any() && getenv(devSimEnv) != "1" {
		return nil, fmt.Errorf("dev options need %s=1", devSimEnv)
	}
	if !common.IsHexAddress(customer) || common.HexToAddress(customer) == (common.Address{}) {
		return nil, fmt.Errorf("--customer (SEALED_CUSTOMER_ADDRESS) must be the customer's Tempo address, got %q", customer)
	}
	c.Customer = common.HexToAddress(customer)
	var err error
	if c.ChainID, err = strconv.ParseUint(chainID, 10, 64); err != nil || c.ChainID == 0 {
		return nil, fmt.Errorf("--chain-id %q is not a chain id", chainID)
	}
	for _, a := range []struct {
		name, val string
		dst       *common.Address
	}{{"platform-registry", platformReg, &c.Addrs.PlatformRegistry}, {"app-registry", appReg, &c.Addrs.AppRegistry}, {"deployment-registry", depReg, &c.Addrs.DeploymentRegistry}} {
		if !common.IsHexAddress(a.val) {
			return nil, fmt.Errorf("--%s %q is not an address", a.name, a.val)
		}
		*a.dst = common.HexToAddress(a.val)
	}
	if u, err := url.Parse(c.RPCURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("--tempo-rpc %s is not an http(s) URL", chain.RedactURL(c.RPCURL))
	}
	if _, err := keybroker.BundleURL(c.ReleaseBase, "probe-app", "0"); err != nil {
		return nil, fmt.Errorf("--release-asset-base: %w", err)
	}
	if !strings.HasPrefix(c.ReleaseBase, "https://") && !(devBuild && getenv(devSimEnv) == "1") {
		return nil, fmt.Errorf("--release-asset-base must be https")
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
	needProject := c.dev.SecretsFile == "" || c.dev.DecisionLog == ""
	if needProject && c.Project == "" {
		return nil, errors.New("--project (SEALED_GCP_PROJECT) is required for Secret Manager and Cloud Logging")
	}
	if c.dev.KMSKeyFile == "" {
		if c.KMSKey, err = gcp.KMSKeyVersion(kmsKey, kmsVersion); err != nil {
			return nil, fmt.Errorf("--kms-key (SEALED_KMS_KEY_VERSION): %w", err)
		}
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

	getter, err := attest.NewCachingGetter(attest.CacheOptions{TTL: c.CollateralTTL})
	if err != nil {
		return nil, err
	}
	quotes, err := attest.NewVerifier(attest.VerifierOptions{AllowSimulated: allowSim, Getter: getter, TCBPolicy: c.TCBPolicy})
	if err != nil {
		return nil, err
	}
	reader, err := chain.Dial(ctx, c.RPCURL, c.Addrs)
	if err != nil {
		return nil, err
	}
	bundles, err := keybroker.NewHTTPBundleSource(keybroker.HTTPBundleSourceOptions{Base: c.ReleaseBase})
	if err != nil {
		return nil, err
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
		sink, err := gcp.NewLoggingSink(c.Project, c.LogID, gcp.CloudRunResource(c.Project, c.Region, getenv), tokens)
		if err != nil {
			return nil, err
		}
		sink.Endpoint = c.LoggingEndpoint
		dlog = sink
	}
	if allowSim {
		log.Warn("DEV MODE: simulated quotes are accepted; every decision is flagged simulated", "env", devSimEnv)
	}

	a.broker, err = keybroker.New(keybroker.Config{Customer: c.Customer, ChainID: c.ChainID, Contracts: c.Addrs, AllowSimulated: allowSim},
		keybroker.Deps{
			Nonces: keybroker.NewNonceStore(keybroker.NonceOptions{Capacity: c.NonceCapacity}),
			Quotes: quotes, Chain: keybroker.NewClientChain(reader), Bundles: bundles, Secrets: secrets, MAC: mac, Log: dlog, OpLog: log,
		})
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
	a.handler = a.broker.Handler(keybroker.ServerOptions{MaxInFlight: c.MaxInFlight})
	return a, nil
}

func run(ctx context.Context, args []string, getenv func(string) string, log *slog.Logger) error {
	c, err := loadConfig(args, getenv, os.Stderr)
	if err != nil {
		return err
	}
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
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- hs.ListenAndServe() }()
	log.Info("key broker listening", "addr", c.Listen, "customer", strings.ToLower(c.Customer.Hex()), "chainId", c.ChainID,
		"rpc", chain.RedactURL(c.RPCURL), "releaseAssetBase", c.ReleaseBase, "kmsKey", c.KMSKey, "project", c.Project,
		"tcbAllowed", c.TCBPolicy.AllowedStatuses, "devBuild", devBuild, "allowSimulated", a.broker.Config().AllowSimulated)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return hs.Shutdown(shutdown)
}
