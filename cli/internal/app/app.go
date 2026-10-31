// Package app is the sealed command line: bootstrap (alias connect gcp), secrets, deploy, verify, catalog and
// release build (spec 8.4). Every collaborator that reaches Google Cloud, Tempo, Terraform or the network goes
// through Env, so the commands run end to end in tests against fakes.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/sealedtempo/sealed/cli/internal/bootstrap"
	"github.com/sealedtempo/sealed/cli/internal/bundles"
	"github.com/sealedtempo/sealed/cli/internal/deploy"
	"github.com/sealedtempo/sealed/cli/internal/gcp"
	"github.com/sealedtempo/sealed/cli/internal/registry"
	"github.com/sealedtempo/sealed/cli/internal/secrets"
	"github.com/sealedtempo/sealed/cli/internal/settings"
)

// Version is the CLI version.
const Version = "0.1.0"

// Exit codes.
const (
	ExitOK          = 0
	ExitFailed      = 1 // the operation failed, or a verification check failed
	ExitUsage       = 2
	ExitNotApproved = 3 // deploy: the wallet has not approved the stack yet
)

// Env is the process environment and the collaborators. Nil factories use the real implementations.
type Env struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Getenv func(string) string
	Now    func() time.Time
	// Interactive is true when stdin is a terminal (prompts are allowed).
	Interactive bool
	// ReadSecret reads one line without echo.
	ReadSecret func(prompt string) (string, error)

	NewTokens      func(impersonate string) (gcp.TokenSource, error)
	NewChain       func(ctx context.Context, s *settings.Settings) (registry.Reader, error)
	NewSecretStore func(project string, ts gcp.TokenSource) secrets.Store
	NewCompute     func(project string, ts gcp.TokenSource) deploy.Compute
	NewShared      func(project, bucket string, ts gcp.TokenSource) deploy.SharedDisk
	Terraform      bootstrap.Runner
	// ImportOSImages, when set, replaces bootstrap.OSImages.Ensure (tests).
	ImportOSImages func(ctx context.Context, o *bootstrap.OSImages) ([]bootstrap.OSImage, error)
	// HTTP fetches bundles and talks to the platform api.
	HTTP *http.Client
	// AllowHTTPBundles lets tests serve bundles over plain HTTP.
	AllowHTTPBundles bool
}

// OSEnv returns the real environment.
func OSEnv() *Env {
	interactive := false
	if fi, err := os.Stdin.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		interactive = true
	}
	return &Env{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Getenv: os.Getenv, Now: time.Now, Interactive: interactive, ReadSecret: readSecretTTY}
}

func (e *Env) getenv(k string) string {
	if e.Getenv == nil {
		return ""
	}
	return e.Getenv(k)
}

func (e *Env) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Env) printf(format string, a ...any) { fmt.Fprintf(e.Stdout, format, a...) }
func (e *Env) errorf(format string, a ...any) { fmt.Fprintf(e.Stderr, format, a...) }

func (e *Env) tokens(impersonate string) (gcp.TokenSource, error) {
	if e.NewTokens != nil {
		return e.NewTokens(impersonate)
	}
	return gcp.DefaultTokenSource(e.getenv, exec.LookPath, impersonate)
}

func (e *Env) gcpClient(ts gcp.TokenSource) *gcp.Client {
	return &gcp.Client{Tokens: ts, UserAgent: "sealed-cli/" + Version}
}

func (e *Env) secretStore(project string, ts gcp.TokenSource) secrets.Store {
	if e.NewSecretStore != nil {
		return e.NewSecretStore(project, ts)
	}
	return &gcp.SecretManager{C: e.gcpClient(ts), Project: project}
}

func (e *Env) compute(project string, ts gcp.TokenSource) deploy.Compute {
	if e.NewCompute != nil {
		return e.NewCompute(project, ts)
	}
	return &gcp.Compute{C: e.gcpClient(ts), Project: project}
}

func (e *Env) shared(project, bucket string, ts gcp.TokenSource) deploy.SharedDisk {
	if e.NewShared != nil {
		return e.NewShared(project, bucket, ts)
	}
	c := e.gcpClient(ts)
	return &deploy.GCEShared{Project: project, Bucket: bucket, Images: &gcp.Compute{C: c, Project: project}, Storage: &gcp.Storage{C: c}}
}

func (e *Env) chain(ctx context.Context, s *settings.Settings) (registry.Reader, error) {
	if e.NewChain != nil {
		return e.NewChain(ctx, s)
	}
	return registry.Dial(ctx, s.RPCURL, s.Registries)
}

func (e *Env) terraform() bootstrap.Runner {
	if e.Terraform != nil {
		return e.Terraform
	}
	return &bootstrap.ExecRunner{Stdin: e.Stdin, Stdout: e.Stdout, Stderr: e.Stderr}
}

func (e *Env) importOSImages(ctx context.Context, o *bootstrap.OSImages) ([]bootstrap.OSImage, error) {
	if e.ImportOSImages != nil {
		return e.ImportOSImages(ctx, o)
	}
	return o.Ensure(ctx)
}

func (e *Env) httpClient() *http.Client {
	if e.HTTP != nil {
		return e.HTTP
	}
	return nil
}

// common holds the flags shared by commands that read the chain or the catalog.
type commonFlags struct {
	rpc, defaultsFile, deploymentsFile, assetBase, bundleCache string
	chainID                                                    uint64
	json, devHTTPAssets                                        bool
}

func (c *commonFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&c.rpc, "rpc", "", "Tempo JSON-RPC URL (TEMPO_RPC_URL; default chain.public_rpc_url, mainnet only)")
	fs.StringVar(&c.defaultsFile, "defaults", "", "config/defaults.yaml to use instead of the embedded copy (SEALED_DEFAULTS_FILE)")
	fs.StringVar(&c.deploymentsFile, "deployments", "", "contracts/deployments/<network>.json instead of the embedded mainnet file (SEALED_DEPLOYMENTS_FILE); a file for another chain sets the chain id and fee token, and then needs --rpc")
	fs.Uint64Var(&c.chainID, "chain-id", 0, "the Tempo chain id you expect (TEMPO_CHAIN_ID); must match the deployments file (default its chainId, else 4217)")
	fs.StringVar(&c.assetBase, "release-asset-base", "", "release asset base URL (default catalog.release_asset_base)")
	fs.StringVar(&c.bundleCache, "bundle-cache", "", "content-addressed bundle cache directory (default the user cache dir)")
	fs.BoolVar(&c.json, "json", false, "print JSON")
	fs.BoolVar(&c.devHTTPAssets, "dev-allow-http-assets", false, "DEV ONLY (SEALED_DEV_SIM=1): fetch release bundles from a plain http asset base (local devnets); the sha256 check against bundleHash still applies")
}

func (c *commonFlags) settings(e *Env) (*settings.Settings, error) {
	if c.devHTTPAssets && e.getenv("SEALED_DEV_SIM") != "1" {
		return nil, usagef("--dev-allow-http-assets needs SEALED_DEV_SIM=1 (never for a production check)")
	}
	return settings.Load(settings.Options{DefaultsFile: c.defaultsFile, DeploymentsFile: c.deploymentsFile, RPCURL: c.rpc, ChainID: c.chainID}.FromEnv(e.getenv))
}

func (c *commonFlags) fetcher(e *Env, s *settings.Settings) *bundles.Fetcher {
	base := c.assetBase
	if base == "" {
		base = s.ReleaseAssetBase()
	}
	cache := c.bundleCache
	if cache == "" {
		if dir, err := os.UserCacheDir(); err == nil {
			cache = filepath.Join(dir, "sealed", "bundles")
		}
	}
	return &bundles.Fetcher{Base: base, HTTP: e.httpClient(), CacheDir: cache, AllowHTTP: e.AllowHTTPBundles || c.devHTTPAssets}
}

// usageError is a command line mistake (exit 2).
type usageError struct{ msg string }

func (u *usageError) Error() string { return u.msg }

func usagef(format string, a ...any) error { return &usageError{fmt.Sprintf(format, a...)} }

// exitError carries an exit code with a message already printed (or none).
type exitError struct {
	code int
	msg  string
}

func (x *exitError) Error() string { return x.msg }

func newFlags(name string, e *Env) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(e.Stderr)
	return fs
}

// parse parses flags allowing them before and after positional arguments.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

const usage = `sealed: verified open-source apps in confidential VMs in your own Google Cloud project.

Usage:
  sealed bootstrap --project <id> --region <region> --customer-address <0x...> --platform-sa <email> [--key-broker-image <ref@sha256:...>] [--plan] [--yes]
  sealed connect gcp --project <id> ...          same as sealed bootstrap
  sealed secrets set <app> <NAME> [--generate [--kind <generator>] | --value-file <f> | --stdin] [--rotate]
  sealed secrets set gate [--generate | --value-file <f> | --stdin]
  sealed secrets set --config stack.yaml --missing
  sealed secrets list [--config stack.yaml | --apps a,b]
  sealed secrets rm <app> <NAME> | gate [--yes]
  sealed deploy --config stack.yaml [--plan]
  sealed verify --deployment <0x id | dep_ alias> [--evidence <file>] [--live <attest url>] [--json]
  sealed verify ... --deployments <network>.json --rpc <url>   another chain: its deployments file and an RPC of it
  sealed catalog list [--json]
  sealed catalog show <app> [--json]
  sealed release build <app> [--catalog <dir>] [--out <file>] [--check <version|latest>]
  sealed version

Run sealed <command> --help for the flags of a command.
`

// Main runs the CLI and returns the exit code.
func Main(args []string, e *Env) int {
	if len(args) == 0 {
		fmt.Fprint(e.Stderr, usage)
		return ExitUsage
	}
	ctx := context.Background()
	var err error
	switch args[0] {
	case "bootstrap":
		err = runBootstrap(ctx, args[1:], e)
	case "connect":
		if len(args) < 2 || args[1] != "gcp" {
			err = usagef("usage: sealed connect gcp --project <id> ... (an alias of sealed bootstrap)")
		} else {
			err = runBootstrap(ctx, args[2:], e)
		}
	case "secrets":
		err = runSecrets(ctx, args[1:], e)
	case "deploy":
		err = runDeploy(ctx, args[1:], e)
	case "verify":
		err = runVerify(ctx, args[1:], e)
	case "catalog":
		err = runCatalog(ctx, args[1:], e)
	case "release":
		err = runRelease(ctx, args[1:], e)
	case "version", "--version":
		e.printf("sealed %s\n", Version)
		e.printf("Apache-2.0. Statically linked with go-ethereum under LGPL-3.0-or-later and other libraries; their license texts\n" +
			"and the LGPL notice are in licenses/ of the release archive (go run ./cli/release --licenses-only <dir> from source).\n")
		return ExitOK
	case "help", "-h", "--help":
		fmt.Fprint(e.Stdout, usage)
		return ExitOK
	default:
		err = usagef("unknown command %q\n\n%s", args[0], usage)
	}
	if err == nil {
		return ExitOK
	}
	if errors.Is(err, flag.ErrHelp) {
		return ExitOK
	}
	var u *usageError
	if errors.As(err, &u) {
		e.errorf("%s\n", u.msg)
		return ExitUsage
	}
	var x *exitError
	if errors.As(err, &x) {
		if x.msg != "" {
			e.errorf("%s\n", x.msg)
		}
		return x.code
	}
	e.errorf("error: %s\n", strings.TrimSpace(err.Error()))
	return ExitFailed
}
