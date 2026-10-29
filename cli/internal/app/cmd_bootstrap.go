package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	"github.com/sealedtempo/sealed/cli/internal/bootstrap"
	"github.com/sealedtempo/sealed/cli/internal/embedded"
	"github.com/sealedtempo/sealed/cli/internal/settings"
	"github.com/sealedtempo/sealed/verifier/chain"
)

func runBootstrap(ctx context.Context, args []string, e *Env) error {
	fs := newFlags("sealed bootstrap", e)
	var c commonFlags
	c.register(fs)
	p := &bootstrap.Params{EnableAPIs: true}
	var workDir, stateBucket, subnet, kms, allowedImages string
	var planOnly, yes, noAPIs, debugLogging bool
	fs.StringVar(&p.Project, "project", "", "your Google Cloud project id (required)")
	fs.StringVar(&p.Region, "region", "", "region with C3 TDX zones (default cloud.region, us-central1)")
	fs.StringVar(&p.Customer, "customer-address", "", "your Tempo wallet address; the key broker serves only stacks it approved (required)")
	fs.StringVar(&p.PlatformSA, "platform-sa", "", "the platform service account allowed to impersonate the deployer (required)")
	fs.StringVar(&p.KeyBrokerImage, "key-broker-image", bootstrap.DefaultKeyBrokerImage, "key broker image pinned by digest")
	fs.StringVar(&p.TempoRPC, "tempo-rpc", "", "Tempo RPC the key broker reads approvals from (default --rpc, TEMPO_RPC_URL, else chain.public_rpc_url)")
	fs.StringVar(&workDir, "work-dir", "", "where the module and its Terraform state live (default <user config dir>/sealed/bootstrap/<project>)")
	fs.StringVar(&stateBucket, "state-bucket", "", "keep the Terraform state in this GCS bucket instead of the work dir")
	fs.StringVar(&subnet, "subnet-cidr", "", "IPv4 range of the sealed subnet (default 10.42.0.0/24)")
	fs.StringVar(&kms, "kms-protection", "", "SOFTWARE (default) or HSM for the KMS HMAC key")
	fs.BoolVar(&planOnly, "plan", false, "only show the Terraform plan; create nothing")
	fs.BoolVar(&yes, "yes", false, "apply without asking for confirmation")
	fs.BoolVar(&noAPIs, "no-enable-apis", false, "do not enable the Google Cloud APIs (they are managed elsewhere)")
	fs.BoolVar(&debugLogging, "debug-logging", false, "also create sealed-debug-logs, a log writer identity for debug VMs only (spec 5.8); production VMs never get it")
	fs.StringVar(&p.FeeSplitter, "fee-splitter", e.getenv("SEALED_FEE_SPLITTER"), "FeeSplitter the key broker requires in every config (SEALED_FEE_SPLITTER; default the deployments file's when the registries are not mainnet's)")
	fs.StringVar(&p.FeeToken, "fee-token", e.getenv("SEALED_FEE_TOKEN"), "fee token the key broker requires in every config (SEALED_FEE_TOKEN; default the deployments file's when it is not mainnet's)")
	fs.StringVar(&allowedImages, "allowed-images", e.getenv("SEALED_ALLOWED_IMAGES"), "comma-separated 0x imageIds: the only images the key broker releases to, on top of PlatformRegistry approval (SEALED_ALLOWED_IMAGES)")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return usagef("sealed bootstrap takes no positional arguments")
	}
	if p.Project == "" || p.Customer == "" || p.PlatformSA == "" {
		return usagef("sealed bootstrap needs --project, --customer-address and --platform-sa")
	}
	s, err := c.settings(e)
	if err != nil {
		return err
	}
	if p.Region == "" {
		p.Region = s.Defaults.Cloud.Region
	}
	// The customer's RPC choice reaches the key broker: --tempo-rpc, else the RPC this command was given
	// (--rpc or TEMPO_RPC_URL), else the public RPC. It is never replaced silently (review F5).
	if p.TempoRPC == "" {
		p.TempoRPC = s.RPCURL
	}
	p.ChainID = s.ChainID
	p.Registries = s.Registries
	p.ReleaseAssetBase = s.ReleaseAssetBase()
	if c.assetBase != "" {
		p.ReleaseAssetBase = c.assetBase
	}
	p.SubnetCIDR, p.KMSProtection, p.EnableAPIs, p.EnableDebugLogging = subnet, kms, !noAPIs, debugLogging
	p.AllowedImages = bootstrap.ParseImageIDs(allowedImages)
	if err := brokerFees(p, s); err != nil {
		return err
	}
	if err := p.Validate(); err != nil {
		return usagef("%s", err)
	}
	if workDir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return err
		}
		workDir = filepath.Join(base, "sealed", "bootstrap", p.Project)
	}
	if err := bootstrap.Materialize(workDir, embedded.BootstrapModule()); err != nil {
		return err
	}
	if err := bootstrap.WriteVars(workDir, p); err != nil {
		return err
	}
	if err := bootstrap.WriteBackend(workDir, stateBucket); err != nil {
		return err
	}
	// The google provider gets an access token from the customer's own credentials (gcloud in Cloud Shell).
	var accessToken string
	ts, err := e.tokens("")
	if err != nil {
		// Without gcloud or a token the provider can still use a service account key file.
		if e.getenv("GOOGLE_APPLICATION_CREDENTIALS") == "" {
			return err
		}
	} else if accessToken, err = ts.Token(ctx); err != nil {
		return err
	}
	if !planOnly && !yes && !e.Interactive {
		return usagef("not a terminal: pass --yes to apply without confirmation, or --plan to only plan")
	}
	e.errorf("Bootstrapping project %s in %s for wallet %s. Module and state: %s\n", p.Project, p.Region, p.Customer, workDir)
	e.errorf("The key broker will read Tempo chain %d through %s.\n", p.ChainID, p.TempoRPC)
	if p.FeeSplitter != "" || p.FeeToken != "" {
		e.errorf("It requires FeeSplitter %s and fee token %s in every config (not mainnet's).\n", orMainnet(p.FeeSplitter), orMainnet(p.FeeToken))
	}
	if len(p.AllowedImages) > 0 {
		e.errorf("It releases only to your %d allowed image(s): %s.\n", len(p.AllowedImages), strings.Join(p.AllowedImages, ", "))
	}
	if p.ChainID != chain.MainnetChainID {
		e.errorf("Warning: a production key broker image serves only Tempo mainnet (4217) and refuses to start on chain %d (D-060); other chains need a dev build of the broker.\n", p.ChainID)
	}
	out, err := bootstrap.Run(ctx, e.terraform(), bootstrap.Options{Dir: workDir, PlanOnly: planOnly, AutoApprove: yes, AccessToken: accessToken})
	if err != nil {
		return err
	}
	if planOnly {
		e.errorf("Plan only: nothing was created.\n")
		return nil
	}
	tok, err := out.Token(e.now())
	if err != nil {
		return err
	}
	if c.json {
		return writeJSON(e.Stdout, map[string]any{
			"token": tok, "project": out.Project, "region": out.Region, "deployerAccount": out.DeployerAccount,
			"keyBrokerUrl": out.KeyBrokerURL, "customer": out.Customer, "subnetwork": out.Subnetwork,
			"keyBrokerServiceAccount": out.KeyBrokerSA, "kmsKeyVersion": out.KMSKeyVersion, "bootBucket": out.BootBucket,
			"tempoRpc": out.TempoRPC, "debugLogServiceAccount": out.DebugLogSA,
		})
	}
	e.printf("\nYour project is ready.\n\n")
	e.printf("  Deployer account   %s (the platform may only impersonate it)\n", out.DeployerAccount)
	e.printf("  Key broker         %s\n", out.KeyBrokerURL)
	e.printf("  Key broker account %s\n", out.KeyBrokerSA)
	e.printf("  KMS HMAC key       %s\n", out.KMSKeyVersion)
	if out.TempoRPC != "" {
		e.printf("  Key broker RPC     %s\n", out.TempoRPC)
	}
	if out.DebugLogSA != "" {
		e.printf("  Debug log writer   %s (debug VMs only)\n", out.DebugLogSA)
	}
	if out.BootBucket != "" {
		e.printf("  Boot bucket        %s\n", out.BootBucket)
	}
	e.printf("\nConnection token (paste it in the console, or use it as connection: in stack.yaml):\n\n%s\n\n", tok)
	e.printf("Next: store your secrets with sealed secrets set, then check the IAM rules with scripts/iam-checks/check.sh.\n")
	return nil
}

// brokerFees fills the FeeSplitter and fee token the key broker checks (SEALED_FEE_SPLITTER, SEALED_FEE_TOKEN) from
// the deployments file when they are not mainnet's, the broker's defaults. Registries other than mainnet's settle
// fees through their own FeeSplitter: a broker that required mainnet's would refuse every release, so bootstrap
// stops when it cannot tell which one applies.
func brokerFees(p *bootstrap.Params, s *settings.Settings) error {
	mainnet, err := settings.Load(settings.Options{})
	if err != nil {
		return err
	}
	if p.FeeSplitter == "" && s.FeeSplitter != (common.Address{}) && s.FeeSplitter != mainnet.FeeSplitter {
		p.FeeSplitter = strings.ToLower(s.FeeSplitter.Hex())
	}
	if p.FeeToken == "" && s.FeeToken != (common.Address{}) && s.FeeToken != mainnet.FeeToken {
		p.FeeToken = strings.ToLower(s.FeeToken.Hex())
	}
	own := s.Registries.PlatformRegistry != mainnet.Registries.PlatformRegistry || s.Registries.AppRegistry != mainnet.Registries.AppRegistry ||
		s.Registries.DeploymentRegistry != mainnet.Registries.DeploymentRegistry
	if own && p.FeeSplitter == "" && s.FeeSplitter == (common.Address{}) {
		return usagef("the deployments file names registries other than mainnet's but no FeeSplitter: pass --fee-splitter (SEALED_FEE_SPLITTER), or the key broker would require mainnet's and refuse every release")
	}
	if s.Derived && p.FeeToken == "" && s.FeeToken == (common.Address{}) {
		return usagef("the deployments file for chain %d names no config.feeToken: pass --fee-token (SEALED_FEE_TOKEN), or the key broker would require mainnet's USDC.e", s.ChainID)
	}
	return nil
}

func orMainnet(a string) string {
	if a == "" {
		return "(mainnet's)"
	}
	return a
}
