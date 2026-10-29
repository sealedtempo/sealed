// Package bootstrap drives infra/terraform/customer-bootstrap for `sealed bootstrap` and `sealed connect gcp`
// (spec 8.4, D-032). The module is embedded in the binary; it is written to a work directory that also keeps the
// Terraform state, run with the customer's own credentials, and its outputs become the sct_ connection token.
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/sealedtempo/sealed/cli/internal/token"
	"github.com/sealedtempo/sealed/verifier/chain"
)

// DefaultKeyBrokerImage is the key broker image bootstrap deploys: the sealed-key-broker entry of
// catalog/tools/release/extra-images.json, which the runtime image workflow pins (TestDefaultKeyBrokerImagePin keeps
// the two equal). The digest stays all zeros until the release workflow publishes the image; bootstrap refuses it
// (pass --key-broker-image).
const DefaultKeyBrokerImage = "ghcr.io/sealedtempo/sealed-key-broker@sha256:0000000000000000000000000000000000000000000000000000000000000000"

// Params are the module variables.
type Params struct {
	Project          string
	Region           string
	Customer         string
	PlatformSA       string
	KeyBrokerImage   string
	TempoRPC         string
	ChainID          uint64
	Registries       chain.Addresses
	ReleaseAssetBase string
	SubnetCIDR       string
	KMSProtection    string
	EnableAPIs       bool
	// EnableDebugLogging creates sealed-debug-logs, the log writer identity debug VMs get (spec 5.8).
	EnableDebugLogging bool
	// FeeSplitter and FeeToken, when set, are what the key broker requires in every config (SEALED_FEE_SPLITTER,
	// SEALED_FEE_TOKEN); empty leaves the broker's mainnet defaults. Set for registries other than mainnet's.
	FeeSplitter string
	FeeToken    string
	// AllowedImages, when set, are the only imageIds the key broker releases to, on top of PlatformRegistry
	// approval (SEALED_ALLOWED_IMAGES).
	AllowedImages []string
}

var (
	projectRe = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	regionRe  = regexp.MustCompile(`^[a-z]+-[a-z]+[0-9]+$`)
	saRe      = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$`)
	imageRe   = regexp.MustCompile(`^[a-z0-9.-]+(:[0-9]+)?(/[a-z0-9._-]+)+@sha256:[0-9a-f]{64}$`)
	imageIDRe = regexp.MustCompile(`^0x[0-9a-fA-F]{64}$`)
)

// ParseImageIDs splits a comma-separated imageId list (--allowed-images, SEALED_ALLOWED_IMAGES).
func ParseImageIDs(list string) []string {
	var out []string
	for _, p := range strings.Split(list, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Validate checks the parameters before Terraform sees them, with plain messages.
func (p *Params) Validate() error {
	var errs []string
	if !projectRe.MatchString(p.Project) {
		errs = append(errs, fmt.Sprintf("--project %q is not a project id", p.Project))
	}
	if !regionRe.MatchString(p.Region) {
		errs = append(errs, fmt.Sprintf("--region %q is not a region", p.Region))
	}
	if !common.IsHexAddress(p.Customer) || !strings.HasPrefix(p.Customer, "0x") {
		errs = append(errs, fmt.Sprintf("--customer-address %q is not an address", p.Customer))
	}
	if !saRe.MatchString(p.PlatformSA) {
		errs = append(errs, fmt.Sprintf("--platform-sa %q is not a service account email", p.PlatformSA))
	} else if strings.HasSuffix(p.PlatformSA, "@"+p.Project+".iam.gserviceaccount.com") {
		errs = append(errs, "--platform-sa must belong to the platform's project, not yours")
	}
	if !imageRe.MatchString(p.KeyBrokerImage) {
		errs = append(errs, fmt.Sprintf("--key-broker-image %q must be pinned by digest", p.KeyBrokerImage))
	} else if strings.HasSuffix(p.KeyBrokerImage, "@sha256:"+strings.Repeat("0", 64)) {
		errs = append(errs, "the key broker image is not published yet (all-zero digest); pass --key-broker-image <ref>@sha256:<digest>")
	}
	if !strings.HasPrefix(p.TempoRPC, "https://") {
		errs = append(errs, "--tempo-rpc must be an https URL")
	}
	if p.ChainID == 0 {
		errs = append(errs, "the chain id is not set")
	}
	if err := p.Registries.Validate(); err != nil {
		errs = append(errs, err.Error())
	}
	for _, a := range []struct{ flag, v string }{{"--fee-splitter (SEALED_FEE_SPLITTER)", p.FeeSplitter}, {"--fee-token (SEALED_FEE_TOKEN)", p.FeeToken}} {
		if a.v != "" && (!common.IsHexAddress(a.v) || !strings.HasPrefix(a.v, "0x") || common.HexToAddress(a.v) == (common.Address{})) {
			errs = append(errs, fmt.Sprintf("%s %q is not an address", a.flag, a.v))
		}
	}
	seen := map[string]bool{}
	for _, id := range p.AllowedImages {
		switch {
		case !imageIDRe.MatchString(id):
			errs = append(errs, fmt.Sprintf("--allowed-images (SEALED_ALLOWED_IMAGES): %q is not a 0x-prefixed 32-byte imageId", id))
		case seen[strings.ToLower(id)]:
			errs = append(errs, fmt.Sprintf("--allowed-images (SEALED_ALLOWED_IMAGES): %s is listed twice", id))
		}
		seen[strings.ToLower(id)] = true
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "\n"))
	}
	return nil
}

// Vars returns terraform.tfvars.json content.
func (p *Params) Vars() map[string]any {
	v := map[string]any{
		"project_id":               p.Project,
		"region":                   p.Region,
		"customer_address":         strings.ToLower(p.Customer),
		"platform_service_account": p.PlatformSA,
		"key_broker_image":         p.KeyBrokerImage,
		"tempo_rpc_url":            p.TempoRPC,
		"chain_id":                 p.ChainID,
		"platform_registry":        lower(p.Registries.PlatformRegistry),
		"app_registry":             lower(p.Registries.AppRegistry),
		"deployment_registry":      lower(p.Registries.DeploymentRegistry),
		"release_asset_base":       strings.TrimRight(p.ReleaseAssetBase, "/"),
		"enable_apis":              p.EnableAPIs,
		"enable_debug_logging":     p.EnableDebugLogging,
	}
	if p.SubnetCIDR != "" {
		v["subnet_cidr"] = p.SubnetCIDR
	}
	if p.KMSProtection != "" {
		v["kms_protection_level"] = p.KMSProtection
	}
	if p.FeeSplitter != "" {
		v["fee_splitter"] = strings.ToLower(p.FeeSplitter)
	}
	if p.FeeToken != "" {
		v["fee_token"] = strings.ToLower(p.FeeToken)
	}
	if len(p.AllowedImages) > 0 {
		ids := make([]string, len(p.AllowedImages))
		for i, id := range p.AllowedImages {
			ids[i] = strings.ToLower(id)
		}
		v["key_broker_allowed_images"] = ids
	}
	return v
}

func lower(a common.Address) string { return strings.ToLower(a.Hex()) }

// managedList records which files Materialize wrote, so a newer binary can remove files the module dropped.
const managedList = ".sealed-module-files"

// Materialize writes the module into dir (created 0700). Terraform state, .terraform and tfvars are kept.
func Materialize(dir string, module fs.FS) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	var files []string
	err := fs.WalkDir(module, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		// Tests are not part of a customer's root module.
		if strings.HasPrefix(p, "tests/") {
			return nil
		}
		b, err := fs.ReadFile(module, p)
		if err != nil {
			return err
		}
		dst := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(dst, b, 0o644); err != nil {
			return err
		}
		files = append(files, p)
		return nil
	})
	if err != nil {
		return err
	}
	if old, err := os.ReadFile(filepath.Join(dir, managedList)); err == nil {
		keep := map[string]bool{}
		for _, f := range files {
			keep[f] = true
		}
		for _, f := range strings.Split(string(old), "\n") {
			if f != "" && !keep[f] && !strings.Contains(f, "..") {
				_ = os.Remove(filepath.Join(dir, filepath.FromSlash(f)))
			}
		}
	}
	sort.Strings(files)
	return os.WriteFile(filepath.Join(dir, managedList), []byte(strings.Join(files, "\n")+"\n"), 0o644)
}

// WriteVars writes terraform.tfvars.json.
func WriteVars(dir string, p *Params) error {
	b, err := json.MarshalIndent(p.Vars(), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "terraform.tfvars.json"), append(b, '\n'), 0o644)
}

// WriteBackend writes a GCS backend for the state when bucket is set, and removes it otherwise.
func WriteBackend(dir, bucket string) error {
	path := filepath.Join(dir, "sealed_backend.tf")
	if bucket == "" {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$`).MatchString(bucket) {
		return fmt.Errorf("--state-bucket %q is not a bucket name", bucket)
	}
	return os.WriteFile(path, []byte(fmt.Sprintf("terraform {\n  backend \"gcs\" {\n    bucket = %q\n    prefix = \"sealed/customer-bootstrap\"\n  }\n}\n", bucket)), 0o644)
}

// Runner runs terraform. Streamed commands write to the user's terminal; captured ones return stdout.
type Runner interface {
	Stream(ctx context.Context, dir string, env []string, args ...string) error
	Capture(ctx context.Context, dir string, env []string, args ...string) ([]byte, error)
}

// ExecRunner runs a terraform binary.
type ExecRunner struct {
	Binary string // default "terraform"
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

func (r *ExecRunner) cmd(ctx context.Context, dir string, env []string, args ...string) *exec.Cmd {
	bin := r.Binary
	if bin == "" {
		bin = "terraform"
	}
	c := exec.CommandContext(ctx, bin, append([]string{"-chdir=" + dir}, args...)...)
	c.Env = append(os.Environ(), env...)
	return c
}

// Stream runs terraform attached to the terminal.
func (r *ExecRunner) Stream(ctx context.Context, dir string, env []string, args ...string) error {
	c := r.cmd(ctx, dir, env, args...)
	c.Stdin, c.Stdout, c.Stderr = r.Stdin, r.Stdout, r.Stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("terraform %s: %w", args[0], err)
	}
	return nil
}

// Capture runs terraform and returns stdout.
func (r *ExecRunner) Capture(ctx context.Context, dir string, env []string, args ...string) ([]byte, error) {
	c := r.cmd(ctx, dir, env, args...)
	c.Stderr = r.Stderr
	out, err := c.Output()
	if err != nil {
		return nil, fmt.Errorf("terraform %s: %w", args[0], err)
	}
	return out, nil
}

// Options control a run.
type Options struct {
	Dir         string
	PlanOnly    bool
	AutoApprove bool
	// AccessToken is passed to the google provider as GOOGLE_OAUTH_ACCESS_TOKEN (never logged). Empty lets the
	// provider use application default credentials.
	AccessToken string
}

// Outputs are the module outputs the connection token needs.
type Outputs struct {
	Project         string
	Region          string
	Customer        string
	DeployerAccount string
	KeyBrokerURL    string
	Subnetwork      string
	KMSKeyVersion   string
	KeyBrokerSA     string
	BootBucket      string // optional
	// TempoRPC is the RPC the key broker reads approvals from (optional: older modules lack the output).
	TempoRPC string
	// DebugLogSA is the log writer identity for debug VMs, empty unless enabled.
	DebugLogSA string
}

// Run initializes and applies (or plans) the module, then reads its outputs. Outputs are nil for a plan.
func Run(ctx context.Context, r Runner, o Options) (*Outputs, error) {
	env := []string{"TF_IN_AUTOMATION=1"}
	if o.AccessToken != "" {
		env = append(env, "GOOGLE_OAUTH_ACCESS_TOKEN="+o.AccessToken)
	}
	if err := r.Stream(ctx, o.Dir, env, "init", "-input=false", "-upgrade=false"); err != nil {
		return nil, err
	}
	if o.PlanOnly {
		return nil, r.Stream(ctx, o.Dir, env, "plan", "-input=false")
	}
	args := []string{"apply", "-input=" + fmt.Sprint(!o.AutoApprove)}
	if o.AutoApprove {
		args = append(args, "-auto-approve")
	}
	if err := r.Stream(ctx, o.Dir, env, args...); err != nil {
		return nil, err
	}
	raw, err := r.Capture(ctx, o.Dir, env, "output", "-json")
	if err != nil {
		return nil, err
	}
	return ParseOutputs(raw)
}

// ParseOutputs reads `terraform output -json`.
func ParseOutputs(raw []byte) (*Outputs, error) {
	var doc map[string]struct {
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("terraform output: %w", err)
	}
	str := func(k string) (string, error) {
		v, ok := doc[k]
		if !ok {
			return "", fmt.Errorf("terraform output %s is missing", k)
		}
		var s string
		if err := json.Unmarshal(v.Value, &s); err != nil || s == "" {
			return "", fmt.Errorf("terraform output %s is not a string", k)
		}
		return s, nil
	}
	o := &Outputs{}
	for _, f := range []struct {
		k   string
		dst *string
	}{
		{"project_id", &o.Project}, {"region", &o.Region}, {"customer_address", &o.Customer},
		{"deployer_service_account", &o.DeployerAccount}, {"key_broker_url", &o.KeyBrokerURL},
		{"subnetwork", &o.Subnetwork}, {"kms_key_version", &o.KMSKeyVersion}, {"key_broker_service_account", &o.KeyBrokerSA},
	} {
		v, err := str(f.k)
		if err != nil {
			return nil, err
		}
		*f.dst = v
	}
	for k, dst := range map[string]*string{"boot_bucket": &o.BootBucket, "tempo_rpc_url": &o.TempoRPC, "debug_log_service_account": &o.DebugLogSA} {
		if v, ok := doc[k]; ok {
			_ = json.Unmarshal(v.Value, dst)
		}
	}
	return o, nil
}

// Token builds the connection token from the outputs.
func (o *Outputs) Token(now time.Time) (string, error) {
	return token.Encode(token.Connection{
		V: token.Version, Project: o.Project, Region: o.Region, DeployerAccount: o.DeployerAccount,
		KeyBrokerURL: o.KeyBrokerURL, Customer: o.Customer, Subnetwork: o.Subnetwork, IssuedAt: now.Unix(),
	})
}
