package app

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/sealedtempo/sealed/cli/internal/deploy"
)

func runDeploy(ctx context.Context, args []string, e *Env) error {
	fs := newFlags("sealed deploy", e)
	var c commonFlags
	c.register(fs)
	var config, writeConfig, platformAPI string
	var planOnly, asDeployer, skipSecrets, devUnbuilt, replace bool
	var wait time.Duration
	fs.StringVar(&config, "config", "", "stack.yaml (required)")
	fs.StringVar(&writeConfig, "write-config", "", "also write the public config (sealed-config/v1) to this file")
	fs.StringVar(&platformAPI, "platform-api", "", "platform api URL when the stack file has no endpoints.platformApi (SEALED_PLATFORM_API)")
	fs.BoolVar(&planOnly, "plan", false, "compose and check only; create nothing (the static IP must already be reserved)")
	fs.BoolVar(&asDeployer, "as-deployer", false, "act as the bootstrap's deployer account through impersonation (needs serviceAccountTokenCreator on it, which only the platform service account holds)")
	fs.BoolVar(&skipSecrets, "skip-secrets-check", false, "do not check that every required secret has a value")
	fs.BoolVar(&replace, "replace", false, "upgrade: delete the VM of this name when it runs another deployment and create it again with this stack; the data disk is kept (same salt, D-058)")
	fs.DurationVar(&wait, "wait-approval", 0, "poll the chain this long for the wallet's approval instead of stopping")
	fs.BoolVar(&devUnbuilt, "dev-allow-unbuilt", false, "DEV ONLY (SEALED_DEV_SIM=1): compose stacks whose images still have placeholder digests")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 || config == "" {
		return usagef("usage: sealed deploy --config stack.yaml [--plan]")
	}
	if devUnbuilt && e.getenv("SEALED_DEV_SIM") != "1" {
		return usagef("--dev-allow-unbuilt needs SEALED_DEV_SIM=1 (never in production)")
	}
	stack, err := deploy.LoadStackFile(config)
	if err != nil {
		return err
	}
	if stack.Image.Debug && asDeployer {
		return usagef("a debug image needs the %s log writer attached, which the deployer can never do (spec 8.6): deploy debug stacks with your own credentials, without --as-deployer", deploy.DebugLogAccountID)
	}
	s, err := c.settings(e)
	if err != nil {
		return err
	}
	reader, err := e.chain(ctx, s)
	if err != nil {
		return err
	}
	impersonate := ""
	if asDeployer {
		impersonate = "sealed-deployer@" + stack.Project + ".iam.gserviceaccount.com"
	}
	ts, err := e.tokens(impersonate)
	if err != nil {
		return err
	}
	if platformAPI == "" {
		platformAPI = e.getenv("SEALED_PLATFORM_API")
	}
	bucket := stack.BootBucket
	if bucket == "" {
		bucket = stack.Project + "-sealed-boot"
	}
	d := &deploy.Deployer{
		Settings: s, Chain: reader, Fetcher: c.fetcher(e, s), Compute: e.compute(stack.Project, ts),
		Shared: e.shared(stack.Project, bucket, ts), Out: e.Stderr, PlatformAPI: platformAPI, AllowUnbuilt: devUnbuilt,
		Replace: replace,
	}
	if !skipSecrets {
		// The secrets check uses the customer's own account: the deployer cannot read Secret Manager at all.
		sts, err := e.tokens("")
		if err != nil {
			return err
		}
		d.Secrets = e.secretStore(stack.Project, sts)
	}
	p, err := d.Prepare(ctx, stack, !planOnly)
	if err != nil {
		return err
	}
	// Before the wallet is asked to approve: a VM of a shape the image was not measured on never gets its keys.
	if err := deploy.CheckMachineType(p.MachineType, p.Image, s.Defaults.Cloud); err != nil {
		return err
	}
	deadline := e.now().Add(wait)
	for !p.Approval.Approved && !p.Debug && wait > 0 && e.now().Before(deadline) {
		e.errorf("waiting for the wallet's approval of %s ...\n", p.Result.StackHash.Hex())
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Second):
		}
		if p, err = d.Prepare(ctx, stack, !planOnly); err != nil {
			return err
		}
	}
	if writeConfig != "" {
		if err := os.WriteFile(writeConfig, append(append([]byte(nil), p.ConfigJSON...), '\n'), 0o644); err != nil {
			return err
		}
	}
	summary := map[string]any{
		"name": stack.Name, "project": stack.Project, "zone": stack.Zone, "ip": p.IP,
		"deploymentId": p.Result.DeploymentID.Hex(), "stackHash": p.Result.StackHash.Hex(), "configHash": p.Result.ConfigHash.Hex(),
		"approved": p.Approval.Approved, "missingSecrets": p.MissingSecrets, "debug": p.Debug,
	}
	if !c.json {
		e.printf("deploymentId %s\nstackHash    %s\nconfigHash   %s\n", p.Result.DeploymentID.Hex(), p.Result.StackHash.Hex(), p.Result.ConfigHash.Hex())
		if p.IP != "" {
			e.printf("static IP    %s\n", p.IP)
		}
	}
	if p.Debug {
		e.errorf("\nDEBUG IMAGE: for development only. The key broker releases no secrets, disk key or signer seed to it,\n"+
			"and the VM gets %s (logging.write only) so its container logs reach Cloud Logging in %s.\n"+
			"Create that account with sealed bootstrap --debug-logging if it does not exist yet.\n", p.DebugLogSA, stack.Project)
	} else if !p.Approval.Approved {
		e.errorf("\n%s", p.ApprovalInstructions(s.Registries.DeploymentRegistry, s.RPCURL, strings.ToLower(s.Defaults.Chain.FeeToken)))
		if c.json {
			_ = writeJSON(e.Stdout, summary)
		}
		return &exitError{code: ExitNotApproved}
	}
	if len(p.MissingSecrets) > 0 && !p.Debug {
		if c.json {
			_ = writeJSON(e.Stdout, summary)
		}
		return &exitError{code: ExitFailed, msg: "missing secrets (the key broker would refuse the stack):\n  " + strings.Join(p.MissingSecrets, "\n  ") + "\nrun: sealed secrets set --config " + config + " --missing"}
	}
	if planOnly {
		if p.Debug {
			e.errorf("plan only: debug stack; nothing was created\n")
		} else {
			e.errorf("plan only: the stack is approved; nothing was created\n")
		}
		if c.json {
			return writeJSON(e.Stdout, summary)
		}
		return nil
	}
	out, err := d.Apply(ctx, p)
	if err != nil {
		if errors.Is(err, deploy.ErrNotApproved) {
			return &exitError{code: ExitNotApproved, msg: err.Error()}
		}
		return err
	}
	summary["instance"], summary["created"], summary["attestUrl"] = out.Instance, out.Created, out.AttestURL
	if out.Replaced != "" {
		summary["replaced"] = out.Replaced
	}
	if c.json {
		return writeJSON(e.Stdout, summary)
	}
	e.printf("instance     %s (%s)\n", out.Instance, out.Zone)
	if out.Replaced != "" {
		e.printf("replaced     %s (data disk kept)\n", out.Replaced)
	}
	if out.AttestURL != "" {
		e.printf("attest       %s\n", out.AttestURL)
		e.printf("\nWhen it has booted and registered, check it yourself:\n  sealed verify --deployment %s --live %s\n", out.DeploymentID, out.AttestURL)
	}
	return nil
}
