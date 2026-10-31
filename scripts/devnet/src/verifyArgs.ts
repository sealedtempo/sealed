// The `sealed verify` command line of the devnet's verify steps. A deployments file for another chain than mainnet is
// enough for the CLI (cli/internal/settings): it sets the chain id and the registries, --rpc names that chain's RPC
// and --release-asset-base the devnet's asset server. The embedded defaults (this tree's config/defaults.yaml, built
// into the binary) give the TCB policy and everything else, so no defaults file is written (merge-c-final).

export interface VerifyArgs {
  /** 0x deployment id or dep_ alias. */
  deployment: string;
  /** Whether evidence.json is in the working directory. */
  evidence: boolean;
  rpcUrl: string;
  /** The devnet's release asset server (plain http, hence --dev-allow-http-assets). */
  assetBase: string;
  extra?: string[];
}

export function sealedVerifyArgs(o: VerifyArgs): string[] {
  return [
    "verify", "--deployment", o.deployment, ...(o.evidence ? ["--evidence", "evidence.json"] : []),
    "--rpc", o.rpcUrl, "--deployments", "deployments.json", "--release-asset-base", o.assetBase,
    "--dev-allow-simulated", "--dev-allow-http-assets", "--json", "--report", "report.json", "--bundle-cache", "cache/bundles", "--collateral-cache", "cache/pcs",
    ...(o.extra ?? []),
  ];
}
