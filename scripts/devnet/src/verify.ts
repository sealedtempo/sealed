/**
 * The arguments of `sealed verify` in the devnet's verify steps. They are what a user on a chain other than Tempo
 * mainnet passes (docs/VERIFY.md): the chain's deployments file, an RPC of that chain and the release asset base.
 * No defaults file: the CLI takes the chain id, registries and fee token from the deployments file and keeps its
 * embedded defaults for everything platform-wide (catalog, TCB policy, settlement).
 */
export function sealedVerifyArgs(o: { deploymentId: string; evidence: boolean; rpcUrl: string; assetBase: string; extra?: string[] }): string[] {
  return [
    "verify", "--deployment", o.deploymentId, ...(o.evidence ? ["--evidence", "evidence.json"] : []),
    "--deployments", "deployments.json", "--rpc", o.rpcUrl, "--release-asset-base", o.assetBase,
    "--dev-allow-simulated", "--dev-allow-http-assets", "--json", "--report", "report.json", "--bundle-cache", "cache/bundles", "--collateral-cache", "cache/pcs",
    ...(o.extra ?? []),
  ];
}
