# Contract ABIs

Copied from `contracts/abi/` (generated there by `make -C contracts abi`, which runs `forge inspect <C> abi`).
Only the three registries the verifier reads are kept: PlatformRegistry, AppRegistry, DeploymentRegistry.

`../deployments/tempo-mainnet.json` is a byte copy of `contracts/deployments/tempo-mainnet.json`, embedded as the
default registry addresses on chain 4217.

Refresh after the contracts change: `go generate ./verifier/chain` (or `make -C verifier abi`), then run
`go test ./verifier/chain`. The anvil test deploys the contracts built from source and reads every view through
these ABIs, so a stale copy fails there.
