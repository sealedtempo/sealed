// Package localtempo holds what every local Tempo node in the Go tests shares.
package localtempo

// Hardfork is the anvil --hardfork of every local Tempo node the Go tests start: mainnet's, so gas, the TIP-403
// policy registry and the AccountKeychain and escrow precompiles behave as there (D-053, Foundry 1.8.6). It is
// Mainnet activated T13 (2026-11-03 15:00 UTC); it moves with contracts/foundry.toml and
// @sealed/core's LOCAL_HARDFORK, which TestHardforkMatchesContractsAndCore keeps in step.
const Hardfork = "T13"
