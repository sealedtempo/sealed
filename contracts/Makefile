# Sealed contracts. Run from this directory. `make help` lists targets.
#
# Secrets and addresses come from the workspace .env (two levels up: the directory that holds both repos),
# or from SEALED_ENV=/path/to/.env. The file is included, never printed.

SEALED_ENV ?= ../../.env
-include $(SEALED_ENV)
export

TEMPO_RPC_URL ?=
TEMPO_PUBLIC_RPC_URL ?= https://rpc.tempo.xyz
RPC := $(if $(TEMPO_RPC_URL),$(TEMPO_RPC_URL),$(TEMPO_PUBLIC_RPC_URL))
# Resolve foundry.toml's `tempo = "${TEMPO_RPC_URL}"` to the same fallback for every forge/cast call below.
override TEMPO_RPC_URL := $(RPC)
TEMPO_VERIFIER_URL ?= https://contracts.tempo.xyz
FEE_TOKEN_ADDRESS ?= 0x20c0000000000000000000000000000000000000
MAINNET_DEPLOYMENTS := deployments/tempo-mainnet.json
CONTRACTS := PlatformRegistry AppRegistry OracleSignatureVerifier DeploymentRegistry FeeSplitter
# Toolchain pin. Older releases run Tempo T4 rules: forks read token policy ids as 0 and CREATE gas is ~2.3x mainnet.
FOUNDRY_VERSION := 1.8.6

.PHONY: help foundry-check deps build test test-ci test-fork local-e2e deploy-mainnet record-mainnet verify-mainnet \
	fee-token-pref estimate-mainnet abi coverage gas-report fmt fmt-check clean

help:
	@echo "deps            install pinned Soldeer dependencies (soldeer.lock)"
	@echo "build           forge build"
	@echo "test            unit, fuzz, invariant and script tests (no network)"
	@echo "test-ci         same with the ci profile (fuzz 1000 runs, invariant depth 100)"
	@echo "test-fork       fork tests against Tempo mainnet (TEMPO_RPC_URL or $(TEMPO_PUBLIC_RPC_URL))"
	@echo "local-e2e       full flow on a local anvil --network tempo node"
	@echo "deploy-mainnet  dry run of script/Deploy.s.sol against mainnet; BROADCAST=1 sends it"
	@echo "verify-mainnet  verify every contract of $(MAINNET_DEPLOYMENTS) at $(TEMPO_VERIFIER_URL)"
	@echo "estimate-mainnet  eth_estimateGas of each contract creation on mainnet (read only)"
	@echo "abi             regenerate abi/*.json"
	@echo "coverage        coverage summary + lcov.info"
	@echo "gas-report      gas report (Tempo T12 gas schedule; deployment cost reads 0, use estimate-mainnet)"
	@echo "foundry-check   fail unless forge is Foundry $(FOUNDRY_VERSION)"

foundry-check:
	@forge --version | head -1 | grep -q "Version: $(FOUNDRY_VERSION)$$" || { echo "need Foundry $(FOUNDRY_VERSION), found: $$(forge --version | head -1) (foundryup -i v$(FOUNDRY_VERSION))"; exit 1; }

deps:
	forge soldeer install

build:
	forge build

test:
	forge test --no-match-path 'test/fork/*'

test-ci:
	FOUNDRY_PROFILE=ci forge test --no-match-path 'test/fork/*'

test-fork: foundry-check
	forge test --match-path 'test/fork/*' -vv

local-e2e: foundry-check
	script/local-e2e.sh

# Dry run by default: simulates against mainnet and writes deployments/tempo-mainnet.dry-run.json. Nothing is sent.
# Its CREATE gas is within 3% of mainnet; the three wiring calls show ~22k gas because they are estimated before the
# contracts exist (mainnet: 0.28M to 0.53M), so use estimate-mainnet for costs.
# BROADCAST=1 sends standard EIP-1559 transactions (deploy profile, D-038). --skip-simulation --slow makes forge take
# each gas limit from the node's eth_estimateGas just before sending, after the previous transaction is mined.
deploy-mainnet: foundry-check
	@test -n "$$OWNER_PRIVATE_KEY" || { echo "OWNER_PRIVATE_KEY is not set (see $(SEALED_ENV))"; exit 1; }
	@test "$$(cast chain-id --rpc-url $(RPC))" = "4217" || { echo "RPC is not Tempo mainnet (4217)"; exit 1; }
ifeq ($(BROADCAST),1)
	@test "$$(cast call 0xfeec000000000000000000000000000000000000 'userTokens(address)(address)' $$(cast wallet address --private-key $$OWNER_PRIVATE_KEY) --rpc-url $(RPC) | tr A-F a-f)" = "$$(echo $(FEE_TOKEN_ADDRESS) | tr A-F a-f)" || { echo "OWNER's fee token preference is not FEE_TOKEN; run make fee-token-pref KEY_VAR=OWNER_PRIVATE_KEY"; exit 1; }
	FOUNDRY_PROFILE=deploy forge script script/Deploy.s.sol:Deploy --rpc-url $(RPC) --broadcast --skip-simulation --slow
	script/record-deployment.sh $(MAINNET_DEPLOYMENTS) broadcast/Deploy.s.sol/4217/run-latest.json
	$(MAKE) abi
	@echo "Deployed. Next: make verify-mainnet, then log the fees in MAINNET_LEDGER.md."
else
	forge script script/Deploy.s.sol:Deploy --rpc-url $(RPC)
	@echo "Dry run only (deployments/tempo-mainnet.dry-run.json). Re-run with BROADCAST=1 to send."
endif

record-mainnet:
	script/record-deployment.sh $(MAINNET_DEPLOYMENTS) broadcast/Deploy.s.sol/4217/run-latest.json

# Sourcify-compatible verification. Pass the host only: forge appends /v2/verify/<chainId>/<address>.
# Contract creations are not sent as Tempo 0x76 transactions: with gas left to the node, forge and cast (1.7.1 and
# 1.8.6) send an eth_estimateGas request with an empty `calls` list, which mainnet rejects (1.7.1 then failed with
# "missing keys: gas"). Instead each sending account sets FeeManager.setUserToken(FEE_TOKEN) once with a plain call,
# and later type-2 transactions pay fees in that token. KEY_VAR names the .env variable holding the key.
fee-token-pref:
	@test -n "$(KEY_VAR)" || { echo "usage: make fee-token-pref KEY_VAR=OPS_PRIVATE_KEY"; exit 1; }
	cast send 0xfeec000000000000000000000000000000000000 'setUserToken(address)' $(FEE_TOKEN_ADDRESS) \
		--private-key $$$(KEY_VAR) --rpc-url $(RPC) --tempo.fee-token $(FEE_TOKEN_ADDRESS)

verify-mainnet:
	@test -f $(MAINNET_DEPLOYMENTS) || { echo "missing $(MAINNET_DEPLOYMENTS)"; exit 1; }
	@set -e; for c in $(CONTRACTS); do \
		addr=$$(jq -r ".contracts.$$c.address" $(MAINNET_DEPLOYMENTS)); \
		args=$$(jq -r ".contracts.$$c.constructorArgs" $(MAINNET_DEPLOYMENTS)); \
		echo "verifying $$c at $$addr"; \
		forge verify-contract $$addr src/$$c.sol:$$c --chain 4217 --rpc-url $(RPC) \
			--verifier sourcify --verifier-url $(TEMPO_VERIFIER_URL) \
			--constructor-args $$args --retries 10 --delay 10 --watch; \
	done

# FeeSplitter's constructor reads appRegistry() from the DeploymentRegistry argument, so its estimate overrides the
# placeholder registry address with a stub whose every call returns the placeholder AppRegistry address.
estimate-mainnet: foundry-check build
	@set -e; o=0x1111111111111111111111111111111111111111; r2=0x2222222222222222222222222222222222222222; \
	r3=0x3333333333333333333333333333333333333333; from=$${ESTIMATE_FROM:-0x9a044ae05e5e6290dcf56afd69548565e957a626}; \
	gp=$$(cast gas-price --rpc-url $(RPC)); total=0; \
	for c in $(CONTRACTS); do \
		case $$c in \
			DeploymentRegistry) args=$$(cast abi-encode "f(address,address,address)" $$o $$r2 $$r3);; \
			FeeSplitter) args=$$(cast abi-encode "f(address,address,address,address,address,uint256,uint256)" \
				$$o $$r2 $$r3 $(FEE_TOKEN_ADDRESS) $$o 5000000 20000000);; \
			*) args=$$(cast abi-encode "f(address)" $$o);; \
		esac; \
		code=$$(jq -r '.bytecode.object' out/$$c.sol/$$c.json); \
		if [ $$c = FeeSplitter ]; then \
			stub="0x73$${r3#0x}60005260206000f3"; \
			g=$$(cast to-dec $$(cast rpc --rpc-url $(RPC) eth_estimateGas \
				"{\"from\":\"$$from\",\"data\":\"$$code$${args#0x}\"}" latest "{\"$$r2\":{\"code\":\"$$stub\"}}" | tr -d '"')); \
		else \
			g=$$(cast estimate --rpc-url $(RPC) --from $$from --create "$$code$${args#0x}"); \
		fi; total=$$((total + g)); \
		printf '%-24s %10s gas\n' $$c $$g; \
	done; \
	printf '%-24s %10s gas at %s attodollars/gas = $$%s (floor 6e8) .. $$%s (cap 1.2e10)\n' total $$total $$gp \
		$$(echo "scale=4; $$total * $$gp / 10^18" | bc) $$(echo "scale=4; $$total * 12000000000 / 10^18" | bc)

abi: build
	@mkdir -p abi
	@for c in $(CONTRACTS); do forge inspect $$c abi --json > abi/$$c.json; echo "abi/$$c.json"; done
	@forge inspect IAttestationVerifier abi --json > abi/IAttestationVerifier.json; echo "abi/IAttestationVerifier.json"

coverage:
	forge coverage --no-match-path 'test/fork/*' --report summary --report lcov

gas-report:
	forge test --gas-report --no-match-path 'test/fork/*' --no-match-contract Invariant

fmt:
	forge fmt

fmt-check:
	forge fmt --check

clean:
	forge clean
