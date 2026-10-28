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
TEMPO_VERIFIER_URL ?= https://contracts.tempo.xyz
FEE_TOKEN_ADDRESS ?= 0x20c0000000000000000000000000000000000000
MAINNET_DEPLOYMENTS := deployments/tempo-mainnet.json
CONTRACTS := PlatformRegistry AppRegistry OracleSignatureVerifier DeploymentRegistry FeeSplitter

.PHONY: help deps build test test-ci test-fork local-e2e deploy-mainnet record-mainnet verify-mainnet \
	estimate-mainnet abi coverage gas-report fmt fmt-check clean

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
	@echo "gas-report      gas report (Tempo T4 gas schedule)"

deps:
	forge soldeer install

build:
	forge build

test:
	forge test --no-match-path 'test/fork/*'

test-ci:
	FOUNDRY_PROFILE=ci forge test --no-match-path 'test/fork/*'

test-fork:
	forge test --match-path 'test/fork/*' -vv

local-e2e:
	script/local-e2e.sh

# Dry run by default: simulates against mainnet and writes deployments/tempo-mainnet.dry-run.json. Nothing is sent.
# BROADCAST=1 sends the transactions. --skip-simulation makes forge take each gas limit from the node's
# eth_estimateGas (Foundry 1.7.1 simulates with Tempo T4 rules, which do not match mainnet T12).
deploy-mainnet:
	@test -n "$$OWNER_PRIVATE_KEY" || { echo "OWNER_PRIVATE_KEY is not set (see $(SEALED_ENV))"; exit 1; }
	@test "$$(cast chain-id --rpc-url $(RPC))" = "4217" || { echo "RPC is not Tempo mainnet (4217)"; exit 1; }
ifeq ($(BROADCAST),1)
	forge script script/Deploy.s.sol:Deploy --rpc-url $(RPC) --broadcast --skip-simulation --slow \
		--tempo.fee-token $(FEE_TOKEN_ADDRESS)
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

estimate-mainnet: build
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
		g=$$(cast estimate --rpc-url $(RPC) --from $$from --create "$$code$${args#0x}"); total=$$((total + g)); \
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
