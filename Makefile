# Root Makefile: delegates to each component. Components own their own Makefiles.
SEALED_ENV ?= ../.env
-include $(SEALED_ENV)
export

GO_PKGS := ./...

.PHONY: all build test go-test go-vet ts-test contracts-test lint devnet-e2e
all: build test

build:
	go build $(GO_PKGS)
	pnpm -r build

test: go-test ts-test contracts-test

go-test:
	go test $(GO_PKGS)

go-vet:
	go vet $(GO_PKGS)

ts-test:
	pnpm -r test

contracts-test:
	$(MAKE) -C contracts test

# The whole trust and payment flow on this machine: anvil, the contracts, key broker, sealed-verifierd, the platform
# api with PostgreSQL, the dstack simulator and sealed-agent as processes (scripts/devnet/README.md).
# DEVNET_ARGS=--keep keeps the run directory and logs.
devnet-e2e:
	scripts/devnet/run.sh $(DEVNET_ARGS)
