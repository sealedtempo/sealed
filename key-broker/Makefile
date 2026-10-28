# Key broker targets. Run from the repository root with `make -C key-broker <target>`.
ROOT := ..

.PHONY: test test-ci test-short vet build build-dev image vector

# Unit and integration tests, in the production build and in the dev build (simulated quotes through the binary).
# The anvil tests need anvil and forge on PATH and contracts/dependencies (forge soldeer install); they skip
# otherwise. The TypeScript interop test needs node and a built @sealed/core (pnpm --filter @sealed/core build).
test:
	cd $(ROOT) && go test ./key-broker/... && go test -tags sealeddev ./key-broker/...

# CI: the same with the race detector; a missing anvil, forge, contracts tree, node or core build fails.
test-ci:
	cd $(ROOT) && SEALED_REQUIRE_ANVIL=1 SEALED_REQUIRE_NODE=1 go test -race ./key-broker/... && \
		SEALED_REQUIRE_ANVIL=1 go test -race -tags sealeddev ./key-broker/...

# Without the local chain.
test-short:
	cd $(ROOT) && go test -short ./key-broker/...

vet:
	cd $(ROOT) && go vet ./key-broker/... && go vet -tags sealeddev ./key-broker/...

# The production binary (no build tags).
build:
	cd $(ROOT) && CGO_ENABLED=0 go build -trimpath -o tmp/key-broker/key-broker ./key-broker/cmd/key-broker

# A dev binary for local runs with SEALED_DEV_SIM=1. Never deploy it.
build-dev:
	cd $(ROOT) && go build -tags sealeddev -o tmp/key-broker/key-broker-dev ./key-broker/cmd/key-broker

image:
	cd $(ROOT) && docker build -f key-broker/Dockerfile -t sealed-key-broker .

# Regenerate testdata/hpke-kb-release-vector.json (only when the release encryption changes on purpose).
vector:
	cd $(ROOT) && go test ./key-broker -run TestHPKEReleaseVector -update
