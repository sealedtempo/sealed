// Command sealed-verifierd serves the Sealed verifier over HTTP (spec 8.5): evidence bundles, live attestations
// and stack composition. It only reads the chain (eth_call) and Intel PCS; it holds no keys.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	verify "github.com/sealedtempo/sealed/verifier"
	"github.com/sealedtempo/sealed/verifier/attest"
	"github.com/sealedtempo/sealed/verifier/chain"
	"github.com/sealedtempo/sealed/verifier/httpapi"
)

// composerFactory builds the stack composer (composer.go). Tests replace it; nil leaves the daemon without a
// composer, so stack recomputation fails closed and POST /v1/compose answers 501.
var composerFactory = newComposer

// signaturesFactory builds the release signature checker (composer.go). Tests replace it; nil leaves the daemon
// without one, so release_signature fails closed outside dev mode.
var signaturesFactory = newSignatures

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(os.Args[1:], os.Getenv, log); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		log.Error("sealed-verifierd", "err", err)
		os.Exit(1)
	}
}

func run(args []string, getenv func(string) string, log *slog.Logger) error {
	c, err := loadConfig(args, getenv, os.Stderr)
	if err != nil {
		return err
	}
	srv, err := newServer(context.Background(), c, log)
	if err != nil {
		return err
	}
	hs := &http.Server{
		Addr:              c.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      3 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- hs.ListenAndServe() }()
	log.Info("listening", "addr", c.Listen, "chainId", c.ChainID, "rpc", chain.RedactURL(c.RPCURL), "allowSimulated", c.AllowSimulated,
		"addresses", c.AddrSource, "deploymentRegistry", c.Addrs.DeploymentRegistry.Hex(),
		"composer", srv.Deps.Composer != nil, "releaseSignatures", srv.Deps.Signatures != nil, "composerVersion", srv.ComposerVersion(), "maxBodyBytes", httpapi.MaxBodyBytes, "releaseAssetBases", c.ReleaseAssetBases, "bundleCache", orMemory(c.BundleCacheDir),
		"liveAllowedHosts", c.LiveHosts, "liveFetch", c.LiveFetch, "allowedClients", c.AllowedClients,
		"maxChainHeadAge", c.MaxChainHeadAge.String(), "maxInFlight", c.MaxInFlight)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return hs.Shutdown(shutdown)
}

func newServer(ctx context.Context, c *config, log *slog.Logger) (*httpapi.Server, error) {
	getter, err := attest.NewCachingGetter(attest.CacheOptions{Dir: c.CacheDir, TTL: c.CacheTTL})
	if err != nil {
		return nil, err
	}
	quotes, err := attest.NewVerifier(attest.VerifierOptions{AllowSimulated: c.AllowSimulated, Getter: getter, TCBPolicy: c.TCBPolicy, AllowedXFAM: c.AllowedXFAM})
	if err != nil {
		return nil, err
	}
	if c.AllowSimulated {
		log.Warn("DEV MODE: simulated quotes are accepted; reports are flagged simulated", "env", devSimEnv)
	}
	if c.LivePrivate {
		log.Warn("DEV MODE: live verification may fetch loopback and private addresses", "env", devSimEnv)
	}
	if c.StackConfigFile != "" && len(c.AllowedClients) == 0 {
		log.Warn("running as a stack sidecar without --allowed-clients: every container that reaches this API is served (D-061 expects the payer's address)")
	}
	reader, err := chain.Dial(ctx, c.RPCURL, c.Addrs)
	if err != nil {
		return nil, err
	}
	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	switch id, err := reader.ChainID(checkCtx); {
	case err != nil:
		log.Warn("Tempo RPC not reachable at startup; verifications fail until it is", "err", err)
	case id != c.ChainID:
		return nil, fmt.Errorf("RPC %s is chain %d, expected %d", chain.RedactURL(c.RPCURL), id, c.ChainID)
	}
	deps := verify.Deps{Quotes: quotes, Chain: reader}
	if composerFactory != nil {
		if deps.Composer, err = composerFactory(c, reader); err != nil {
			return nil, err
		}
	} else {
		log.Warn("no composer: stack_recompute fails closed and /v1/compose returns 501")
	}
	if signaturesFactory != nil {
		if deps.Signatures, err = signaturesFactory(c); err != nil {
			return nil, err
		}
	}
	return &httpapi.Server{
		Deps: deps, ChainID: c.ChainID, LiveInsecureTLS: c.InsecureLiveTLS, LiveTimeout: c.LiveTimeout,
		LiveAllowedHosts: c.LiveHosts, LiveAllowPrivate: c.LivePrivate, MaxInFlight: c.MaxInFlight, Log: log,
		AllowedClients: c.AllowedClients, DisableLiveFetch: !c.LiveFetch, MaxChainHeadAge: c.MaxChainHeadAge,
	}, nil
}

func orMemory(dir string) string {
	if dir == "" {
		return "memory"
	}
	return dir
}
