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

	verify "github.com/sealed-dev/sealed/verifier"
	"github.com/sealed-dev/sealed/verifier/attest"
	"github.com/sealed-dev/sealed/verifier/chain"
	"github.com/sealed-dev/sealed/verifier/httpapi"
)

// composerFactory wires runtime/composer once it is merged (see composer.go). Until then it is nil: stack
// recomputation fails closed and POST /v1/compose answers 501.
var composerFactory func(c *config, reader verify.ChainReader) (verify.Composer, error)

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
		"composer", srv.Deps.Composer != nil, "liveAllowedHosts", c.LiveHosts, "maxInFlight", c.MaxInFlight)
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
	quotes, err := attest.NewVerifier(attest.VerifierOptions{AllowSimulated: c.AllowSimulated, Getter: getter, TCBPolicy: c.TCBPolicy})
	if err != nil {
		return nil, err
	}
	if c.AllowSimulated {
		log.Warn("DEV MODE: simulated quotes are accepted; reports are flagged simulated", "env", devSimEnv)
	}
	if c.LivePrivate {
		log.Warn("DEV MODE: live verification may fetch loopback and private addresses", "env", devSimEnv)
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
		log.Warn("composer not wired: stack_recompute fails closed and /v1/compose returns 501")
	}
	return &httpapi.Server{
		Deps: deps, ChainID: c.ChainID, LiveInsecureTLS: c.InsecureLiveTLS, LiveTimeout: c.LiveTimeout,
		LiveAllowedHosts: c.LiveHosts, LiveAllowPrivate: c.LivePrivate, MaxInFlight: c.MaxInFlight, Log: log,
	}, nil
}
