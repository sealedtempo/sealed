// Command sealed-egress is the outbound proxy and filtering DNS server for a
// Sealed deployment VM. Usage:
//
//	sealed-egress [-config PATH] [-auth-dir DIR]   run
//	sealed-egress [-config PATH] -check            validate the config and exit
//	sealed-egress [-config PATH] -healthcheck      probe the local /healthz (for compose healthchecks)
//
// The config path comes from -config, else $SEALED_EGRESS_CONFIG, else
// DefaultConfigPath. -auth-dir (default egress.DefaultAuthDir) receives the
// proxy credentials of callers that set proxyAuth.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sealedtempo/sealed/runtime/egress"
	"github.com/sealedtempo/sealed/runtime/egress/policy"
)

// DefaultConfigPath is where the composer mounts the measured egress config.
const DefaultConfigPath = "/etc/sealed/egress.json"

// shutdownTimeout bounds the tunnel drain on SIGTERM. Docker sends SIGKILL
// 10 seconds after SIGTERM unless stop_grace_period says otherwise, and the
// drain must finish (and the final counts line be written) before that.
const shutdownTimeout = 8 * time.Second

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("sealed-egress", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to the egress config (CJSON); default $SEALED_EGRESS_CONFIG or "+DefaultConfigPath)
	check := fs.Bool("check", false, "validate the config and exit")
	healthcheck := fs.Bool("healthcheck", false, "probe the local stats /healthz endpoint and exit")
	authDir := fs.String("auth-dir", egress.DefaultAuthDir, "directory for the proxy credentials of proxyAuth callers")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	logger := slog.New(slog.NewJSONHandler(stderr, nil))

	path := resolveConfigPath(*configPath)
	cfg, raw, err := policy.Load(path)
	if err != nil {
		logger.Error("config rejected", "path", path, "error", err.Error())
		return 2
	}
	if *check {
		fmt.Fprintf(stderr, "ok %s sha256:%s\n", path, digest(raw))
		return 0
	}
	if *healthcheck {
		if err := probe(cfg.Listen.Stats); err != nil {
			fmt.Fprintln(stderr, "unhealthy:", err)
			return 1
		}
		return 0
	}

	// goproxy would honor these and chain through another proxy.
	for _, v := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"} {
		if os.Getenv(v) != "" {
			logger.Warn("ignoring proxy environment variable", "name", v)
			os.Unsetenv(v)
		}
	}

	// Catch signals before serving so an early SIGTERM still shuts down cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	svc, err := egress.Start(cfg, egress.Options{Logger: logger, AuthDir: *authDir})
	if err != nil {
		logger.Error("start failed", "error", err.Error())
		return 1
	}
	logger.Info("sealed-egress started",
		"config_sha256", digest(raw),
		"callers", len(cfg.Callers),
		"proxy_auth_callers", len(policyAuthCallers(cfg)),
		"proxy", svc.ProxyAddr.String(),
		"dns", svc.DNSUDPAddr.String(),
		"stats", svc.StatsAddr.String(),
	)

	code := 0
	select {
	case <-ctx.Done():
		logger.Info("shutting down")
	case err := <-svc.Err():
		logger.Error("serve failed", "error", err.Error())
		code = 1
	}
	sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := svc.Shutdown(sctx); err != nil {
		logger.Error("shutdown", "error", err.Error())
	}
	return code
}

func policyAuthCallers(cfg *policy.Config) []string {
	var names []string
	for _, c := range cfg.Callers {
		if c.ProxyAuth {
			names = append(names, c.Name)
		}
	}
	return names
}

func resolveConfigPath(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if env := os.Getenv("SEALED_EGRESS_CONFIG"); env != "" {
		return env
	}
	return DefaultConfigPath
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// probe GETs /healthz on the stats listener via loopback.
func probe(statsListen string) error {
	host, port, err := net.SplitHostPort(statsListen)
	if err != nil {
		return err
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}
