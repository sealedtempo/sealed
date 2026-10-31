// Command sealed-ollama-gate is the entrypoint of the Sealed local-model image.
//
// It starts Ollama on a loopback address and serves the Ollama API on the container's
// network port only to allowed peers (the llm-gateway-litellm service, resolved by name,
// plus loopback for the healthcheck) and only for inference and read endpoints. Other
// apps on the shared apps network therefore cannot run unmetered inference, fill the
// request queue, or touch the model store. An optional bearer key can be required as well
// (-key-env), for when per-service secret mounts exist.
//
//	sealed-ollama-gate [flags] -- /bin/ollama serve
//	sealed-ollama-gate probe http://127.0.0.1:11434/healthz
//	sealed-ollama-gate verify-manifest -manifest <file> -config <hex> -model <hex> ...
//
// Request and response bodies are never logged.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	os.Exit(run(os.Args[1:], os.Environ(), os.Stdout, os.Stderr))
}

func run(args []string, env []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "probe":
			return probe(args[1:], stderr)
		case "verify-manifest":
			return verifyManifestCmd(args[1:], stdout, stderr)
		}
	}
	opts, err := parseServe(args, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "sealed-ollama-gate:", err)
		return 2
	}
	return serve(opts, env, stdout, stderr)
}

type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			*l = append(*l, part)
		}
	}
	return nil
}

type serveOptions struct {
	listen        string
	upstream      string
	peers         []string
	allowLoopback bool
	keyEnv        string
	maxBody       int64
	child         []string
}

func parseServe(args []string, stderr io.Writer) (serveOptions, error) {
	var opts serveOptions
	var peers listFlag
	fs := flag.NewFlagSet("sealed-ollama-gate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opts.listen, "listen", "0.0.0.0:11434", "address served to peers")
	fs.StringVar(&opts.upstream, "upstream", "127.0.0.1:11435", "loopback host:port Ollama listens on (set as OLLAMA_HOST)")
	fs.Var(&peers, "allow-peer", "service name whose addresses may connect (repeatable or comma separated)")
	fs.BoolVar(&opts.allowLoopback, "allow-loopback", true, "admit connections from loopback (healthcheck)")
	fs.StringVar(&opts.keyEnv, "key-env", "", "if set, require Authorization: Bearer <value of this env var>")
	fs.Int64Var(&opts.maxBody, "max-body", 64<<20, "largest request body in bytes")
	sep := len(args)
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	if err := fs.Parse(args[:sep]); err != nil {
		return opts, err
	}
	if fs.NArg() > 0 {
		return opts, fmt.Errorf("unexpected argument %q (put the Ollama command after --)", fs.Arg(0))
	}
	if sep < len(args) {
		opts.child = args[sep+1:]
	}
	if len(opts.child) == 0 {
		return opts, errors.New("missing Ollama command after --")
	}
	host, _, err := net.SplitHostPort(opts.upstream)
	if err != nil {
		return opts, fmt.Errorf("bad -upstream: %w", err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return opts, errors.New("-upstream must be a loopback address, so Ollama is never reachable directly")
	}
	if len(peers) == 0 && !opts.allowLoopback {
		return opts, errors.New("no peer is allowed (use -allow-peer)")
	}
	opts.peers = peers
	return opts, nil
}

// childEnv is the gate's environment with OLLAMA_HOST pointing at the loopback upstream and
// without the bearer key variable.
func childEnv(env []string, upstream, keyEnv string) []string {
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if name == "OLLAMA_HOST" || (keyEnv != "" && name == keyEnv) {
			continue
		}
		out = append(out, kv)
	}
	return append(out, "OLLAMA_HOST="+upstream)
}

func lookupEnv(env []string, name string) string {
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == name {
			return v
		}
	}
	return ""
}

func serve(opts serveOptions, env []string, stdout, stderr io.Writer) int {
	var key []byte
	if opts.keyEnv != "" {
		value := strings.TrimRight(lookupEnv(env, opts.keyEnv), "\r\n")
		if len(value) < 16 {
			fmt.Fprintf(stderr, "sealed-ollama-gate: %s is missing or shorter than 16 characters\n", opts.keyEnv)
			return 2
		}
		key = []byte(value)
	}
	ln, err := net.Listen("tcp", opts.listen)
	if err != nil {
		fmt.Fprintln(stderr, "sealed-ollama-gate:", err)
		return 1
	}
	cmd := exec.Command(opts.child[0], opts.child[1:]...)
	cmd.Env = childEnv(env, opts.upstream, opts.keyEnv)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Start(); err != nil {
		ln.Close()
		fmt.Fprintln(stderr, "sealed-ollama-gate: start ollama:", err)
		return 1
	}
	fmt.Fprintf(stderr, "sealed-ollama-gate: serving %s for peers %v (loopback %t, bearer %t), ollama on %s\n",
		ln.Addr(), opts.peers, opts.allowLoopback, key != nil, opts.upstream)

	srv := &http.Server{
		Handler:           newGate(opts.upstream, newPeerSet(opts.peers, opts.allowLoopback), key, opts.maxBody),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	childDone := make(chan error, 1)
	go func() { childDone <- cmd.Wait() }()
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigs)

	for {
		select {
		case s := <-sigs:
			_ = cmd.Process.Signal(s) // Ollama shuts down; its exit ends the loop
		case err := <-childDone:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = srv.Shutdown(ctx)
			cancel()
			return exitCode(err)
		case err := <-serveErr:
			fmt.Fprintln(stderr, "sealed-ollama-gate: server stopped:", err)
			_ = cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-childDone:
			case <-time.After(10 * time.Second):
				_ = cmd.Process.Kill()
				<-childDone
			}
			return 1
		}
	}
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			return 128 + int(status.Signal())
		}
		return exitErr.ExitCode()
	}
	return 1
}

func probe(args []string, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: sealed-ollama-gate probe <url>")
		return 2
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Get(args[0])
	if err != nil {
		fmt.Fprintln(stderr, "probe:", err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(stderr, "probe: HTTP", resp.StatusCode)
		return 1
	}
	return 0
}

func verifyManifestCmd(args []string, stdout, stderr io.Writer) int {
	var path string
	var pins manifestPins
	fs := flag.NewFlagSet("verify-manifest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&path, "manifest", "", "path of the pulled Ollama manifest")
	fs.StringVar(&pins.Config, "config", "", "config blob sha256 (hex)")
	fs.StringVar(&pins.Model, "model", "", "model (weights) blob sha256")
	fs.StringVar(&pins.Template, "template", "", "template blob sha256")
	fs.StringVar(&pins.License, "license", "", "license blob sha256")
	fs.StringVar(&pins.Params, "params", "", "params blob sha256")
	fs.StringVar(&pins.Nested, "nested", "", "nested manifest blob sha256 (hex)")
	fs.StringVar(&pins.ManifestSHA256, "sha256", "", "optional sha256 of the manifest file")
	if err := fs.Parse(args); err != nil || path == "" {
		fmt.Fprintln(stderr, "usage: sealed-ollama-gate verify-manifest -manifest <file> -config <hex> -model <hex> -template <hex> -license <hex> -params <hex> -nested <hex> [-sha256 <hex>]")
		return 2
	}
	digest, err := verifyManifest(path, pins)
	if digest != "" {
		fmt.Fprintf(stdout, "manifest sha256:%s\n", digest)
	}
	if err != nil {
		fmt.Fprintln(stderr, "verify-manifest:", err)
		return 1
	}
	return 0
}
