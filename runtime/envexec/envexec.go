// Command envexec is the entrypoint wrapper for every Sealed app container
// (INTERFACES section 14). It waits for the secrets-ready gate written by
// sealed-agent, exports the service's declared secrets from
// /run/sealed/secrets/<app>/<NAME> as environment variables and execs the
// original entrypoint. It also installs itself into the shared sealed-bin
// volume (sealed-init) and serves as an image-independent healthcheck probe.
//
//	envexec --app <id> [--secret NAME]... [--optional-secret NAME]... -- <cmd> [args...]
//	envexec install <dir>
//	envexec probe <tcp://host:port | http://host:port/path>
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Defaults match the composer's in-VM layout.
const (
	defaultSecretsDir = "/run/sealed/secrets"
	defaultReady      = "/run/sealed/ready"
	readyMarker       = "ok"
	maxSecretBytes    = 64 << 10
	pollInterval      = 500 * time.Millisecond
)

var (
	appRe    = regexp.MustCompile(`^[a-z0-9_][a-z0-9_-]{0,63}$`)
	secretRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)
)

// runOptions is the parsed command line of the run mode.
type runOptions struct {
	App        string
	Required   []string
	Optional   []string
	SecretsDir string
	Ready      string
	Timeout    time.Duration
	Command    []string
}

func parseRunArgs(args []string) (*runOptions, error) {
	o := &runOptions{SecretsDir: defaultSecretsDir, Ready: defaultReady}
	seen := map[string]bool{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			o.Command = args[i+1:]
			break
		}
		if i+1 >= len(args) {
			return nil, fmt.Errorf("flag %s needs a value", a)
		}
		val := args[i+1]
		i++
		switch a {
		case "--app":
			o.App = val
		case "--secret", "--optional-secret":
			if !secretRe.MatchString(val) {
				return nil, fmt.Errorf("invalid secret name %q", val)
			}
			if seen[val] {
				return nil, fmt.Errorf("secret %q listed twice", val)
			}
			seen[val] = true
			if a == "--secret" {
				o.Required = append(o.Required, val)
			} else {
				o.Optional = append(o.Optional, val)
			}
		case "--secrets-dir":
			o.SecretsDir = val
		case "--ready":
			o.Ready = val
		case "--timeout":
			d, err := time.ParseDuration(val)
			if err != nil || d < 0 {
				return nil, fmt.Errorf("invalid --timeout %q", val)
			}
			o.Timeout = d
		default:
			return nil, fmt.Errorf("unknown flag %q", a)
		}
	}
	if !appRe.MatchString(o.App) {
		return nil, fmt.Errorf("--app %q is not a valid app id", o.App)
	}
	if len(o.Command) == 0 {
		return nil, errors.New("missing command after --")
	}
	return o, nil
}

// isReady reports whether the gate is open: the ready path is a regular
// file, or a directory (the shared tmpfs volume) that contains "ok".
func isReady(ready string) bool {
	st, err := os.Stat(ready)
	if err != nil {
		return false
	}
	if st.Mode().IsRegular() {
		return true
	}
	if st.IsDir() {
		m, err := os.Stat(filepath.Join(ready, readyMarker))
		return err == nil && m.Mode().IsRegular()
	}
	return false
}

// waitReady blocks until the gate opens or the timeout (0 = none) expires.
func waitReady(ready string, timeout time.Duration, log io.Writer) error {
	start := time.Now()
	logged := false
	for !isReady(ready) {
		if !logged {
			fmt.Fprintf(log, "envexec: waiting for %s\n", ready)
			logged = true
		}
		if timeout > 0 && time.Since(start) >= timeout {
			return fmt.Errorf("%s not ready after %s", ready, timeout)
		}
		time.Sleep(pollInterval)
	}
	return nil
}

// loadSecrets reads the declared secrets. Values are the exact file bytes.
func loadSecrets(o *runOptions) (map[string]string, error) {
	dir := filepath.Join(o.SecretsDir, o.App)
	out := map[string]string{}
	read := func(name string, required bool) error {
		b, err := readLimited(filepath.Join(dir, name))
		if errors.Is(err, os.ErrNotExist) && !required {
			return nil
		}
		if err != nil {
			return fmt.Errorf("secret %s: %w", name, err)
		}
		if strings.ContainsRune(string(b), 0) {
			return fmt.Errorf("secret %s contains a NUL byte", name)
		}
		out[name] = string(b)
		return nil
	}
	for _, n := range o.Required {
		if err := read(n, true); err != nil {
			return nil, err
		}
	}
	for _, n := range o.Optional {
		if err := read(n, false); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func readLimited(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxSecretBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxSecretBytes {
		return nil, fmt.Errorf("larger than %d bytes", maxSecretBytes)
	}
	return b, nil
}

// buildEnv returns base with the secrets set, replacing existing entries.
func buildEnv(base []string, secrets map[string]string) []string {
	out := make([]string, 0, len(base)+len(secrets))
	for _, kv := range base {
		k, _, _ := strings.Cut(kv, "=")
		if _, override := secrets[k]; override {
			continue
		}
		out = append(out, kv)
	}
	for _, k := range sortedKeys(secrets) {
		out = append(out, k+"="+secrets[k])
	}
	return out
}

// install copies the running binary to dir/envexec atomically with mode 0755.
func install(self, dir string) error {
	src, err := os.Open(self)
	if err != nil {
		return err
	}
	defer src.Close()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".envexec-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, src); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, "envexec"))
}

// probe checks a tcp:// address (connect only) or an http:// URL (status
// below 400). It never uses proxy settings.
func probe(target string, timeout time.Duration) error {
	u, err := url.Parse(target)
	if err != nil {
		return err
	}
	if u.Port() == "" {
		return fmt.Errorf("%s: port required", target)
	}
	deadline := time.Now().Add(timeout)
	conn, err := net.DialTimeout("tcp", u.Host, timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	switch u.Scheme {
	case "tcp":
		return nil
	case "http":
	default:
		return fmt.Errorf("%s: scheme must be tcp or http", target)
	}
	_ = conn.SetDeadline(deadline)
	path := u.RequestURI()
	if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: sealed-envexec-probe\r\nConnection: close\r\n\r\n", path, u.Host); err != nil {
		return err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return fmt.Errorf("reading status: %w", err)
	}
	fields := strings.Fields(line)
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "HTTP/") {
		return fmt.Errorf("malformed status line %q", strings.TrimSpace(line))
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil {
		return fmt.Errorf("malformed status %q", fields[1])
	}
	if code >= 400 {
		return fmt.Errorf("status %d", code)
	}
	return nil
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
