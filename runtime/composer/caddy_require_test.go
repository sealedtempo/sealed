package composer

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// runtime-3: CI sets SEALED_REQUIRE_CADDY=1, so a compose job that lost its
// Caddy binary fails instead of reporting a skipped real-Caddy test as a pass.
// Local runs without either variable still skip. Runs the real-Caddy test in a
// child process of this test binary.
func TestRealCaddyTestIsRequiredInCI(t *testing.T) {
	child := func(require bool) (string, error) {
		var env []string
		for _, kv := range os.Environ() {
			if !strings.HasPrefix(kv, "SEALED_CADDY_BIN=") && !strings.HasPrefix(kv, "SEALED_REQUIRE_CADDY=") {
				env = append(env, kv)
			}
		}
		if require {
			env = append(env, "SEALED_REQUIRE_CADDY=1")
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestCaddyfileWithRealCaddy$", "-test.count=1", "-test.v")
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	out, err := child(true)
	if err == nil {
		t.Fatalf("SEALED_REQUIRE_CADDY=1 without SEALED_CADDY_BIN must fail the real-Caddy test, it passed:\n%s", out)
	}
	if !strings.Contains(out, "SEALED_REQUIRE_CADDY=1 but SEALED_CADDY_BIN is not set") {
		t.Fatalf("the failure must name the missing binary:\n%s", out)
	}
	out, err = child(false)
	if err != nil || !strings.Contains(out, "--- SKIP: TestCaddyfileWithRealCaddy") {
		t.Fatalf("without SEALED_REQUIRE_CADDY the real-Caddy test skips: %v\n%s", err, out)
	}
}
