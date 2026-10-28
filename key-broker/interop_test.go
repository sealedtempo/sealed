package keybroker_test

import (
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	keybroker "github.com/sealed-dev/sealed/key-broker"
	"github.com/sealed-dev/sealed/key-broker/internal/kbtest"
	"github.com/sealed-dev/sealed/runtime/composer"
)

// coreDist returns node and the built @sealed/core entry point, or skips (fails with SEALED_REQUIRE_NODE=1).
func coreDist(t *testing.T) (node, dist string) {
	t.Helper()
	node, err := exec.LookPath("node")
	dist = repoPath(t, "packages", "core", "dist", "index.js")
	_, distErr := os.Stat(dist)
	if err != nil || distErr != nil {
		if os.Getenv("SEALED_REQUIRE_NODE") == "1" {
			t.Fatalf("SEALED_REQUIRE_NODE=1 but node (%v) or %s (%v) is missing", err, dist, distErr)
		}
		t.Skip("node or a built @sealed/core is missing (pnpm --filter @sealed/core build)")
	}
	return node, dist
}

// TestCoreAgentReleasesFromGoBroker: a boot written only with @sealed/core (the TypeScript agent's library: its
// simulator quote and event log, kb-release report_data, request schema, HPKE open and plaintext schema) gets its
// secrets from the Go broker over HTTP, and a refused boot gets a denial core's schema accepts.
func TestCoreAgentReleasesFromGoBroker(t *testing.T) {
	node, dist := coreDist(t)
	w := kbtest.NewWorld(t, kbtest.NewMemRegistrar())
	h := newHarness(t, w, harnessOpts{})
	srv := httptest.NewServer(h.b.Handler(keybroker.ServerOptions{}))
	defer srv.Close()
	script, _ := filepath.Abs("testdata/core-agent-release.mjs")

	run := func(s *kbtest.Stack) map[string]any {
		t.Helper()
		ids := make([]string, len(s.ReleaseIDs))
		for i, id := range s.ReleaseIDs {
			ids[i] = "0x" + hex.EncodeToString(id[:])
		}
		raw, _ := json.Marshal(map[string]any{"config": s.Config, "appCompose": string(s.Result.AppCompose), "releaseIds": ids, "imageId": "0x" + hex.EncodeToString(s.ImageID[:])})
		p := filepath.Join(t.TempDir(), "stack.json")
		if err := os.WriteFile(p, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(node, script, dist, srv.URL, p).CombinedOutput()
		if err != nil {
			t.Fatalf("node: %v\n%s", err, out)
		}
		var res map[string]any
		if err := json.Unmarshal(out, &res); err != nil {
			t.Fatalf("node output %s", out)
		}
		return res
	}

	s := w.Compose(t, kbtest.StackOptions{Apps: []string{"notes", "llm-gateway"}})
	w.Approve(t, s)
	res := run(s)
	if res["status"] != float64(200) || res["canonical"] != true {
		t.Fatalf("result %v", res)
	}
	dep := s.Result.DeploymentID
	if res["deploymentId"] != dep.Hex() || res["expectedDeploymentId"] != dep.Hex() || res["stackHash"] != s.Result.StackHash.Hex() {
		t.Fatalf("ids %v", res)
	}
	secrets := res["secrets"].(map[string]any)
	if secrets["notes"].(map[string]any)["APP_SECRET"] != "notes-app-secret" || secrets["llm-gateway"].(map[string]any)["MASTER_KEY"] != "sk-gateway-master" ||
		secrets["_gate"].(map[string]any)["GATE_PASSWORD_BCRYPT"] != w.GateHash {
		t.Fatalf("secrets %v", secrets)
	}
	if res["diskKey"] != hmacKey(w.MACKey, keybroker.DiskKeyTag, dep) || !regexp.MustCompile(`^0x[0-9a-f]{40}$`).MatchString(res["signer"].(string)) {
		t.Fatalf("keys %v", res)
	}
	if d := h.log.Last(); d == nil || d.Decision != keybroker.DecisionAllowed || !d.Simulated {
		t.Fatalf("decision %+v", d)
	}

	// Not approved: the denial body passes core's denialSchema and carries the reason.
	other := w.Compose(t, kbtest.StackOptions{Edit: func(c *composer.Config) { c.Salt = "0x" + strings.Repeat("77", 32) }})
	res = run(other)
	if res["status"] != float64(403) || res["denial"].(map[string]any)["reason"] != keybroker.ReasonStackNotApproved {
		t.Fatalf("denial %v", res)
	}
}
