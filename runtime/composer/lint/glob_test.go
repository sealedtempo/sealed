package lint

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/sealedtempo/sealed/runtime/composer"
)

func mustPattern(t *testing.T, raw string, policy bool) *pathPattern {
	t.Helper()
	p, err := compilePattern(raw, policy)
	if err != nil {
		t.Fatalf("%q: %v", raw, err)
	}
	return p
}

func TestPatternMatchesFiles(t *testing.T) {
	cases := []struct{ pattern, file, root string }{
		// Anchored "/**": the directory and everything below it, from the root only.
		{"/app/enterprise/**", "app/enterprise/enterprise_hooks/banned_keywords.py", "app/enterprise"},
		{"/app/enterprise/**", "/app/enterprise/LICENSE.md", "app/enterprise"},
		{"/app/enterprise/**", "app/enterprise", "app/enterprise"},
		{"/app/enterprise/**", "srv/app/enterprise/x.py", ""},
		{"/app/enterprise/**", "app/enterprises/x.py", ""},
		{"/app/enterprise/**", "app/litellm/proxy/enterprise_billing/README.md", ""},
		// "**/" prefixes and "*" inside a segment.
		{"**/litellm_enterprise/**", "app/.venv/lib/python3.13/site-packages/litellm_enterprise/__init__.py", "app/.venv/lib/python3.13/site-packages/litellm_enterprise"},
		{"**/litellm_enterprise/**", "app/.venv/lib/python3.13/site-packages/litellm_enterprise_extra/x.py", ""},
		{"**/litellm_enterprise-*.dist-info/**", "app/.venv/lib/python3.13/site-packages/litellm_enterprise-0.1.20.dist-info/METADATA", "app/.venv/lib/python3.13/site-packages/litellm_enterprise-0.1.20.dist-info"},
		{"**/litellm_enterprise-*.dist-info/**", "app/.venv/lib/python3.13/site-packages/litellm-1.106.5.dist-info/METADATA", ""},
		// Unanchored patterns start at any segment; a matched directory covers its files.
		{"ms-playwright/chromium-*", "ms-playwright/chromium-1187/chrome-linux/chrome", "ms-playwright/chromium-1187"},
		{"ms-playwright/chromium-*", "root/.cache/ms-playwright/chromium-1187/INSTALLATION_COMPLETE", "root/.cache/ms-playwright/chromium-1187"},
		{"ms-playwright/chromium-*", "ms-playwright/firefox-1490/firefox/firefox", ""},
		{"ms-playwright/chromium-*", "ms-playwright/chromium_headless_shell-1187/chrome-linux/headless_shell", ""},
		{"ms-playwright/chromium-*", "Ms-Playwright/chromium-1187/chrome", ""}, // file paths are case-sensitive
		{"**/node_modules/@playwright/browser-chromium", "app/node_modules/@playwright/browser-chromium/package.json", "app/node_modules/@playwright/browser-chromium"},
		{"**/node_modules/@playwright/browser-chromium", "app/node_modules/@playwright/browser-chromium-extra/package.json", ""},
		// Trailing "/": directories only, as whole segments.
		{"ee/", "app/server/ee/licensing/license.service.js", "app/server/ee"},
		{"ee/", "app/server/ee", ""},
		{"ee/", "app/server/ee.config.js", ""},
		{"ee/", "app/server/tree/index.js", ""},
		{"ee/", "app/server/src/modules/free/index.js", ""},
		{"ee/", "app/node_modules/ee-first/index.js", ""},
		{"/opt/oracle/", "opt/oracle/instantclient_21_10/libclntsh.so.21.1", "opt/oracle"},
		{"/opt/oracle/", "opt/oracle", ""},
		{"/opt/oracle/", "opt/oraclex/lib.so", ""},
		// Exact files.
		{"/usr/bin/redis-server", "usr/bin/redis-server", "usr/bin/redis-server"},
		{"/usr/bin/redis-server", "./usr/bin/redis-server", "usr/bin/redis-server"},
		{"/usr/bin/redis-server", "usr/bin/redis-server-wrapper", ""},
		{"/usr/bin/redis-server", "usr/local/bin/redis-server", ""},
		// "?" and classes.
		{"/usr/lib/ollama/cuda_v1?/**", "usr/lib/ollama/cuda_v12/libggml-cuda.so", "usr/lib/ollama/cuda_v12"},
		{"/usr/lib/ollama/[cm]*/**", "usr/lib/ollama/mlx_cuda_v13/libmlx.so", "usr/lib/ollama/mlx_cuda_v13"},
		{"/usr/lib/ollama/[cm]*/**", "usr/lib/ollama/vulkan/libggml-vulkan.so", ""},
		{"*.so", "usr/lib/ollama/libggml-cpu-haswell.so", "usr/lib/ollama/libggml-cpu-haswell.so"},
		// "**" in the middle.
		{"/app/**/ee/", "app/server/dist/ee/x.js", "app/server/dist/ee"},
		{"/app/**/ee/", "app/ee/x.js", "app/ee"},
		// Upstream source notes never match.
		{"BerriAI/litellm:enterprise/", "BerriAI/litellm:enterprise/x.py", ""},
		{"anomalyco/opencode:packages/enterprise/", "packages/enterprise/src/index.ts", ""},
	}
	for _, c := range cases {
		if got := mustPattern(t, c.pattern, false).matchFile(c.file); got != c.root {
			t.Errorf("%q on %q: got %q, want %q", c.pattern, c.file, got, c.root)
		}
	}
}

func TestPatternMatchesPackages(t *testing.T) {
	cases := []struct {
		pattern, name string
		files         []string
		want          bool
	}{
		{"**/litellm_enterprise/**", "litellm-enterprise", nil, true},
		{"**/litellm_enterprise/**", "litellm", nil, false},
		{"litellm_enterprise*", "litellm-enterprise", nil, true},
		{"litellm_enterprise*", "LiteLLM_Enterprise", nil, true},
		{"**/litellm_enterprise-*.dist-info/**", "litellm-enterprise", []string{"/app/.venv/lib/python3.13/site-packages/litellm_enterprise-0.1.20.dist-info/METADATA"}, true},
		{"@anthropic-ai/claude-agent-sdk*", "@anthropic-ai/claude-agent-sdk", nil, true},
		{"@anthropic-ai/claude-agent-sdk*", "@Anthropic-AI/claude-agent-sdk-linux-x64", nil, true},
		{"@anthropic-ai/claude-agent-sdk*", "@anthropic-ai/sdk", nil, false},
		{"**/@anthropic-ai/claude-agent-sdk*/**", "@anthropic-ai/claude-agent-sdk", nil, true},
		// A package is a directory, so "enterprise/" matches a module named enterprise.
		{"enterprise/", "github.com/acme/enterprise", nil, true},
		{"enterprise/", "github.com/acme/enterprise/billing", nil, true},
		{"enterprise/", "github.com/acme/enterprises", nil, false},
		{"ee/", "@tooljet/ee", nil, true},
		{"ee/", "ee-first", nil, false},
		// Anchored patterns never match a bare name, only source files.
		{"/usr/bin/redis-server", "redis-server", nil, false},
		{"/acp-node/**", "@zed-industries/claude-code-acp", []string{"/acp-node/node_modules/@zed-industries/claude-code-acp/package.json"}, true},
		{"**/node_modules/idcac-playwright", "idcac-playwright", nil, false},
		{"**/node_modules/idcac-playwright", "idcac-playwright", []string{"/app/node_modules/idcac-playwright/package.json"}, true},
		{"**/node_modules/idcac-playwright", "idcac-playwright", []string{"/pnpm-lock.yaml"}, false},
		{"BerriAI/litellm:enterprise/", "enterprise", nil, false},
	}
	for _, c := range cases {
		if got := mustPattern(t, c.pattern, false).matchPackage(c.name, c.files); got != c.want {
			t.Errorf("%q on package %q %v: got %v", c.pattern, c.name, c.files, got)
		}
	}
}

func TestPatternErrors(t *testing.T) {
	for _, bad := range []string{"", " ", "/", "**", "/**", "**/", "a//b", "a/../b", "./a", "[", "/usr/[x"} {
		if _, err := compilePattern(bad, false); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
	for _, note := range []string{"BerriAI/litellm:enterprise/", "OpenHands/legacy:enterprise/", "anomalyco/opencode:packages/enterprise/"} {
		if p := mustPattern(t, note, false); !p.note {
			t.Errorf("%q: want an upstream source note", note)
		}
	}
}

func TestSourcePaths(t *testing.T) {
	got := sourcePaths("acquired package info from installed python package manifest file: /a/METADATA, /a/RECORD")
	if want := []string{"/a/METADATA", "/a/RECORD"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
	if got := sourcePaths("acquired package info from DPKG DB: /var/lib/dpkg/status, relative"); !reflect.DeepEqual(got, []string{"/var/lib/dpkg/status"}) {
		t.Fatalf("%v", got)
	}
	if sourcePaths("") != nil || sourcePaths("no colon") != nil {
		t.Fatal("expected nil")
	}
}

// catalogPatternCases has a matching and a non-matching image path for every
// license_exclusions pattern in catalog/apps (license audit F6). A new
// pattern fails TestCatalogManifestPatterns until it is listed here; also add
// both paths to testdata/syft-image/make-image-sbom.sh.
var catalogPatternCases = map[string]struct{ pos, neg []string }{
	"OpenHands/legacy:enterprise/":            {},
	"anomalyco/opencode:packages/enterprise/": {},
	"BerriAI/litellm:enterprise/":             {},
	"/acp-node/": {
		[]string{"acp-node/node_modules/@zed-industries/claude-code-acp/package.json"},
		[]string{"app/acp-node/index.js", "acp-node-extra/index.js", "opt/acp-nodes.txt"}},
	"@anthropic-ai/claude-agent-sdk": {
		[]string{"acp-node/node_modules/@anthropic-ai/claude-agent-sdk/cli.js", "usr/lib/node_modules/@anthropic-ai/claude-agent-sdk/cli.js"},
		[]string{"app/node_modules/@anthropic-ai/sdk/index.js"}},
	"litellm_enterprise": {
		[]string{"app/.venv/lib/python3.13/site-packages/litellm_enterprise/__init__.py"},
		[]string{"app/.venv/lib/python3.13/site-packages/litellm/proxy/enterprise_billing/__init__.py", "app/.venv/lib/python3.13/site-packages/litellm/__init__.py"}},
	"/app/enterprise/": {
		[]string{"app/enterprise/enterprise_hooks/banned_keywords.py"},
		[]string{"app/litellm/proxy/enterprise_billing/README.md", "opt/app/enterprise/x.py", "app/enterprise"}},
	// inference-relay (LiteLLM) keeps the glob forms of the same exclusions.
	"**/litellm_enterprise/**": {
		[]string{"app/.venv/lib/python3.13/site-packages/litellm_enterprise/__init__.py"},
		[]string{"app/.venv/lib/python3.13/site-packages/litellm/proxy/enterprise_billing/__init__.py"}},
	"/app/enterprise/**": {
		[]string{"app/enterprise/enterprise_hooks/banned_keywords.py"},
		[]string{"app/litellm/proxy/enterprise_billing/README.md", "opt/app/enterprise/x.py"}},
	"**/litellm_enterprise-*.dist-info/**": {
		[]string{"app/.venv/lib/python3.13/site-packages/litellm_enterprise-0.1.20.dist-info/METADATA"},
		[]string{"app/.venv/lib/python3.13/site-packages/litellm-1.106.5.dist-info/METADATA"}},
	"/usr/lib/ollama/cuda_v12/":     {[]string{"usr/lib/ollama/cuda_v12/libggml-cuda.so"}, []string{"usr/lib/ollama/libggml-cpu-haswell.so"}},
	"/usr/lib/ollama/cuda_v13/":     {[]string{"usr/lib/ollama/cuda_v13/libggml-cuda.so"}, []string{"usr/lib/ollama/cuda_v12/libggml-cuda.so"}},
	"/usr/lib/ollama/mlx_cuda_v13/": {[]string{"usr/lib/ollama/mlx_cuda_v13/libmlx.so"}, []string{"usr/lib/ollama/cuda_v13/libggml-cuda.so"}},
	"/usr/lib/ollama/vulkan/":       {[]string{"usr/lib/ollama/vulkan/libggml-vulkan.so"}, []string{"usr/lib/ollama/libggml-base.so"}},
	"/app/**/ee/": {
		[]string{"app/server/ee/licensing/license.service.js", "app/server/dist/src/modules/ee/stub.js", "app/frontend/build/ee/billing.js"},
		[]string{"app/server/ee.config.js", "app/server/src/modules/free/index.js", "app/server/eeprom.txt", "usr/share/locale/ee/LC_MESSAGES/iso_639.mo"}},
	"/app/server/ee/":          {[]string{"app/server/ee/licensing/license.service.js"}, []string{"app/server/ee.config.js", "app/server/src/modules/free/index.js"}},
	"/app/frontend/ee/":        {[]string{"app/frontend/ee/components/Billing.jsx"}, []string{"app/frontend/build/main.js"}},
	"/app/server/dist/ee/":     {[]string{"app/server/dist/ee/licensing/license.service.js"}, []string{"app/server/dist/main.js"}},
	"/app/frontend/build/ee/":  {[]string{"app/frontend/build/ee/billing.js"}, []string{"app/frontend/build/main.js"}},
	"/opt/oracle/":             {[]string{"opt/oracle/instantclient_21_10/libclntsh.so.21.1"}, []string{"opt/oraclex/lib.so"}},
	"/usr/bin/redis-server":    {[]string{"usr/bin/redis-server"}, []string{"usr/bin/valkey-server", "usr/local/bin/redis-server"}},
	"/usr/bin/redis-check-aof": {[]string{"usr/bin/redis-check-aof"}, []string{"usr/bin/valkey-check-aof"}},
	"/usr/bin/redis-check-rdb": {[]string{"usr/bin/redis-check-rdb"}, []string{"usr/bin/valkey-check-rdb"}},
	"/usr/bin/redis-benchmark": {[]string{"usr/bin/redis-benchmark"}, []string{"usr/bin/valkey-benchmark"}},
	"/usr/bin/redis-cli":       {[]string{"usr/bin/redis-cli"}, []string{"usr/bin/valkey-cli"}},
	"/usr/lib/redis/":          {[]string{"usr/lib/redis/modules/redisearch.so"}, []string{"usr/lib/valkey/modules/x.so"}},
	"/etc/redis/":              {[]string{"etc/redis/redis.conf"}, []string{"etc/valkey/valkey.conf"}},
	"ms-playwright/chromium-*": {
		[]string{"ms-playwright/chromium-1187/chrome-linux/chrome", "root/.cache/ms-playwright/chromium-1187/INSTALLATION_COMPLETE"},
		[]string{"ms-playwright/firefox-1490/firefox/firefox"}},
	"ms-playwright/chromium_headless_shell-*": {
		[]string{"ms-playwright/chromium_headless_shell-1187/chrome-linux/headless_shell"},
		[]string{"ms-playwright/firefox-1490/firefox/firefox", "ms-playwright/chromium-1187/chrome-linux/chrome"}},
	"@playwright/browser-chromium": {
		[]string{"app/node_modules/@playwright/browser-chromium/package.json"},
		[]string{"app/node_modules/@playwright/browser-firefox/package.json", "app/node_modules/@playwright/test/package.json"}},
	"idcac-playwright": {
		[]string{"app/node_modules/idcac-playwright/package.json"},
		[]string{"app/node_modules/playwright/package.json", "app/node_modules/idcac-playwright-extra/index.js"}},
}

// catalogApps reads the manifests in catalog/apps of this checkout.
func catalogApps(t *testing.T) map[string]*composer.Manifest {
	t.Helper()
	root := filepath.Join("..", "..", "..", "catalog", "apps")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Skipf("no catalog in this checkout: %v", err)
	}
	out := map[string]*composer.Manifest{}
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(root, e.Name(), composer.ManifestFile))
		if err != nil {
			continue
		}
		m, err := composer.ParseManifest(raw)
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		out[e.Name()] = m
	}
	if len(out) == 0 {
		t.Skip("no catalog manifests")
	}
	return out
}

func TestCatalogManifestPatterns(t *testing.T) {
	for app, m := range catalogApps(t) {
		for _, raw := range m.LicenseExclusions {
			c, ok := catalogPatternCases[raw]
			if !ok {
				t.Errorf("%s: pattern %q has no test paths: add it to catalogPatternCases", app, raw)
				continue
			}
			p := mustPattern(t, raw, false)
			if p.note != (len(c.pos) == 0) {
				t.Errorf("%s: %q: an upstream source note has no paths, any other pattern needs some", app, raw)
			}
			for _, f := range c.pos {
				if p.matchFile(f) == "" {
					t.Errorf("%s: %q does not match %q", app, raw, f)
				}
			}
			for _, f := range c.neg {
				if got := p.matchFile(f); got != "" {
					t.Errorf("%s: %q matches %q (at %q)", app, raw, f, got)
				}
			}
		}
	}
}

func TestDefaultEnterprisePatterns(t *testing.T) {
	var pats []*pathPattern
	for _, raw := range DefaultEnterprisePatterns {
		pats = append(pats, mustPattern(t, raw, true))
	}
	match := func(f string) bool {
		for _, p := range pats {
			if p.matchFile(f) != "" {
				return true
			}
		}
		return false
	}
	for _, f := range []string{
		"app/server/ee/licensing/license.service.js", // ToolJet (license audit F7)
		"app/frontend/build/ee/billing.js",
		"srv/gitlab/ee/app/models/license.rb",
		"app/packages/twenty-server/src/engine/core-modules/enterprise/key.ts",
		"usr/lib/python3/site-packages/litellm_enterprise/__init__.py",
		"usr/lib/python3/site-packages/litellm_enterprise-0.1.20.dist-info/METADATA",
		"app/node_modules/@anthropic-ai/claude-agent-sdk/cli.js",
	} {
		if !match(f) {
			t.Errorf("defaults miss %q", f)
		}
	}
	for _, f := range []string{
		"app/server/tree/index.js", "app/node_modules/free/index.js", "app/node_modules/ee-first/index.js",
		"app/server/ee.config.js", "app/litellm/proxy/enterprise_billing/x.py", "app/node_modules/@anthropic-ai/sdk/index.js",
	} {
		if match(f) {
			t.Errorf("defaults match %q", f)
		}
	}
}
