package composer

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Tests for the composer 1.2.0 rules (integration brief items 4 to 15).

// serviceNetworks returns the networks a composed service joins.
func serviceNetworks(t *testing.T, doc map[string]any, name string) []string {
	t.Helper()
	nets, _ := svc(doc, name)["networks"].(map[string]any)
	return sortedKeys(nets)
}

// appOfService maps every app service in the fixture stack to its app.
func appServices(r *Result) map[string]string {
	var si struct {
		Apps []struct {
			ID       string `json:"id"`
			Services []struct {
				Name    string `json:"name"`
				Primary bool   `json:"primary"`
			} `json:"services"`
		} `json:"apps"`
	}
	_ = json.Unmarshal(r.StackInfo, &si)
	out := map[string]string{}
	for _, a := range si.Apps {
		for _, s := range a.Services {
			out[s.Name] = a.ID
		}
	}
	return out
}

// TestAppsCannotReachOtherAppsServices checks network membership in the
// composed document (D-041): two containers can talk only if they share a
// network, so a service of one app can reach another app's service only
// when both are primaries on the shared apps network.
func TestAppsCannotReachOtherAppsServices(t *testing.T) {
	cfg, bundles := fixtureStack(t)
	relay := buildFixture(t, "inference-relay")
	// A third app with its own database shows the rule is pairwise.
	cfg = testConfig(append(bundles, relay)...)
	r := mustCompose(t, cfg, append(bundles, relay)...)
	doc := composeDoc(t, r)
	owner := appServices(r)
	primaries := map[string]bool{"notes-web": true, "llm-gateway-proxy": true, "inference-relay-front": true}
	members := map[string]map[string]bool{} // network -> services
	for _, name := range sortedKeys(doc["services"].(map[string]any)) {
		for _, n := range serviceNetworks(t, doc, name) {
			if members[n] == nil {
				members[n] = map[string]bool{}
			}
			members[n][name] = true
		}
	}
	for name, app := range owner {
		nets := serviceNetworks(t, doc, name)
		want := []string{"app-" + app}
		if primaries[name] {
			want = []string{"app-" + app, "apps"}
		}
		if strings.Join(nets, ",") != strings.Join(want, ",") {
			t.Errorf("%s joins %v, want %v", name, nets, want)
		}
	}
	shareNetwork := func(a, b string) bool {
		for _, m := range members {
			if m[a] && m[b] {
				return true
			}
		}
		return false
	}
	for a, appA := range owner {
		for b, appB := range owner {
			if appA == appB {
				if !shareNetwork(a, b) {
					t.Errorf("%s and %s of %s cannot reach each other", a, b, appA)
				}
				continue
			}
			want := primaries[a] && primaries[b]
			if got := shareNetwork(a, b); got != want {
				t.Errorf("%s (%s) and %s (%s) share a network: %v, want %v", a, appA, b, appB, got, want)
			}
		}
	}
	// notes-db is reachable only from its own app and from the sidecars
	// that join every app network.
	for name := range members["app-notes"] {
		if owner[name] != "notes" && name != "sealed-egress" && name != "sealed-agent" {
			t.Errorf("%s is on app-notes", name)
		}
	}
	// Caddy, the payer and verifierd stay on the shared network only.
	for _, name := range []string{"caddy", "sealed-mpp-payer", "sealed-verifierd"} {
		for _, n := range serviceNetworks(t, doc, name) {
			if strings.HasPrefix(n, AppNetworkPrefix) {
				t.Errorf("%s joins %s", name, n)
			}
		}
	}
	// Every service's DNS and proxy point at sealed-egress on its own app network.
	for name, app := range owner {
		var si stackInfoDoc
		_ = json.Unmarshal(r.StackInfo, &si)
		var egress string
		for _, a := range si.Apps {
			if a.ID == app {
				egress = a.Network.Egress
			}
		}
		s := svc(doc, name)
		env := s["environment"].(map[string]any)
		if !jsonEqual(s["dns"], []any{egress}) || env["HTTPS_PROXY"] != "http://"+egress+":3128" || env["http_proxy"] != "http://"+egress+":3128" {
			t.Errorf("%s: dns %v proxy %v, want %s", name, s["dns"], env["HTTPS_PROXY"], egress)
		}
		if !contains(serviceNetworks(t, doc, "sealed-egress"), "app-"+app) {
			t.Errorf("egress is not on app-%s", app)
		}
	}
}

func TestStackInfoListsEveryAddress(t *testing.T) {
	cfg, bundles := fixtureStack(t)
	r := mustCompose(t, cfg, bundles...)
	var si stackInfoDoc
	if err := json.Unmarshal(r.StackInfo, &si); err != nil {
		t.Fatal(err)
	}
	doc := composeDoc(t, r)
	var ec struct {
		Callers []struct{ Name, IP string } `json:"callers"`
	}
	if err := json.Unmarshal(r.EgressConfig, &ec); err != nil {
		t.Fatal(err)
	}
	callerIPs := map[string]bool{}
	for _, c := range ec.Callers {
		callerIPs[c.IP] = true
	}
	for _, a := range si.Apps {
		if a.Network.Name != "app-"+a.ID || a.Network.Agent == "" {
			t.Errorf("%s network %+v", a.ID, a.Network)
		}
		for _, s := range a.Services {
			var got []string
			for _, n := range serviceNetworks(t, doc, s.Name) {
				got = append(got, svc(doc, s.Name)["networks"].(map[string]any)[n].(map[string]any)["ipv4_address"].(string))
				if s.Networks[n] == "" {
					t.Errorf("%s: network %s missing from stack info", s.Name, n)
				}
			}
			sortIPs(got)
			if strings.Join(got, ",") != strings.Join(s.IPs, ",") {
				t.Errorf("%s: compose IPs %v, stack IPs %v", s.Name, got, s.IPs)
			}
			if s.IP != s.Networks["app-"+a.ID] {
				t.Errorf("%s: ip %s is not its app-network address", s.Name, s.IP)
			}
			for _, ip := range s.IPs {
				if !callerIPs[ip] {
					t.Errorf("%s: %s is not an egress caller", s.Name, ip)
				}
			}
		}
	}
}

// TestServiceGetsOnlyDeclaredSecretFiles: a service mounts exactly the
// secret files it lists in x-sealed-secrets, read-only (D-042).
func TestServiceGetsOnlyDeclaredSecretFiles(t *testing.T) {
	cfg, bundles := fixtureStack(t)
	r := mustCompose(t, cfg, bundles...)
	doc := composeDoc(t, r)
	want := map[string][]string{
		"notes-web":         {"/run/sealed/secrets/notes/APP_SECRET", "/run/sealed/secrets/notes/DB_PASSWORD", "/run/sealed/secrets/notes/SMTP_PASSWORD"},
		"notes-db":          {"/run/sealed/secrets/notes/DB_PASSWORD"},
		"llm-gateway-proxy": {"/run/sealed/secrets/llm-gateway/MASTER_KEY"},
		"sealed-mpp-payer":  {"/run/sealed/secrets/sealed-mpp-payer/ENCLAVE_KEY", "/run/sealed/secrets/sealed-mpp-payer/SPEND_LIMIT_PER_DAY"},
		"caddy":             nil,
		"sealed-egress":     nil,
		"sealed-verifierd":  nil,
		"sealed-init":       nil,
	}
	for name, files := range want {
		var got []string
		vols, _ := svc(doc, name)["volumes"].([]any)
		for _, v := range vols {
			m := v.(map[string]any)
			tgt, _ := m["target"].(string)
			if !strings.HasPrefix(tgt, SecretsRoot) {
				continue
			}
			if m["type"] != "bind" || m["source"] != tgt || m["read_only"] != true {
				t.Errorf("%s: secret mount %v is not a read-only file bind", name, m)
			}
			got = append(got, tgt)
		}
		sort.Strings(got)
		if strings.Join(got, ",") != strings.Join(files, ",") {
			t.Errorf("%s secret mounts %v, want %v", name, got, files)
		}
	}
	// No Docker volume holds secrets any more, and the agent writes the
	// host directory every file bind comes from.
	for _, v := range sortedKeys(doc["volumes"].(map[string]any)) {
		if strings.Contains(v, "secret") {
			t.Errorf("volume %s", v)
		}
	}
	var si struct {
		SecretsRoot string   `json:"secretsRoot"`
		SecretFiles []string `json:"secretFiles"`
	}
	_ = json.Unmarshal(r.StackInfo, &si)
	var all []string
	for _, files := range want {
		all = append(all, files...)
	}
	all = sortedStrings(all)
	if si.SecretsRoot != SecretsRoot || strings.Join(si.SecretFiles, ",") != strings.Join(all, ",") {
		t.Errorf("stack secretFiles %v, want %v", si.SecretFiles, all)
	}
	agentVols, _ := json.Marshal(svc(doc, "sealed-agent")["volumes"])
	if !strings.Contains(string(agentVols), `{"bind":{"create_host_path":true},"source":"/run/sealed/secrets","target":"/run/sealed/secrets","type":"bind"}`) {
		t.Errorf("agent secrets root mount: %s", agentVols)
	}
	// envexec still exports only the declared names.
	ep := svc(doc, "notes-db")["entrypoint"].([]any)
	if !jsonEqual(ep, []any{EnvexecPath, "--app", "notes", "--secret", "DB_PASSWORD", "--", "docker-entrypoint.sh"}) {
		t.Errorf("notes-db entrypoint %v", ep)
	}
}

// writeApp copies a fixture and applies text replacements to its files.
func writeApp(t *testing.T, app string, edits map[string][][2]string) string {
	t.Helper()
	dir := copyFixture(t, app)
	for file, reps := range edits {
		p := filepath.Join(dir, file)
		src := string(mustRead(t, p))
		for _, r := range reps {
			if r[0] == "" {
				src += r[1]
				continue
			}
			if !strings.Contains(src, r[0]) {
				t.Fatalf("%s: %q not found", file, r[0])
			}
			src = strings.Replace(src, r[0], r[1], 1)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func buildDir(t *testing.T, dir string) (*Bundle, error) {
	t.Helper()
	return BuildBundle(BuildInput{AppDir: dir, Registry: testRegistry})
}

func TestSameAs(t *testing.T) {
	gw := buildFixture(t, "llm-gateway")
	notesWith := func(secret string) *Bundle {
		t.Helper()
		dir := writeApp(t, "notes", map[string][][2]string{
			ManifestFile: {{"telemetry_off_env:", secret + "telemetry_off_env:"}},
			FragmentFile: {{"x-sealed-secrets: [DB_PASSWORD]", "x-sealed-secrets: [DB_PASSWORD, LLM_KEY]"}},
		})
		b, err := buildDir(t, dir)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	ok := notesWith("  - name: LLM_KEY\n    description: Gateway key\n    generate: none\n    same_as: llm-gateway/MASTER_KEY\n")
	r := mustCompose(t, testConfig(ok, gw), ok, gw)
	var si struct {
		Apps []struct {
			ID      string `json:"id"`
			Secrets []struct {
				Name   string `json:"name"`
				SameAs string `json:"sameAs"`
			} `json:"secrets"`
		} `json:"apps"`
	}
	_ = json.Unmarshal(r.StackInfo, &si)
	found := false
	for _, s := range si.Apps[1].Secrets {
		if s.Name == "LLM_KEY" && s.SameAs == "llm-gateway/MASTER_KEY" {
			found = true
		}
	}
	if !found {
		t.Errorf("sameAs not in stack info: %+v", si.Apps[1].Secrets)
	}
	// The referenced app must be in the stack.
	if _, err := Compose(testConfig(ok), []*Bundle{ok}); err == nil || !strings.Contains(err.Error(), "not in this stack") {
		t.Errorf("missing referenced app: %v", err)
	}
	// ...and declare the secret.
	bad := notesWith("  - name: LLM_KEY\n    description: Gateway key\n    generate: none\n    same_as: llm-gateway/NOPE\n")
	if _, err := Compose(testConfig(bad, gw), []*Bundle{bad, gw}); err == nil || !strings.Contains(err.Error(), "declares no secret") {
		t.Errorf("undeclared referenced secret: %v", err)
	}
	// A required secret cannot point at an optional one.
	relay := buildFixture(t, "inference-relay")
	dir := writeApp(t, "inference-relay", map[string][][2]string{ManifestFile: {{"    generate: password\n", "    generate: password\n    optional: true\n"}}})
	optRelay, err := buildDir(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	req := notesWith("  - name: LLM_KEY\n    description: Relay key\n    generate: none\n    same_as: inference-relay/MPP_SECRET_KEY\n")
	if _, err := Compose(testConfig(req, optRelay), []*Bundle{req, optRelay}); err == nil || !strings.Contains(err.Error(), "optional") {
		t.Errorf("required secret referencing an optional one: %v", err)
	}
	mustCompose(t, testConfig(req, relay), req, relay)
	// Manifest rules: generate none, no self reference, syntax.
	for name, entry := range map[string]string{
		"generate":  "  - name: LLM_KEY\n    description: x\n    generate: hex32\n    same_as: llm-gateway/MASTER_KEY\n",
		"self":      "  - name: LLM_KEY\n    description: x\n    generate: none\n    same_as: notes/APP_SECRET\n",
		"syntax":    "  - name: LLM_KEY\n    description: x\n    generate: none\n    same_as: llm-gateway:MASTER_KEY\n",
		"lowercase": "  - name: LLM_KEY\n    description: x\n    generate: none\n    same_as: llm-gateway/master_key\n",
	} {
		dir := writeApp(t, "notes", map[string][][2]string{ManifestFile: {{"telemetry_off_env:", entry + "telemetry_off_env:"}}})
		if _, err := buildDir(t, dir); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A chain is refused: point at the original secret.
	chainDir := writeApp(t, "llm-gateway", map[string][][2]string{ManifestFile: {{"telemetry_off_env:", "  - name: RELAY_KEY\n    description: x\n    generate: none\n    same_as: inference-relay/MPP_SECRET_KEY\n" + "telemetry_off_env:"}}})
	gwChain, err := buildDir(t, chainDir)
	if err != nil {
		t.Fatal(err)
	}
	chain := notesWith("  - name: LLM_KEY\n    description: x\n    generate: none\n    same_as: llm-gateway/RELAY_KEY\n")
	cfg := testConfig(chain, gwChain, relay)
	if _, err := Compose(cfg, []*Bundle{chain, gwChain, relay}); err == nil || !strings.Contains(err.Error(), "itself a reference") {
		t.Errorf("chain: %v", err)
	}
}

func TestPasswordGeneratorInSchema(t *testing.T) {
	relay := buildFixture(t, "inference-relay")
	if s, _ := relay.Manifest.Secret("MPP_SECRET_KEY"); s.Generate != "password" {
		t.Fatalf("fixture secret %+v", s)
	}
	dir := writeApp(t, "inference-relay", map[string][][2]string{ManifestFile: {{"generate: password", "generate: passphrase"}}})
	if _, err := buildDir(t, dir); err == nil {
		t.Error("unknown generator accepted")
	}
}

func TestPublicURLEnv(t *testing.T) {
	if got := PublicURLEnv("tools"); got != "SEALED_PUBLIC_URL_TOOLS" {
		t.Error(got)
	}
	if got := PublicURLEnv("my-route"); got != "SEALED_PUBLIC_URL_MY_ROUTE" {
		t.Error(got)
	}
	cfg, bundles := fixtureStack(t)
	relay := buildFixture(t, "inference-relay")
	cfg = testConfig(append(bundles, relay)...)
	r := mustCompose(t, cfg, append(bundles, relay)...)
	doc := composeDoc(t, r)
	want := map[string]map[string]string{
		"notes":           {"SEALED_PUBLIC_URL_TOOLS": "https://tools.34-1-2-3.sslip.io"},
		"llm-gateway":     {"SEALED_PUBLIC_URL_GATEWAY": "https://gateway.34-1-2-3.sslip.io"},
		"inference-relay": {"SEALED_PUBLIC_URL_RELAY": "https://attest.34-1-2-3.sslip.io"},
	}
	for name, app := range appServices(r) {
		env := svc(doc, name)["environment"].(map[string]any)
		var got []string
		for k, v := range env {
			if strings.HasPrefix(k, PublicURLEnvPrefix) {
				got = append(got, k+"="+v.(string))
				if strings.HasSuffix(v.(string), "/") {
					t.Errorf("%s: %s has a trailing slash", name, k)
				}
			}
		}
		var exp []string
		for k, v := range want[app] {
			exp = append(exp, k+"="+v)
		}
		sort.Strings(got)
		sort.Strings(exp)
		if strings.Join(got, " ") != strings.Join(exp, " ") {
			t.Errorf("%s (%s): %v, want %v", name, app, got, exp)
		}
	}
	for _, name := range []string{"caddy", "sealed-agent", "sealed-mpp-payer"} {
		for k := range svc(doc, name)["environment"].(map[string]any) {
			if strings.HasPrefix(k, PublicURLEnvPrefix) {
				t.Errorf("sidecar %s has %s", name, k)
			}
		}
	}
	// Fragments and manifests cannot set the variables themselves.
	dir := writeApp(t, "notes", map[string][][2]string{FragmentFile: {{"NOTES_WORKERS: 2", "NOTES_WORKERS: 2\n      SEALED_PUBLIC_URL_TOOLS: https://evil.example"}}})
	if _, err := buildDir(t, dir); err == nil || !strings.Contains(err.Error(), "set by the composer") {
		t.Errorf("fragment set SEALED_PUBLIC_URL_TOOLS: %v", err)
	}
	dir = writeApp(t, "notes", map[string][][2]string{ManifestFile: {{"  DO_NOT_TRACK: \"1\"", "  DO_NOT_TRACK: \"1\"\n  SEALED_PUBLIC_URL_X: y"}}})
	if _, err := buildDir(t, dir); err == nil || !strings.Contains(err.Error(), "set by the composer") {
		t.Errorf("telemetry_off_env set SEALED_PUBLIC_URL_X: %v", err)
	}
}

func TestRelayOnAttestHost(t *testing.T) {
	relay := buildFixture(t, "inference-relay")
	cfg := testConfig(relay)
	r := mustCompose(t, cfg, relay)
	cf := string(r.Caddyfile)
	if strings.Contains(cf, "relay.34-1-2-3.sslip.io") {
		t.Error("relay route got its own host")
	}
	attest := cf[strings.Index(cf, "\nattest.34-1-2-3.sslip.io {"):]
	for _, want := range []string{"@attest path / /attest", "@r0 path /v1 /v1/*", "reverse_proxy inference-relay-front:8080"} {
		if !strings.Contains(attest, want) {
			t.Errorf("attest site lacks %q:\n%s", want, attest)
		}
	}
	var si stackInfoDoc
	_ = json.Unmarshal(r.StackInfo, &si)
	var rt map[string]any
	raw, _ := json.Marshal(si.Apps[0].Routes[0])
	_ = json.Unmarshal(raw, &rt)
	if rt["host"] != "attest.34-1-2-3.sslip.io" || rt["onAttestHost"] != true || rt["publicUrl"] != "https://attest.34-1-2-3.sslip.io" {
		t.Errorf("stack route %v", rt)
	}
	// Custom hostnames: the relay route needs no domain and may not have one.
	cfg.Hostnames = Hostnames{Scheme: SchemeCustom, Domains: map[string]string{"attest": "attest.relay.example.com"}}
	mustCompose(t, cfg, relay)
	cfg.Hostnames.Domains["relay"] = "relay.example.com"
	if _, err := Compose(cfg, []*Bundle{relay}); err == nil || !strings.Contains(err.Error(), "attest host") {
		t.Errorf("relay domain accepted: %v", err)
	}
	// Manifest rules.
	for name, edit := range map[string][2]string{
		"whole host":   {"path_or_host: /v1", "path_or_host: relay"},
		"attest path":  {"path_or_host: /v1", "path_or_host: /attest"},
		"under attest": {"path_or_host: /v1", "path_or_host: /attest/v1"},
	} {
		dir := writeApp(t, "inference-relay", map[string][][2]string{ManifestFile: {edit}})
		if _, err := buildDir(t, dir); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	dir := writeApp(t, "notes", map[string][][2]string{ManifestFile: {{"    auth: gate\n", "    auth: gate\n    on_attest_host: true\n"}}})
	if _, err := buildDir(t, dir); err == nil || !strings.Contains(err.Error(), "only the relay route") {
		t.Errorf("tools on the attest host: %v", err)
	}
}

func TestRelayEndpointIsAttestOrigin(t *testing.T) {
	cfg, bundles := fixtureStack(t)
	for _, bad := range []string{"https://relay.sealed.example", "https://attest.relay.sealed.example/", "https://attest.relay.sealed.example/v1", "http://attest.relay.sealed.example"} {
		c := *cfg
		c.Endpoints.Relay = bad
		if _, err := Compose(&c, bundles); err == nil || !strings.Contains(err.Error(), "endpoints.relay") {
			t.Errorf("relay %q accepted: %v", bad, err)
		}
	}
	// Without llm-gateway the relay endpoints are not used and not checked.
	notes := buildFixture(t, "notes")
	c := testConfig(notes)
	c.Endpoints.Relay = "https://relay.sealed.example"
	mustCompose(t, c, notes)
}

func TestRoutesMustTargetThePrimary(t *testing.T) {
	dir := writeApp(t, "notes", map[string][][2]string{ManifestFile: {{"    service: notes-web\n    internal_port: 8080", "    service: notes-db\n    internal_port: 8080"}}})
	_, err := buildDir(t, dir)
	var me *ManifestError
	if !errors.As(err, &me) || me.Field != "routes[0].service" || !strings.Contains(err.Error(), "primary") {
		t.Fatalf("route to a non-primary service: %v", err)
	}
}

func TestBootstrapRestartsOnFailure(t *testing.T) {
	gw := buildFixture(t, "llm-gateway")
	dir := writeApp(t, "notes", map[string][][2]string{ManifestFile: {{"", "bootstrap:\n  service: notes-db\n  done_file: pgdata/sealed/done\n"}}})
	b, err := buildDir(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	r := mustCompose(t, testConfig(b, gw), b, gw)
	doc := composeDoc(t, r)
	if svc(doc, "notes-db")["restart"] != "on-failure" || svc(doc, "notes-web")["restart"] != "unless-stopped" {
		t.Errorf("restart: bootstrap %v, other %v", svc(doc, "notes-db")["restart"], svc(doc, "notes-web")["restart"])
	}
	var si stackInfoDoc
	_ = json.Unmarshal(r.StackInfo, &si)
	if bs := si.Apps[1].Bootstrap; bs == nil || bs.DonePath != "/mnt/sealed-data/notes/pgdata/sealed/done" {
		t.Errorf("bootstrap %+v", bs)
	}
}

func TestVolumeOwners(t *testing.T) {
	cfg, bundles := fixtureStack(t)
	r := mustCompose(t, cfg, bundles...)
	var si struct {
		Apps []struct {
			ID      string `json:"id"`
			Volumes []map[string]string
		} `json:"apps"`
	}
	if err := json.Unmarshal(r.StackInfo, &si); err != nil {
		t.Fatal(err)
	}
	vols := si.Apps[1].Volumes
	if len(vols) != 2 || vols[0]["name"] != "pgdata" || vols[0]["owner"] != "" || vols[1]["name"] != "uploads" || vols[1]["owner"] != "1000:1000" {
		t.Errorf("volumes %v", vols)
	}
	for _, bad := range []string{`"root:root"`, `"1000"`, `1000`, `"-1:0"`, `"2147483648:0"`, `"01:1"`, `"1:1:1"`} {
		dir := writeApp(t, "notes", map[string][][2]string{FragmentFile: {{`x-sealed-owner: "1000:1000"`, "x-sealed-owner: " + bad}}})
		if _, err := buildDir(t, dir); err == nil {
			t.Errorf("owner %s accepted", bad)
		}
	}
	dir := writeApp(t, "notes", map[string][][2]string{FragmentFile: {{`x-sealed-owner: "1000:1000"`, `x-sealed-owner: "1000:1000"` + "\n    driver: local"}}})
	if _, err := buildDir(t, dir); err == nil {
		t.Error("volume driver accepted next to x-sealed-owner")
	}
}

func TestDebugLogging(t *testing.T) {
	cfg, bundles := fixtureStack(t)
	prod := mustCompose(t, cfg, bundles...)
	dbg := *cfg
	dbg.Debug = true
	debug := mustCompose(t, &dbg, bundles...)
	if prod.ConfigHash == debug.ConfigHash || prod.StackHash == debug.StackHash {
		t.Fatal("debug is not part of configHash and stackHash")
	}
	for r, driver := range map[*Result]string{prod: "none", debug: "local"} {
		doc := composeDoc(t, r)
		for _, name := range sortedKeys(doc["services"].(map[string]any)) {
			if !jsonEqual(svc(doc, name)["logging"], map[string]any{"driver": driver}) {
				t.Errorf("%s logging %v, want %s", name, svc(doc, name)["logging"], driver)
			}
		}
	}
	// Absent means false and the canonical config always carries it.
	if !strings.Contains(string(prod.ConfigJSON), `"debug":false`) || !strings.Contains(string(debug.ConfigJSON), `"debug":true`) {
		t.Error("debug missing from the canonical config")
	}
	raw := []byte(strings.Replace(string(prod.ConfigJSON), `"debug":false,`, "", 1))
	c, err := ParseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if h, _ := c.Hash(); h != prod.ConfigHash {
		t.Error("absent debug does not normalize to false")
	}
	if _, err := ParseConfig([]byte(strings.Replace(string(prod.ConfigJSON), `"debug":false`, `"debug":"yes"`, 1))); err == nil {
		t.Error("non-boolean debug accepted")
	}
}

func TestAgentDeviceRulesAndCaddyAdminSocket(t *testing.T) {
	cfg, bundles := fixtureStack(t)
	r := mustCompose(t, cfg, bundles...)
	doc := composeDoc(t, r)
	agent := svc(doc, "sealed-agent")
	if !jsonEqual(agent["device_cgroup_rules"], []any{"b 252:* rwm", "b 253:* rwm", "b 254:* rwm"}) {
		t.Errorf("device_cgroup_rules %v", agent["device_cgroup_rules"])
	}
	if !contains(toStrings(agent["devices"].([]any)), "/dev/mapper/control:/dev/mapper/control") {
		t.Errorf("devices %v", agent["devices"])
	}
	for _, name := range sortedKeys(doc["services"].(map[string]any)) {
		if name != "sealed-agent" && svc(doc, name)["device_cgroup_rules"] != nil {
			t.Errorf("%s has device rules", name)
		}
	}
	vol := doc["volumes"].(map[string]any)["sealed-caddy-admin"].(map[string]any)["driver_opts"].(map[string]any)["o"]
	if vol != "size=1m,mode=2770,uid=10001,gid=10001,noexec,nosuid,nodev" {
		t.Errorf("caddy admin tmpfs %v", vol)
	}
	caddySvc := svc(doc, "caddy")
	if !jsonEqual(caddySvc["group_add"], []any{"10001"}) {
		t.Errorf("caddy group_add %v", caddySvc["group_add"])
	}
	// Caddy no longer holds the gate secret or runs envexec.
	raw, _ := json.Marshal(caddySvc)
	if strings.Contains(string(raw), "GATE_PASSWORD") || strings.Contains(string(raw), "envexec") || strings.Contains(string(raw), "/run/sealed/secrets") {
		t.Errorf("caddy still wired for the old gate: %s", raw)
	}
	if !strings.Contains(string(r.Caddyfile), "admin unix//run/sealed/caddy-admin/admin.sock|0660") {
		t.Error("admin socket mode")
	}
	var si struct {
		Caddy map[string]string `json:"caddy"`
		Gate  map[string]any    `json:"gate"`
	}
	_ = json.Unmarshal(r.StackInfo, &si)
	if si.Caddy["adminSocketOwner"] != "10001:10001" || si.Caddy["adminSocketMode"] != "0660" ||
		si.Gate["path"] != "/v1/gate" || si.Gate["cookie"] != "sealed_gate" || si.Gate["cookieMaxAgeSeconds"] != float64(43200) {
		t.Errorf("stack caddy %v gate %v", si.Caddy, si.Gate)
	}
}

func TestServiceNameRules(t *testing.T) {
	long := "notes-" + strings.Repeat("x", MaxServiceNameLen-len("notes-")+1)
	for _, name := range []string{long, "notes--db"} {
		dir := writeApp(t, "notes", map[string][][2]string{FragmentFile: {{"  notes-db:\n", "  " + name + ":\n"}}})
		if _, err := buildDir(t, dir); err == nil {
			t.Errorf("service name %q accepted", name)
		}
	}
}

func TestVpcRangesAvoidAppNetworks(t *testing.T) {
	cfg, _ := fixtureStack(t)
	for _, r := range []string{"172.30.5.0/24", "172.30.16.0/28", "172.30.0.0/16"} {
		c := *cfg
		c.AllowedVpcRanges = []string{r}
		if err := c.Validate(); err == nil {
			t.Errorf("%s accepted", r)
		}
	}
	c := *cfg
	c.AllowedVpcRanges = []string{"172.30.128.0/20"}
	if err := c.Validate(); err != nil {
		t.Errorf("range outside the VM networks: %v", err)
	}
}

// TestThreeAppStackIsDeterministic repeats the determinism check on a stack
// that uses every 1.2.0 feature: three app networks, secret files, the
// relay on the attest host, volume owners and debug logging.
func TestThreeAppStackIsDeterministic(t *testing.T) {
	notes, gw, relay := buildFixture(t, "notes"), buildFixture(t, "llm-gateway"), buildFixture(t, "inference-relay")
	cfg := testConfig(notes, gw, relay)
	cfg.Debug = true
	first := mustCompose(t, cfg, notes, gw, relay)
	raw, err := cfg.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		cfg2, err := ParseConfig(raw)
		if err != nil {
			t.Fatal(err)
		}
		order := []*Bundle{buildFixture(t, "inference-relay"), buildFixture(t, "notes"), buildFixture(t, "llm-gateway")}
		r := mustCompose(t, cfg2, order...)
		if r.StackHash != first.StackHash || string(r.StackInfo) != string(first.StackInfo) || string(r.EgressConfig) != string(first.EgressConfig) {
			t.Fatalf("run %d differs", i)
		}
	}
	doc := composeDoc(t, first)
	if n := len(doc["networks"].(map[string]any)); n != 5 {
		t.Errorf("%d networks, want apps, edge and three app networks", n)
	}
}
