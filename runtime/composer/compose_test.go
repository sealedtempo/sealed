package composer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/sealed-dev/sealed/runtime/composer/cjson"
)

func TestComposeIsDeterministic(t *testing.T) {
	cfg, bundles := fixtureStack(t)
	first := mustCompose(t, cfg, bundles...)
	for i := 0; i < 10; i++ {
		// Fresh bundles, reversed input order, a config round trip through JSON.
		notes := buildFixture(t, "notes")
		gw := buildFixture(t, "llm-gateway")
		raw, err := cfg.CanonicalJSON()
		if err != nil {
			t.Fatal(err)
		}
		cfg2, err := ParseConfig(raw)
		if err != nil {
			t.Fatal(err)
		}
		r := mustCompose(t, cfg2, gw, notes)
		if !bytes.Equal(first.AppCompose, r.AppCompose) || first.StackHash != r.StackHash ||
			!bytes.Equal(first.Caddyfile, r.Caddyfile) || !bytes.Equal(first.EgressConfig, r.EgressConfig) {
			t.Fatalf("run %d differs", i)
		}
	}
	// Map iteration order must not matter: rebuild the config maps in another insertion order.
	cfg3 := *cfg
	cfg3.EgressAdditions = map[string][]string{}
	cfg3.EgressAdditions["notes"] = []string{"smtp.example.com:587"}
	cfg4 := *cfg
	cfg4.EgressAdditions = map[string][]string{"notes": {"smtp.example.com:587"}}
	a, b := mustCompose(t, &cfg3, bundles...), mustCompose(t, &cfg4, bundles...)
	if a.StackHash != b.StackHash {
		t.Fatal("map construction order changed the stack")
	}
}

func TestAppComposeExactFields(t *testing.T) {
	cfg, bundles := fixtureStack(t)
	r := mustCompose(t, cfg, bundles...)
	var ac map[string]any
	if err := json.Unmarshal(r.AppCompose, &ac); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"allowed_envs": []any{}, "gateway_enabled": false, "key_provider": "tpm", "key_provider_id": "",
		"kms_enabled": false, "local_key_provider_enabled": false, "manifest_version": float64(2),
		"no_instance_id": false, "public_logs": false, "public_sysinfo": false, "public_tcbinfo": true,
		"runner": "docker-compose", "secure_time": false, "storage_fs": "ext4",
	}
	keys := sortedKeys(ac)
	wantKeys := []string{"allowed_envs", "docker_compose_file", "gateway_enabled", "key_provider", "key_provider_id", "kms_enabled",
		"local_key_provider_enabled", "manifest_version", "name", "no_instance_id", "pre_launch_script", "public_logs",
		"public_sysinfo", "public_tcbinfo", "runner", "secure_time", "storage_fs"}
	if strings.Join(keys, ",") != strings.Join(wantKeys, ",") {
		t.Fatalf("keys %v", keys)
	}
	for k, v := range want {
		got, _ := json.Marshal(ac[k])
		exp, _ := json.Marshal(v)
		if string(got) != string(exp) {
			t.Errorf("%s = %s, want %s", k, got, exp)
		}
	}
	if ac["name"] != "sealed-"+r.ConfigHash.Hex()[2:10] {
		t.Errorf("name %v", ac["name"])
	}
	if ac["docker_compose_file"] != string(r.ComposeJSON) || ac["pre_launch_script"] != r.PreLaunchScript {
		t.Error("compose or pre_launch_script not embedded verbatim")
	}
	if bytes.HasSuffix(r.AppCompose, []byte("\n")) {
		t.Error("trailing newline")
	}
	customer, _ := ParseAddress(cfg.Customer)
	salt, _ := ParseHash(cfg.Salt)
	if r.DeploymentID != DeploymentID(customer, r.StackHash, salt) {
		t.Error("deploymentId")
	}
	if r.ConfigHash != SHA256(r.ConfigJSON) {
		t.Error("configHash")
	}
}

// TestOneByteChangesStackHash flips every byte of a fragment, an egress
// policy and the config. Each variant that still parses must give a new
// stackHash (bundle bytes feed releaseId, which the config carries).
func TestOneByteChangesStackHash(t *testing.T) {
	cfg, bundles := fixtureStack(t)
	base := mustCompose(t, cfg, bundles...)

	mutateFile := func(name string) {
		dir := copyFixture(t, "notes")
		path := filepath.Join(dir, name)
		orig, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		checked := 0
		for i := range orig {
			for _, repl := range []byte{'x', '7'} {
				if orig[i] == repl {
					continue
				}
				mut := append([]byte(nil), orig...)
				mut[i] = repl
				if err := os.WriteFile(path, mut, 0o644); err != nil {
					t.Fatal(err)
				}
				b, err := BuildBundle(BuildInput{AppDir: dir, Registry: testRegistry})
				if err != nil {
					continue
				}
				r, err := Compose(testConfig(b, bundles[1]), []*Bundle{b, bundles[1]})
				if err != nil {
					continue
				}
				if r.StackHash == base.StackHash {
					t.Fatalf("%s byte %d -> %q did not change stackHash", name, i, repl)
				}
				checked++
				break
			}
		}
		_ = os.WriteFile(path, orig, 0o644)
		if checked < len(orig)/4 {
			t.Fatalf("%s: only %d of %d mutations composed; test is not exercising enough", name, checked, len(orig))
		}
		t.Logf("%s: %d single-byte variants composed, all with new stack hashes", name, checked)
	}
	mutateFile(FragmentFile)
	mutateFile(EgressFile)
	mutateFile(ManifestFile)

	raw, err := cfg.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for i := range raw {
		for _, repl := range []byte{'1', 'a', 'x'} {
			if raw[i] == repl {
				continue
			}
			mut := append([]byte(nil), raw...)
			mut[i] = repl
			c, err := ParseConfig(mut)
			if err != nil {
				continue
			}
			r, err := Compose(c, bundles)
			if err != nil {
				continue
			}
			if r.StackHash == base.StackHash {
				t.Fatalf("config byte %d -> %q did not change stackHash", i, repl)
			}
			checked++
			break
		}
	}
	if checked < 100 {
		t.Fatalf("only %d config mutations composed", checked)
	}
	t.Logf("config: %d single-byte variants composed, all with new stack hashes", checked)
}

func TestComposePassesDockerComposeConfig(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker CLI not installed")
	}
	if err := exec.Command("docker", "compose", "version").Run(); err != nil {
		t.Skip("docker compose plugin not installed")
	}
	_, bundles := fixtureStack(t)
	relay := buildFixture(t, "inference-relay")
	for i, stack := range [][]*Bundle{bundles, bundles[:1], {relay}, append(append([]*Bundle{}, bundles...), relay)} {
		c := testConfig(stack...)
		if stack[0].Manifest.ID == "notes" {
			c.EgressAdditions = map[string][]string{"notes": {"smtp.example.com:587"}}
		}
		c.Debug = i%2 == 1
		// Literal dollars in measured content must survive interpolation.
		c.Endpoints.KeyBroker = "https://sealed-key-broker-xyz.a.run.app/v1/$release${x}$$"
		r := mustCompose(t, c, stack...)
		path := filepath.Join(t.TempDir(), "docker-compose.json")
		if err := os.WriteFile(path, r.ComposeJSON, 0o644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("docker", "compose", "-f", path, "config", "--quiet")
		cmd.Env = append(os.Environ(), "DOCKER_HOST=unix:///nonexistent.sock")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("docker compose config: %v\n%s", err, out)
		}
		if len(bytes.TrimSpace(out)) > 0 {
			t.Fatalf("docker compose config printed warnings:\n%s", out)
		}
		// Interpolation must give back the literal measured text.
		cmd = exec.Command("docker", "compose", "-f", path, "config", "--format", "json")
		out, err = cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		var resolved struct {
			Configs map[string]struct {
				Content string `json:"content"`
			} `json:"configs"`
		}
		if err := json.Unmarshal(out, &resolved); err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(r.ConfigJSON, []byte("/v1/$release${x}$$")) {
			t.Fatal("test config lost its dollars")
		}
		// compose config prints its interpolated model re-escaped ($ as $$), so
		// the literal measured text comes back exactly doubled. Unescaped
		// input would lose "$release" and "${x}" here.
		if got := resolved.Configs["sealed-config"].Content; got != strings.ReplaceAll(string(r.ConfigJSON), "$", "$$") {
			t.Fatalf("config content changed by compose interpolation:\n got %s\nwant %s", got, r.ConfigJSON)
		}
	}
}

func composeDoc(t *testing.T, r *Result) map[string]any {
	t.Helper()
	v, err := cjson.Parse(r.ComposeJSON)
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]any)
}

func svc(doc map[string]any, name string) map[string]any {
	return doc["services"].(map[string]any)[name].(map[string]any)
}

func TestComposeServices(t *testing.T) {
	cfg, bundles := fixtureStack(t)
	r := mustCompose(t, cfg, bundles...)
	doc := composeDoc(t, r)
	services := doc["services"].(map[string]any)
	names := sortedKeys(services)
	want := []string{"caddy", "llm-gateway-proxy", "notes-db", "notes-web", "sealed-agent", "sealed-egress", "sealed-init", "sealed-mpp-payer", "sealed-verifierd"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("services %v", names)
	}
	ip := func(name, network string) string {
		nets := svc(doc, name)["networks"].(map[string]any)
		n, _ := nets[network].(map[string]any)
		s, _ := n["ipv4_address"].(string)
		return s
	}
	for name, wantIP := range map[string]string{
		"sealed-egress": "172.30.0.2", "sealed-agent": "172.30.0.3", "caddy": "172.30.0.4",
		"sealed-mpp-payer": "172.30.0.5", "sealed-verifierd": "",
		"llm-gateway-proxy": "172.30.0.16", "notes-web": "172.30.0.17", "notes-db": "",
	} {
		if got := ip(name, "apps"); got != wantIP {
			t.Errorf("%s apps ip %q, want %q", name, got, wantIP)
		}
	}
	// App networks: llm-gateway is app 1, notes app 2 (sorted app order).
	for _, c := range []struct{ name, network, ip string }{
		{"llm-gateway-proxy", "app-llm-gateway", "172.30.1.16"},
		{"notes-web", "app-notes", "172.30.2.16"},
		{"notes-db", "app-notes", "172.30.2.17"},
		{"sealed-egress", "app-llm-gateway", "172.30.1.2"},
		{"sealed-egress", "app-notes", "172.30.2.2"},
		{"sealed-agent", "app-llm-gateway", "172.30.1.3"},
		{"sealed-agent", "app-notes", "172.30.2.3"},
		// D-061: verifierd shares a network with the payer and egress only.
		{"sealed-egress", "verifier", "172.30.250.2"},
		{"sealed-mpp-payer", "verifier", "172.30.250.5"},
		{"sealed-verifierd", "verifier", "172.30.250.6"},
	} {
		if got := ip(c.name, c.network); got != c.ip {
			t.Errorf("%s on %s: %q, want %q", c.name, c.network, got, c.ip)
		}
	}
	edge := svc(doc, "sealed-egress")["networks"].(map[string]any)["edge"].(map[string]any)["ipv4_address"]
	if edge != "172.31.0.2" {
		t.Errorf("egress edge ip %v", edge)
	}

	web := svc(doc, "notes-web")
	ep := web["entrypoint"].([]any)
	wantEP := []any{"/sealed/bin/envexec", "--app", "notes", "--secret", "APP_SECRET", "--secret", "DB_PASSWORD", "--optional-secret", "SMTP_PASSWORD", "--", "/usr/local/bin/notes"}
	if !jsonEqual(ep, wantEP) {
		t.Errorf("entrypoint %v", ep)
	}
	env := web["environment"].(map[string]any)
	for k, v := range map[string]string{
		"HTTP_PROXY": "http://172.30.2.2:3128", "HTTPS_PROXY": "http://172.30.2.2:3128", "http_proxy": "http://172.30.2.2:3128",
		"https_proxy": "http://172.30.2.2:3128", "NODE_USE_ENV_PROXY": "1", "NOTES_TELEMETRY": "0", "DO_NOT_TRACK": "1",
		"NOTES_WORKERS": "2", "NOTES_PRICE_LABEL": "costs $$5", "SEALED_PUBLIC_URL_TOOLS": "https://tools.34-1-2-3.sslip.io",
	} {
		if env[k] != v {
			t.Errorf("env %s = %v, want %s", k, env[k], v)
		}
	}
	np := strings.Split(env["NO_PROXY"].(string), ",")
	for _, n := range []string{"localhost", "127.0.0.1", "notes", "notes-web", "notes-db", "llm-gateway", "llm-gateway-proxy", "sealed-agent", "sealed-mpp-payer", "caddy"} {
		if !contains(np, n) {
			t.Errorf("NO_PROXY lacks %s", n)
		}
	}
	if env["no_proxy"] != env["NO_PROXY"] {
		t.Error("no_proxy differs")
	}
	if !jsonEqual(web["dns"], []any{"172.30.2.2"}) || web["restart"] != "unless-stopped" || !jsonEqual(web["logging"], map[string]any{"driver": "none"}) {
		t.Errorf("sidecar plumbing: dns %v restart %v logging %v", web["dns"], web["restart"], web["logging"])
	}
	aliases := web["networks"].(map[string]any)["apps"].(map[string]any)["aliases"]
	if !jsonEqual(aliases, []any{"notes"}) {
		t.Errorf("primary alias %v", aliases)
	}
	if _, ok := svc(doc, "notes-db")["networks"].(map[string]any)["apps"]; ok {
		t.Error("a non-primary service must not join the shared apps network")
	}
	deps := web["depends_on"].(map[string]any)
	for dep, cond := range map[string]string{"sealed-agent": "service_healthy", "sealed-init": "service_completed_successfully", "notes-db": "service_healthy"} {
		if deps[dep].(map[string]any)["condition"] != cond {
			t.Errorf("depends_on %s = %v", dep, deps[dep])
		}
	}
	var sources []string
	for _, v := range web["volumes"].([]any) {
		m := v.(map[string]any)
		sources = append(sources, m["type"].(string)+":"+str(m["source"])+":"+m["target"].(string))
	}
	wantVols := []string{
		"volume:sealed-bin:/sealed/bin", "volume:sealed-ready:/run/sealed/ready",
		"bind:/run/sealed/secrets/notes/APP_SECRET:/run/sealed/secrets/notes/APP_SECRET",
		"bind:/run/sealed/secrets/notes/DB_PASSWORD:/run/sealed/secrets/notes/DB_PASSWORD",
		"bind:/run/sealed/secrets/notes/SMTP_PASSWORD:/run/sealed/secrets/notes/SMTP_PASSWORD",
		"bind:/mnt/sealed-data/notes/uploads:/var/lib/notes/uploads", "tmpfs::/tmp",
	}
	if strings.Join(sources, " ") != strings.Join(wantVols, " ") {
		t.Errorf("volumes\n got %v\nwant %v", sources, wantVols)
	}
	db := svc(doc, "notes-db")
	if !jsonEqual(db["healthcheck"].(map[string]any)["test"], []any{"CMD-SHELL", "pg_isready -U $$POSTGRES_USER"}) {
		t.Errorf("db healthcheck %v", db["healthcheck"])
	}
	webHC := web["healthcheck"].(map[string]any)
	if !jsonEqual(webHC["test"], []any{"CMD", "/sealed/bin/envexec", "probe", "http://127.0.0.1:8080/healthz"}) || webHC["start_period"] != "20s" {
		t.Errorf("generated healthcheck %v", webHC)
	}

	// Only the agent gets the dstack socket, the data disk and SYS_ADMIN.
	for _, name := range names {
		s := svc(doc, name)
		raw, _ := json.Marshal(s)
		isAgent := name == "sealed-agent"
		if strings.Contains(string(raw), "dstack.sock") != isAgent || strings.Contains(string(raw), "SYS_ADMIN") != isAgent || (s["devices"] != nil) != isAgent {
			t.Errorf("%s: privileged plumbing mismatch", name)
		}
		if s["privileged"] != nil {
			t.Errorf("%s is privileged", name)
		}
		if name != "caddy" && s["ports"] != nil {
			t.Errorf("%s publishes ports", name)
		}
		if img, _ := s["image"].(string); !digestRefRe.MatchString(img) {
			t.Errorf("%s image %q not pinned by digest", name, img)
		}
	}
	nets := doc["networks"].(map[string]any)
	if nets["apps"].(map[string]any)["internal"] != true || nets["edge"].(map[string]any)["internal"] != nil {
		t.Error("apps must be internal, edge not")
	}
	if strings.Join(sortedKeys(nets), ",") != "app-llm-gateway,app-notes,apps,edge,verifier" {
		t.Errorf("networks %v", sortedKeys(nets))
	}
	for name, subnet := range map[string]string{"app-llm-gateway": "172.30.1.0/24", "app-notes": "172.30.2.0/24", "verifier": "172.30.250.0/24"} {
		n := nets[name].(map[string]any)
		cfg := n["ipam"].(map[string]any)["config"].([]any)[0].(map[string]any)
		if n["internal"] != true || cfg["subnet"] != subnet {
			t.Errorf("%s: internal %v subnet %v", name, n["internal"], cfg["subnet"])
		}
	}
	for name, content := range map[string][]byte{
		"sealed-config": r.ConfigJSON, "sealed-egress": r.EgressConfig, "sealed-caddyfile": r.Caddyfile,
		"sealed-caddyfile-payment-needed": r.CaddyfilePaymentNeeded, "sealed-stack": r.StackInfo,
	} {
		got := doc["configs"].(map[string]any)[name].(map[string]any)["content"]
		if got != strings.ReplaceAll(string(content), "$", "$$") {
			t.Errorf("config %s not embedded verbatim", name)
		}
	}
}

// TestComposeHardensEveryService checks the capability and privilege
// settings fragments cannot set themselves: no service may forge packets on
// the apps bridge (NET_RAW), and none may gain privileges through setuid
// binaries or file capabilities.
func TestComposeHardensEveryService(t *testing.T) {
	cfg, bundles := fixtureStack(t)
	doc := composeDoc(t, mustCompose(t, cfg, bundles...))
	sidecars := map[string]bool{"sealed-init": true, "sealed-egress": true, "caddy": true, "sealed-mpp-payer": true, "sealed-verifierd": true}
	for _, name := range sortedKeys(doc["services"].(map[string]any)) {
		s := svc(doc, name)
		if !jsonEqual(s["security_opt"], []any{"no-new-privileges:true"}) {
			t.Errorf("%s: security_opt %v", name, s["security_opt"])
		}
		drop, _ := s["cap_drop"].([]any)
		if !contains(toStrings(drop), "ALL") && !contains(toStrings(drop), "NET_RAW") {
			t.Errorf("%s keeps NET_RAW: cap_drop %v", name, drop)
		}
		switch {
		case name == "sealed-agent":
			if !jsonEqual(drop, []any{"NET_RAW"}) || !jsonEqual(s["cap_add"], []any{"SYS_ADMIN"}) {
				t.Errorf("agent caps drop %v add %v", drop, s["cap_add"])
			}
		case name == "caddy":
			if !jsonEqual(drop, []any{"ALL"}) || !jsonEqual(s["cap_add"], []any{"NET_BIND_SERVICE"}) {
				t.Errorf("caddy caps drop %v add %v", drop, s["cap_add"])
			}
		case sidecars[name]:
			if !jsonEqual(drop, []any{"ALL"}) || s["cap_add"] != nil {
				t.Errorf("%s caps drop %v add %v", name, drop, s["cap_add"])
			}
		default:
			if !jsonEqual(drop, []any{"AUDIT_WRITE", "MKNOD", "NET_RAW", "SETFCAP"}) || s["cap_add"] != nil {
				t.Errorf("app %s caps drop %v add %v", name, drop, s["cap_add"])
			}
		}
		// Data-disk binds must not be created by Docker (they would land
		// outside LUKS before the agent mounts it); only the agent's mount
		// point may be.
		vols, _ := s["volumes"].([]any)
		for _, v := range vols {
			m := v.(map[string]any)
			src, _ := m["source"].(string)
			if m["type"] != "bind" || !strings.HasPrefix(src, DataRoot) {
				continue
			}
			create := m["bind"].(map[string]any)["create_host_path"]
			if wantCreate := name == "sealed-agent" && src == DataRoot; create != wantCreate {
				t.Errorf("%s: bind %s create_host_path %v", name, src, create)
			}
		}
		// Secret files are never created by Docker either; only the
		// agent's secrets root on the host tmpfs may be.
		for _, v := range vols {
			m := v.(map[string]any)
			src, _ := m["source"].(string)
			if m["type"] != "bind" || !strings.HasPrefix(src, SecretsRoot) {
				continue
			}
			create := m["bind"].(map[string]any)["create_host_path"]
			if wantCreate := name == "sealed-agent" && src == SecretsRoot; create != wantCreate {
				t.Errorf("%s: secret bind %s create_host_path %v", name, src, create)
			}
			if name != "sealed-agent" && m["read_only"] != true {
				t.Errorf("%s: secret bind %s is writable", name, src)
			}
		}
	}
}

func toStrings(v []any) []string {
	out := make([]string, 0, len(v))
	for _, e := range v {
		s, _ := e.(string)
		out = append(out, s)
	}
	return out
}

func TestComposeRejectsForeignRegistry(t *testing.T) {
	gw := buildFixture(t, "llm-gateway")
	for _, reg := range []string{"docker.io/evil", "ghcr.io/evil", "ghcr.io/sealedtempo/sub"} {
		b, err := BuildBundle(BuildInput{AppDir: fixtureDir("notes"), Registry: reg})
		if err != nil {
			t.Fatal(err)
		}
		_, err = Compose(testConfig(b, gw), []*Bundle{b, gw})
		var me *ManifestError
		if !errors.As(err, &me) || !strings.HasPrefix(me.Field, "images[") || !strings.Contains(err.Error(), "catalog registry") {
			t.Errorf("registry %s accepted or wrong error: %v", reg, err)
		}
	}
}

func TestRequireBuilt(t *testing.T) {
	cfg, bundles := fixtureStack(t)
	r := mustCompose(t, cfg, bundles...)
	err := r.RequireBuilt()
	if err == nil || !strings.Contains(err.Error(), "runtime/sealed-agent") {
		t.Fatalf("unbuilt stack passed: %v", err)
	}
	if err := (&Result{}).RequireBuilt(); err != nil {
		t.Fatal(err)
	}
}

// TestFragmentContentReachesCompose shows that fragment and egress values
// themselves (not only the bundle hash) end up in the measured compose.
func TestFragmentContentReachesCompose(t *testing.T) {
	gw := buildFixture(t, "llm-gateway")
	cases := []struct {
		file, old, new string
		check          func(doc map[string]any, egress string) bool
	}{
		{FragmentFile, "NOTES_WORKERS: 2", "NOTES_WORKERS: 7", func(doc map[string]any, _ string) bool {
			return svc(doc, "notes-web")["environment"].(map[string]any)["NOTES_WORKERS"] == "7"
		}},
		{FragmentFile, `command: ["serve", "--port", "8080"]`, `command: ["serve", "--port", "8080", "--quiet"]`, func(doc map[string]any, _ string) bool {
			return jsonEqual(svc(doc, "notes-web")["command"], []any{"serve", "--port", "8080", "--quiet"})
		}},
		{FragmentFile, "interval: 5s", "interval: 9s", func(doc map[string]any, _ string) bool {
			return svc(doc, "notes-db")["healthcheck"].(map[string]any)["interval"] == "9s"
		}},
		{FragmentFile, "shm_size: 128m", "shm_size: 256m", func(doc map[string]any, _ string) bool {
			return svc(doc, "notes-db")["shm_size"] == "256m"
		}},
		{EgressFile, `"api.example.com:443"`, `"api2.example.com:443"`, func(_ map[string]any, egress string) bool {
			return strings.Contains(egress, `"api2.example.com:443"`) && !strings.Contains(egress, `"api.example.com:443"`)
		}},
	}
	for _, c := range cases {
		dir := copyFixture(t, "notes")
		path := filepath.Join(dir, c.file)
		src := mustRead(t, path)
		mut := bytes.Replace(src, []byte(c.old), []byte(c.new), 1)
		if bytes.Equal(mut, src) {
			t.Fatalf("%s: %q not found", c.file, c.old)
		}
		if err := os.WriteFile(path, mut, 0o644); err != nil {
			t.Fatal(err)
		}
		b, err := BuildBundle(BuildInput{AppDir: dir, Registry: testRegistry})
		if err != nil {
			t.Fatal(err)
		}
		r := mustCompose(t, testConfig(b, gw), b, gw)
		doc := composeDoc(t, r)
		egress := doc["configs"].(map[string]any)["sealed-egress"].(map[string]any)["content"].(string)
		if !c.check(doc, egress) {
			t.Errorf("%s: %q -> %q did not reach the compose", c.file, c.old, c.new)
		}
	}
}

func TestConfigAndComposeSizeBounds(t *testing.T) {
	cfg, bundles := fixtureStack(t)
	many := make([]string, MaxEgressAdditionsPerApp+1)
	for i := range many {
		many[i] = fmt.Sprintf("h%d.example.com:443", i)
	}
	cfg.EgressAdditions = map[string][]string{"notes": many}
	if _, err := Compose(cfg, bundles); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("too many additions accepted: %v", err)
	}
	cfg.EgressAdditions = map[string][]string{"notes": many[:MaxEgressAdditionsPerApp]}
	r := mustCompose(t, cfg, bundles...)
	if len(r.AppCompose) > MaxAppComposeBytes {
		t.Fatalf("bounded config gave %d bytes", len(r.AppCompose))
	}
	raw := append([]byte(`{"pad":"`), bytes.Repeat([]byte("x"), MaxConfigBytes)...)
	raw = append(raw, `"}`...)
	if _, err := ParseConfig(raw); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("oversized config: %v", err)
	}
}

func TestComposeWithoutGatewayHasNoPayer(t *testing.T) {
	notes := buildFixture(t, "notes")
	cfg := testConfig(notes)
	cfg.Endpoints.Relay, cfg.Endpoints.RelayAttest, cfg.RelayOwner = "", "", ""
	r := mustCompose(t, cfg, notes)
	doc := composeDoc(t, r)
	services := doc["services"].(map[string]any)
	if _, ok := services["sealed-mpp-payer"]; ok {
		t.Error("payer without llm-gateway")
	}
	if _, ok := services["sealed-verifierd"]; ok {
		t.Error("verifierd without llm-gateway")
	}
	if ip := svc(doc, "notes-web")["networks"].(map[string]any)["apps"].(map[string]any)["ipv4_address"]; ip != "172.30.0.16" {
		t.Errorf("first app ip %v", ip)
	}
	for _, u := range r.Unbuilt {
		if strings.Contains(u, "payer") || strings.Contains(u, "verifierd") {
			t.Errorf("unbuilt lists unused sidecar %s", u)
		}
	}
	gw := buildFixture(t, "llm-gateway")
	cfg2 := testConfig(gw)
	cfg2.RelayOwner = ""
	if _, err := Compose(cfg2, []*Bundle{gw}); err == nil {
		t.Error("gateway stack without relay settings accepted")
	}
}

func TestEgressConfigCallers(t *testing.T) {
	cfg, bundles := fixtureStack(t)
	cfg.EgressAdditions = map[string][]string{"notes": {"smtp.example.com:587"}}
	cfg.AllowedVpcRanges = []string{"10.10.0.0/16"}
	r := mustCompose(t, cfg, bundles...)
	var ec struct {
		Listen              map[string]string `json:"listen"`
		UpstreamDNS         []string          `json:"upstreamDns"`
		AllowedPrivateCidrs []string          `json:"allowedPrivateCidrs"`
		StatsReaders        []string          `json:"statsReaders"`
		Callers             []struct {
			Name  string   `json:"name"`
			IP    string   `json:"ip"`
			Allow []string `json:"allow"`
		} `json:"callers"`
	}
	if err := json.Unmarshal(r.EgressConfig, &ec); err != nil {
		t.Fatal(err)
	}
	allow := map[string]string{}
	for _, c := range ec.Callers {
		allow[c.Name+"@"+c.IP] = strings.Join(c.Allow, " ")
	}
	// One caller per source address: every address a service owns maps to
	// its allowlist (D-041). Sidecar addresses no traffic leaves from (the
	// agent on app networks, the payer on the verifier network) get none.
	agent := "api.sealed.example:443 rpc.tempo.xyz:443 sealed-key-broker-xyz.a.run.app:443"
	notes := "api.example.com:443 smtp.example.com:587"
	want := map[string]string{
		"sealed-agent@172.30.0.3":                  agent,
		"sealed-agent--app-llm-gateway@172.30.1.3": "",
		"sealed-agent--app-notes@172.30.2.3":       "",
		"caddy@172.30.0.4":                         "acme-v02.api.letsencrypt.org:443",
		"sealed-mpp-payer@172.30.0.5":              "attest.relay.sealed.example:443 rpc.tempo.xyz:443",
		"sealed-mpp-payer--verifier@172.30.250.5":  "",
		// D-061: PCS, the RPC, the relay attest host and the release asset hosts.
		"sealed-verifierd@172.30.250.6": "api.trustedservices.intel.com:443 attest.relay.sealed.example:443 certificates.trustedservices.intel.com:443 " +
			"github.com:443 objects.githubusercontent.com:443 release-assets.githubusercontent.com:443 rpc.tempo.xyz:443",
		"llm-gateway-proxy--apps@172.30.0.16": "",
		"llm-gateway-proxy@172.30.1.16":       "",
		"notes-web--apps@172.30.0.17":         notes,
		"notes-web@172.30.2.16":               notes,
		"notes-db@172.30.2.17":                notes,
	}
	if len(allow) != len(want) {
		t.Fatalf("callers %v", allow)
	}
	for k, v := range want {
		if allow[k] != v {
			t.Errorf("%s allow %q, want %q", k, allow[k], v)
		}
	}
	if ec.Listen["proxy"] != ":3128" || ec.Listen["dns"] != ":53" || ec.Listen["stats"] != ":9100" {
		t.Errorf("listen %v", ec.Listen)
	}
	if strings.Join(ec.StatsReaders, ",") != "172.30.0.3" || strings.Join(ec.AllowedPrivateCidrs, ",") != "10.10.0.0/16" {
		t.Errorf("stats %v cidrs %v", ec.StatsReaders, ec.AllowedPrivateCidrs)
	}

	// The gateway fixture does not allow customer additions.
	cfg.EgressAdditions = map[string][]string{"llm-gateway": {"api.openai.com:443"}}
	if _, err := Compose(cfg, bundles); err == nil || !strings.Contains(err.Error(), "does not allow") {
		t.Fatalf("additions for a closed app accepted: %v", err)
	}
}

func TestComposeRejectsMismatchedInputs(t *testing.T) {
	cfg, bundles := fixtureStack(t)
	bad := *cfg
	bad.Apps = append([]ConfigApp(nil), cfg.Apps...)
	bad.Apps[1].ReleaseID = "0x" + strings.Repeat("00", 32)
	if _, err := Compose(&bad, bundles); err == nil || !strings.Contains(err.Error(), "releaseId") {
		t.Fatalf("wrong releaseId accepted: %v", err)
	}
	if _, err := Compose(cfg, bundles[:1]); err == nil {
		t.Fatal("missing bundle accepted")
	}
	if _, err := Compose(testConfig(bundles[0]), bundles); err == nil {
		t.Fatal("extra bundle accepted")
	}
	if _, err := Compose(cfg, []*Bundle{bundles[0], bundles[0], bundles[1]}); err == nil {
		t.Fatal("duplicate bundle accepted")
	}
	custom := *cfg
	custom.Hostnames = Hostnames{Scheme: SchemeCustom, Domains: map[string]string{"gateway": "llm.example.com", "tools": "notes.example.com"}}
	if _, err := Compose(&custom, bundles); err == nil || !strings.Contains(err.Error(), "attest") {
		t.Fatalf("custom domains without attest accepted: %v", err)
	}
	custom.Hostnames.Domains["attest"] = "attest.example.com"
	r, err := Compose(&custom, bundles)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(r.Caddyfile, []byte("\nnotes.example.com {")) || !bytes.Contains(r.Caddyfile, []byte("\nattest.example.com {")) {
		t.Fatalf("custom hosts missing:\n%s", r.Caddyfile)
	}
	custom.Hostnames.Domains["crm"] = "crm.example.com"
	if _, err := Compose(&custom, bundles); err == nil {
		t.Fatal("domain for a route not in the stack accepted")
	}
}

func TestComposeRoutesAndCaddyfile(t *testing.T) {
	cfg, bundles := fixtureStack(t)
	r := mustCompose(t, cfg, bundles...)
	cf := string(r.Caddyfile)
	for _, want := range []string{
		"admin unix//run/sealed/caddy-admin/admin.sock|0660",
		"\ngateway.34-1-2-3.sslip.io {",
		"\ntools.34-1-2-3.sslip.io {",
		"\nattest.34-1-2-3.sslip.io {",
		"reverse_proxy sealed-agent:7070",
		"forward_auth sealed-agent:7070 {",
		"uri /v1/gate?route=tools",
		"uri /v1/gate?route=gateway",
		`header Authorization "Bearer *"`,
		"reverse_proxy notes-web:8080",
		"@r0 path /admin /admin/*",
	} {
		if !strings.Contains(cf, want) {
			t.Errorf("Caddyfile lacks %q", want)
		}
	}
	pn := string(r.CaddyfilePaymentNeeded)
	if strings.Contains(cf, "basic_auth") || strings.Contains(cf, "GATE_PASSWORD_BCRYPT") {
		t.Error("Caddy must not gate with basic_auth any more (D-044)")
	}
	if strings.Contains(pn, "reverse_proxy notes-web") || strings.Contains(pn, "forward_auth") {
		t.Error("payment-needed variant still proxies apps")
	}
	if !strings.Contains(pn, "status 402") || !strings.Contains(pn, "reverse_proxy sealed-agent:7070") {
		t.Error("payment-needed variant must serve the page and keep attest")
	}
	// Two apps claiming the same route name.
	dir := copyFixture(t, "notes")
	src, _ := os.ReadFile(filepath.Join(dir, ManifestFile))
	_ = os.WriteFile(filepath.Join(dir, ManifestFile), bytes.Replace(src, []byte("name: tools"), []byte("name: gateway"), 1), 0o644)
	_ = os.WriteFile(filepath.Join(dir, ManifestFile), bytes.Replace(mustRead(t, filepath.Join(dir, ManifestFile)), []byte("path_or_host: tools"), []byte("path_or_host: gateway"), 1), 0o644)
	clash, err := BuildBundle(BuildInput{AppDir: dir, Registry: testRegistry})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Compose(testConfig(clash, bundles[1]), []*Bundle{clash, bundles[1]}); err == nil || !strings.Contains(err.Error(), "claimed by both") {
		t.Fatalf("route clash accepted: %v", err)
	}
}

type stackInfoDoc struct {
	Schema string `json:"schema"`
	Apps   []struct {
		ID        string `json:"id"`
		AppID     string `json:"appId"`
		ReleaseID string `json:"releaseId"`
		Network   struct {
			Name, Subnet, Egress, Agent string
		} `json:"network"`
		Services []struct {
			Name     string            `json:"name"`
			IP       string            `json:"ip"`
			IPs      []string          `json:"ips"`
			Networks map[string]string `json:"networks"`
			Primary  bool              `json:"primary"`
			Secrets  []string          `json:"secrets"`
		} `json:"services"`
		Routes    []any `json:"routes"`
		Metering  struct{ Unit, Source string }
		Volumes   []struct{ Name, Path string } `json:"volumes"`
		Bootstrap *struct {
			Service  string `json:"service"`
			DoneFile string `json:"doneFile"`
			DonePath string `json:"donePath"`
		} `json:"bootstrap"`
	} `json:"apps"`
	DataRoot   string   `json:"dataRoot"`
	DataDirs   []string `json:"dataDirs"`
	AttestHost string   `json:"attestHost"`
}

func TestStackInfo(t *testing.T) {
	cfg, bundles := fixtureStack(t)
	r := mustCompose(t, cfg, bundles...)
	var si stackInfoDoc
	if err := json.Unmarshal(r.StackInfo, &si); err != nil {
		t.Fatal(err)
	}
	if si.Schema != "sealed-stack/v1" || len(si.Apps) != 2 || si.AttestHost != "attest.34-1-2-3.sslip.io" {
		t.Fatalf("%+v", si)
	}
	if si.Apps[1].ID != "notes" || si.Apps[1].AppID != AppID("notes").Hex() || si.Apps[1].Metering.Unit != "app_hour" {
		t.Fatalf("%+v", si.Apps[1])
	}
	vols := si.Apps[1].Volumes
	if len(vols) != 2 || vols[0].Name != "pgdata" || vols[0].Path != "/mnt/sealed-data/notes/pgdata" || vols[1].Path != "/mnt/sealed-data/notes/uploads" {
		t.Fatalf("volumes %+v", vols)
	}
	if si.Apps[0].Volumes == nil || len(si.Apps[0].Volumes) != 0 {
		t.Fatalf("gateway volumes must be an empty list: %+v", si.Apps[0].Volumes)
	}
	// With llm-gateway the payer's state directory is listed too (fix-payments).
	want := []string{"/mnt/sealed-data/_caddy/data", "/mnt/sealed-data/_mpp-payer/state", "/mnt/sealed-data/notes/pgdata", "/mnt/sealed-data/notes/uploads"}
	if si.DataRoot != "/mnt/sealed-data" || strings.Join(si.DataDirs, " ") != strings.Join(want, " ") {
		t.Fatalf("dataDirs %v", si.DataDirs)
	}
	// Every data bind in the compose is listed, so the agent can create them all.
	doc := composeDoc(t, r)
	for _, name := range sortedKeys(doc["services"].(map[string]any)) {
		vols, _ := svc(doc, name)["volumes"].([]any)
		for _, v := range vols {
			src, _ := v.(map[string]any)["source"].(string)
			if strings.HasPrefix(src, DataRoot+"/") && !contains(si.DataDirs, src) {
				t.Errorf("%s binds %s, not in dataDirs", name, src)
			}
		}
	}
}

func TestStackInfoBootstrapDonePath(t *testing.T) {
	gw := buildFixture(t, "llm-gateway")
	for _, c := range []struct{ doneFile, want string }{
		{"pgdata/bootstrap/done.json", "/mnt/sealed-data/notes/pgdata/bootstrap/done.json"},
		{"/var/lib/notes/uploads/.sealed/done", "/mnt/sealed-data/notes/uploads/.sealed/done"},
	} {
		dir := copyFixture(t, "notes")
		manifest := filepath.Join(dir, ManifestFile)
		src := string(mustRead(t, manifest)) + "bootstrap:\n  service: notes-web\n  done_file: " + c.doneFile + "\n"
		if err := os.WriteFile(manifest, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		b, err := BuildBundle(BuildInput{AppDir: dir, Registry: testRegistry})
		if err != nil {
			t.Fatal(err)
		}
		r := mustCompose(t, testConfig(b, gw), b, gw)
		var si stackInfoDoc
		if err := json.Unmarshal(r.StackInfo, &si); err != nil {
			t.Fatal(err)
		}
		bs := si.Apps[1].Bootstrap
		if bs == nil || bs.Service != "notes-web" || bs.DoneFile != c.doneFile || bs.DonePath != c.want {
			t.Errorf("%s: bootstrap %+v", c.doneFile, bs)
		}
	}
}

func TestHostRulesScript(t *testing.T) {
	s, err := HostRulesScript(EdgeSubnet, EgressEdgeIP)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Sealed host rules v3", "EDGE_SUBNET=172.31.0.0/24", "EDGE_BRIDGE=sealed-edge", "EGRESS_IP=172.31.0.2",
		`CONTAINER_RANGES="172.30.0.0/16 172.31.0.0/24"`, "CONTAINER_BRIDGES=sealed-+",
		"--ctstate ESTABLISHED,RELATED -j RETURN", `-s "$EGRESS_IP" -j RETURN`, "-A SEALED-EDGE -j DROP",
		"-A SEALED-INPUT -j DROP", `ensure_jump INPUT SEALED-INPUT -s "$range"`, `ensure_jump INPUT SEALED-INPUT -i "$CONTAINER_BRIDGES"`,
		`ensure_jump "$1" SEALED-EDGE -i "$EDGE_BRIDGE"`, `ensure_jump "$1" SEALED-EDGE -s "$EDGE_SUBNET"`,
		"hook_edge FORWARD", "hook_edge DOCKER-USER", "iptables -w -C FORWARD -j DOCKER-USER",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	if strings.Contains(s, "\r") {
		t.Error("CR in script")
	}
	if _, err := HostRulesScript("172.31.0.0/24", "10.0.0.2"); err == nil {
		t.Error("egress IP outside subnet accepted")
	}
	if out, err := exec.Command("bash", "-n", "-c", s).CombinedOutput(); err != nil {
		t.Fatalf("bash -n: %v\n%s", err, out)
	}
}

// fakeIptables simulates the iptables subset the host rules use, one file per
// chain under $FAKE_IPT, so the script's control flow runs for real.
const fakeIptables = `#!/bin/bash
set -u
args=()
for a in "$@"; do [ "$a" = "-w" ] || args+=("$a"); done
set -- "${args[@]}"
echo "$*" >> "$FAKE_IPT/log"
op=$1; shift
case "$op" in
  -N) [ -e "$FAKE_IPT/chain.$1" ] && exit 1; : > "$FAKE_IPT/chain.$1" ;;
  -F) [ -e "$FAKE_IPT/chain.$1" ] || exit 1; : > "$FAKE_IPT/chain.$1" ;;
  -A) c=$1; shift; [ -e "$FAKE_IPT/chain.$c" ] || exit 1; echo "$*" >> "$FAKE_IPT/chain.$c" ;;
  -I) c=$1; pos=$2; shift 2; f="$FAKE_IPT/chain.$c"; [ -e "$f" ] || exit 1
      { head -n $((pos-1)) "$f"; echo "$*"; tail -n +$pos "$f"; } > "$f.tmp"; mv "$f.tmp" "$f" ;;
  -C) c=$1; shift; [ -e "$FAKE_IPT/chain.$c" ] && grep -qxF -- "$*" "$FAKE_IPT/chain.$c" ;;
  -n) [ "$1" = "-L" ] && [ -e "$FAKE_IPT/chain.$2" ] ;;
  *) exit 2 ;;
esac
`

func TestHostRulesScriptRuns(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not installed")
	}
	script, err := HostRulesScript(EdgeSubnet, EgressEdgeIP)
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "iptables"), []byte(fakeIptables), 0o755); err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(t.TempDir(), "pre-launch.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	// hook_edge inserts the interface jump first, then the source jump on
	// top of it; INPUT gets the two range jumps, then the bridge jump.
	edgeJumps := []string{"-s 172.31.0.0/24 -j SEALED-EDGE", "-i sealed-edge -j SEALED-EDGE"}
	inputJumps := []string{"-i sealed-+ -j SEALED-INPUT", "-s 172.31.0.0/24 -j SEALED-INPUT", "-s 172.30.0.0/16 -j SEALED-INPUT"}
	run := func(t *testing.T, state string, chains map[string]string) (string, error) {
		for name, rules := range chains {
			if err := os.WriteFile(filepath.Join(state, "chain."+name), []byte(rules), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		cmd := exec.Command("bash", scriptPath)
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "FAKE_IPT="+state)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	read := func(state, chain string) []string {
		b, _ := os.ReadFile(filepath.Join(state, "chain."+chain))
		return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	}
	head := func(rules []string, n int) string {
		if len(rules) < n {
			return strings.Join(rules, " | ")
		}
		return strings.Join(rules[:n], " | ")
	}
	t.Run("docker iptables backend", func(t *testing.T) {
		state := t.TempDir()
		chains := map[string]string{"INPUT": "-j ACCEPT\n", "FORWARD": "-j DOCKER-USER\n-j DOCKER-FORWARD\n", "DOCKER-USER": "-j RETURN\n"}
		if out, err := run(t, state, chains); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		check := func(when string) {
			if fw := read(state, "FORWARD"); head(fw, 2) != strings.Join(edgeJumps, " | ") || len(fw) != 4 {
				t.Errorf("%s: FORWARD %q", when, fw)
			}
			if du := read(state, "DOCKER-USER"); head(du, 2) != strings.Join(edgeJumps, " | ") || len(du) != 3 || du[2] != "-j RETURN" {
				t.Errorf("%s: DOCKER-USER %q", when, du)
			}
			if in := read(state, "INPUT"); head(in, 3) != strings.Join(inputJumps, " | ") || len(in) != 4 || in[3] != "-j ACCEPT" {
				t.Errorf("%s: INPUT %q", when, in)
			}
			edge := read(state, "SEALED-EDGE")
			if len(edge) != 4 || edge[3] != "-j DROP" {
				t.Errorf("%s: SEALED-EDGE %q", when, edge)
			}
			in := read(state, "SEALED-INPUT")
			if len(in) != 2 || in[0] != "-m conntrack --ctstate ESTABLISHED,RELATED -j RETURN" || in[1] != "-j DROP" {
				t.Errorf("%s: SEALED-INPUT %q", when, in)
			}
		}
		check("first boot")
		// A second boot keeps one copy of each jump and rebuilds the chains.
		if out, err := run(t, state, nil); err != nil {
			t.Fatalf("second run: %v %s", err, out)
		}
		check("second boot")
	})
	t.Run("no docker iptables chains", func(t *testing.T) {
		state := t.TempDir()
		if out, err := run(t, state, map[string]string{"INPUT": "", "FORWARD": ""}); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		if fw := read(state, "FORWARD"); strings.Join(fw, " | ") != strings.Join(edgeJumps, " | ") {
			t.Errorf("FORWARD %q", fw)
		}
		if in := read(state, "INPUT"); strings.Join(in, " | ") != strings.Join(inputJumps, " | ") {
			t.Errorf("INPUT %q", in)
		}
		if _, err := os.Stat(filepath.Join(state, "chain.DOCKER-USER")); err == nil {
			t.Error("script created an unhooked DOCKER-USER chain")
		}
	})
	t.Run("DOCKER-USER not hooked fails the boot", func(t *testing.T) {
		out, err := run(t, t.TempDir(), map[string]string{"INPUT": "", "FORWARD": "-j DOCKER-FORWARD\n", "DOCKER-USER": ""})
		if err == nil || !strings.Contains(out, "does not jump") {
			t.Fatalf("unhooked DOCKER-USER accepted: %v %s", err, out)
		}
	})
	t.Run("missing FORWARD fails the boot", func(t *testing.T) {
		if out, err := run(t, t.TempDir(), map[string]string{"INPUT": ""}); err == nil {
			t.Fatalf("script succeeded without a FORWARD chain: %s", out)
		}
	})
	t.Run("missing INPUT fails the boot", func(t *testing.T) {
		if out, err := run(t, t.TempDir(), map[string]string{"FORWARD": ""}); err == nil {
			t.Fatalf("script succeeded without an INPUT chain: %s", out)
		}
	})
}

func TestNetworkMatchesDefaults(t *testing.T) {
	d, err := LoadDefaults(filepath.Join("..", "..", "config", "defaults.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	n := d.Network
	if n.AppsSubnet != AppsSubnet || n.EdgeSubnet != EdgeSubnet || n.EgressAppsIP != EgressAppsIP || n.EgressEdgeIP != EgressEdgeIP || n.DNSIP != DNSIP {
		t.Fatalf("config/defaults.yaml network %+v differs from the composer constants", n)
	}
	// Compose accepts only bundles built for the runtime images' registry,
	// so catalog.registry must name the same one.
	ri, err := LoadRuntimeImages()
	if err != nil {
		t.Fatal(err)
	}
	if d.Catalog.Registry != ri.Registry {
		t.Errorf("catalog.registry %s differs from runtime-images.json registry %s", d.Catalog.Registry, ri.Registry)
	}
}

func TestRuntimeImages(t *testing.T) {
	ri, err := LoadRuntimeImages()
	if err != nil {
		t.Fatal(err)
	}
	if got := ri.Images["caddy"].Ref; got != "ghcr.io/sealedtempo/caddy@sha256:eb4d35b7452d1ab6171fbdbe8d9275b2301dad6dad92115d91e19fb9b24d510f" {
		t.Errorf("caddy ref %s", got)
	}
	unbuilt := ri.Unbuilt()
	sort.Strings(unbuilt)
	if strings.Join(unbuilt, ",") != "sealed-agent,sealed-egress,sealed-init,sealed-mpp-payer,sealed-verifierd" {
		t.Errorf("unbuilt %v", unbuilt)
	}
	bad := bytes.Replace(runtimeImagesJSON, []byte(`"unbuilt": true`), []byte(`"unbuilt": false`), 1)
	if _, err := parseRuntimeImages(bad); err == nil {
		t.Error("zero digest without unbuilt accepted")
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func contains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
