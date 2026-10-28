package composer

import (
	"bytes"
	"encoding/json"
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
	for _, stack := range [][]*Bundle{bundles, bundles[:1]} {
		c := testConfig(stack...)
		if stack[0].Manifest.ID == "notes" {
			c.EgressAdditions = map[string][]string{"notes": {"smtp.example.com:587"}}
		}
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
		if got := resolved.Configs["sealed-config"].Content; got != strings.ReplaceAll(string(r.ConfigJSON), "$", "$$") {
			t.Fatalf("config content changed by compose:\n%s", got)
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
	ip := func(name string) string {
		nets := svc(doc, name)["networks"].(map[string]any)
		return nets["apps"].(map[string]any)["ipv4_address"].(string)
	}
	for name, wantIP := range map[string]string{
		"sealed-egress": "172.30.0.2", "sealed-agent": "172.30.0.3", "caddy": "172.30.0.4",
		"sealed-mpp-payer": "172.30.0.5", "sealed-verifierd": "172.30.0.6",
		"llm-gateway-proxy": "172.30.0.16", "notes-web": "172.30.0.17", "notes-db": "172.30.0.18",
	} {
		if got := ip(name); got != wantIP {
			t.Errorf("%s ip %s, want %s", name, got, wantIP)
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
		"HTTP_PROXY": "http://172.30.0.2:3128", "HTTPS_PROXY": "http://172.30.0.2:3128", "http_proxy": "http://172.30.0.2:3128",
		"https_proxy": "http://172.30.0.2:3128", "NODE_USE_ENV_PROXY": "1", "NOTES_TELEMETRY": "0", "DO_NOT_TRACK": "1",
		"NOTES_WORKERS": "2", "NOTES_PRICE_LABEL": "costs $$5",
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
	if !jsonEqual(web["dns"], []any{"172.30.0.2"}) || web["restart"] != "unless-stopped" || !jsonEqual(web["logging"], map[string]any{"driver": "none"}) {
		t.Errorf("sidecar plumbing: dns %v restart %v logging %v", web["dns"], web["restart"], web["logging"])
	}
	aliases := web["networks"].(map[string]any)["apps"].(map[string]any)["aliases"]
	if !jsonEqual(aliases, []any{"notes"}) {
		t.Errorf("primary alias %v", aliases)
	}
	if _, ok := svc(doc, "notes-db")["networks"].(map[string]any)["apps"].(map[string]any)["aliases"]; ok {
		t.Error("non-primary service must not get the app alias")
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
		"volume:sealed-bin:/sealed/bin", "volume:sealed-ready:/run/sealed/ready", "volume:sealed-secrets-notes:/run/sealed/secrets/notes",
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
		if strings.Contains(string(raw), "dstack.sock") != isAgent || (s["cap_add"] != nil) != isAgent || (s["devices"] != nil) != isAgent {
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
	want := map[string]string{
		"sealed-agent@172.30.0.3":       "api.sealed.example:443 rpc.tempo.xyz:443 sealed-key-broker-xyz.a.run.app:443",
		"caddy@172.30.0.4":              "acme-v02.api.letsencrypt.org:443",
		"sealed-mpp-payer@172.30.0.5":   "relay.sealed.example:443 rpc.tempo.xyz:443",
		"sealed-verifierd@172.30.0.6":   "api.trustedservices.intel.com:443 attest.relay.sealed.example:443 certificates.trustedservices.intel.com:443 rpc.tempo.xyz:443",
		"llm-gateway-proxy@172.30.0.16": "",
		"notes-web@172.30.0.17":         "api.example.com:443 smtp.example.com:587",
		"notes-db@172.30.0.18":          "api.example.com:443 smtp.example.com:587",
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
		"admin unix//run/sealed/caddy-admin/admin.sock",
		"\ngateway.34-1-2-3.sslip.io {",
		"\ntools.34-1-2-3.sslip.io {",
		"\nattest.34-1-2-3.sslip.io {",
		"reverse_proxy sealed-agent:7070",
		"sealed {env.GATE_PASSWORD_BCRYPT}",
		`header Authorization "Bearer *"`,
		"reverse_proxy notes-web:8080",
		"@r0 path /admin /admin/*",
	} {
		if !strings.Contains(cf, want) {
			t.Errorf("Caddyfile lacks %q", want)
		}
	}
	pn := string(r.CaddyfilePaymentNeeded)
	if strings.Contains(pn, "reverse_proxy notes-web") || strings.Contains(pn, "basic_auth") {
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

func TestStackInfo(t *testing.T) {
	cfg, bundles := fixtureStack(t)
	r := mustCompose(t, cfg, bundles...)
	var si struct {
		Schema string `json:"schema"`
		Apps   []struct {
			ID        string `json:"id"`
			AppID     string `json:"appId"`
			ReleaseID string `json:"releaseId"`
			Metering  struct{ Unit, Source string }
		} `json:"apps"`
		AttestHost string `json:"attestHost"`
	}
	if err := json.Unmarshal(r.StackInfo, &si); err != nil {
		t.Fatal(err)
	}
	if si.Schema != "sealed-stack/v1" || len(si.Apps) != 2 || si.AttestHost != "attest.34-1-2-3.sslip.io" {
		t.Fatalf("%+v", si)
	}
	if si.Apps[1].ID != "notes" || si.Apps[1].AppID != AppID("notes").Hex() || si.Apps[1].Metering.Unit != "app_hour" {
		t.Fatalf("%+v", si.Apps[1])
	}
}

func TestHostRulesScript(t *testing.T) {
	s, err := HostRulesScript(EdgeSubnet, EgressEdgeIP)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"EDGE_SUBNET=172.31.0.0/24", "EGRESS_IP=172.31.0.2", "--ctstate ESTABLISHED,RELATED -j RETURN",
		`-s "$EGRESS_IP" -j RETURN`, "-A SEALED-EDGE -j DROP", `iptables -w -I DOCKER-USER 1 -s "$EDGE_SUBNET" -j SEALED-EDGE`,
		`iptables -w -C DOCKER-USER -s "$EDGE_SUBNET" -j SEALED-EDGE`,
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

func TestNetworkMatchesDefaults(t *testing.T) {
	d, err := LoadDefaults(filepath.Join("..", "..", "config", "defaults.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	n := d.Network
	if n.AppsSubnet != AppsSubnet || n.EdgeSubnet != EdgeSubnet || n.EgressAppsIP != EgressAppsIP || n.EgressEdgeIP != EgressEdgeIP || n.DNSIP != DNSIP {
		t.Fatalf("config/defaults.yaml network %+v differs from the composer constants", n)
	}
	if d.Catalog.Registry != testRegistry {
		t.Logf("catalog.registry is %s (tests use %s)", d.Catalog.Registry, testRegistry)
	}
}

func TestRuntimeImages(t *testing.T) {
	ri, err := LoadRuntimeImages()
	if err != nil {
		t.Fatal(err)
	}
	if got := ri.Images["caddy"].Ref; got != "ghcr.io/sealed-dev/caddy@sha256:eb4d35b7452d1ab6171fbdbe8d9275b2301dad6dad92115d91e19fb9b24d510f" {
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
