package caddy

import (
	"bytes"
	"strings"
	"testing"
)

func testInput() Input {
	return Input{
		ComposerVersion: "1.0.0",
		AdminSocket:     DefaultAdminSocket,
		GateUser:        DefaultGateUser,
		GateEnv:         DefaultGateEnv,
		PageDir:         DefaultPageDir,
		PageFile:        DefaultPageFile,
		AttestHost:      "attest.34-1-2-3.sslip.io",
		AttestUpstream:  "sealed-agent:7070",
		Sites: []Site{
			{Host: "crm.34-1-2-3.sslip.io", Routes: []Route{{Upstream: "crm-server:3000", Auth: AuthGate}}},
			{Host: "gateway.34-1-2-3.sslip.io", Routes: []Route{
				{Upstream: "llm-gateway-proxy:4000", Auth: AuthBearerPassthrough},
				{Path: "/ui", Upstream: "llm-gateway-proxy:4000", Auth: AuthGate},
			}},
			{Host: "tools.34-1-2-3.sslip.io", Routes: []Route{{Path: "/api", Upstream: "tools-api:8080", Auth: AuthPublic}}},
		},
	}
}

// checkBalanced verifies braces and quotes pair up line by line, the way the
// Caddyfile lexer sees them (no braces inside quoted tokens here).
func checkBalanced(t *testing.T, cf []byte) {
	t.Helper()
	depth := 0
	for i, line := range strings.Split(string(cf), "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "#") {
			continue
		}
		if strings.Count(trim, `"`)%2 != 0 {
			t.Fatalf("line %d: unbalanced quotes: %q", i+1, line)
		}
		unquoted := trim
		for strings.Contains(unquoted, `"`) {
			a := strings.Index(unquoted, `"`)
			b := strings.Index(unquoted[a+1:], `"`)
			unquoted = unquoted[:a] + unquoted[a+b+2:]
		}
		depth += strings.Count(unquoted, "{") - strings.Count(unquoted, "}")
		// Placeholders such as {env.X} and {query} open and close on one line.
		if depth < 0 {
			t.Fatalf("line %d: unbalanced braces", i+1)
		}
		if unquoted != "{" && strings.HasSuffix(unquoted, "{") && !strings.HasSuffix(unquoted, " {") {
			t.Fatalf("line %d: block opener must follow a space: %q", i+1, line)
		}
	}
	if depth != 0 {
		t.Fatalf("unbalanced braces at end: %d", depth)
	}
}

func TestRenderNormal(t *testing.T) {
	cf, err := Render(testInput(), false)
	if err != nil {
		t.Fatal(err)
	}
	checkBalanced(t, cf)
	s := string(cf)
	for _, want := range []string{
		"admin unix//run/sealed/caddy-admin/admin.sock",
		"persist_config off",
		"protocols h1 h2",
		"\ncrm.34-1-2-3.sslip.io {",
		"sealed {env.GATE_PASSWORD_BCRYPT}",
		"header_up -Authorization",
		"network_proxy none",
		"@r0 path /ui /ui/*",
		"@r1_bearer {\n\t\theader Authorization \"Bearer *\"\n\t}",
		"handle @r1_bearer {",
		"@r0 path /api /api/*",
		"respond \"Not found\" 404",
		"rewrite * /attest?{query}",
		"reverse_proxy sealed-agent:7070",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
	// The gate path route (/ui) must come before the whole-host bearer route.
	gw := s[strings.Index(s, "gateway.34"):]
	if strings.Index(gw, "handle @r0") > strings.Index(gw, "handle @r1_bearer") {
		t.Error("path route must precede the whole-host route")
	}
	// The public tools route has no gate.
	tools := s[strings.Index(s, "tools.34"):strings.Index(s, "attest.34")]
	if strings.Contains(tools, "basic_auth") {
		t.Error("public route gated")
	}
	if strings.Contains(s, "\u2014") || bytes.ContainsRune(cf, '\r') {
		t.Error("em-dash or CR in output")
	}
	again, _ := Render(testInput(), false)
	if !bytes.Equal(cf, again) {
		t.Fatal("not deterministic")
	}
}

func TestRenderPaymentNeeded(t *testing.T) {
	cf, err := Render(testInput(), true)
	if err != nil {
		t.Fatal(err)
	}
	checkBalanced(t, cf)
	s := string(cf)
	app := s[:strings.Index(s, "attest.34")]
	if strings.Contains(app, "reverse_proxy") || strings.Contains(app, "basic_auth") {
		t.Errorf("payment-needed sites still proxy:\n%s", app)
	}
	if strings.Count(s, "status 402") != 3 || !strings.Contains(s, "rewrite * /payment-needed.html") {
		t.Errorf("each site must serve the page:\n%s", s)
	}
	if !strings.Contains(s, "respond \""+PaymentMessage+"\" 402") {
		t.Error("bearer API calls should get a plain 402")
	}
	if !strings.Contains(s[strings.Index(s, "attest.34"):], "reverse_proxy sealed-agent:7070") {
		t.Error("attest must stay public")
	}
}

func TestRenderValidates(t *testing.T) {
	mutations := map[string]func(*Input){
		"host":      func(in *Input) { in.Sites[0].Host = "Bad Host" },
		"inject":    func(in *Input) { in.Sites[0].Host = "a.example.com {\n}\nevil.example.com" },
		"upstream":  func(in *Input) { in.Sites[0].Routes[0].Upstream = "crm-server" },
		"path":      func(in *Input) { in.Sites[1].Routes[1].Path = "/ui {" },
		"auth":      func(in *Input) { in.Sites[0].Routes[0].Auth = "none" },
		"duphost":   func(in *Input) { in.Sites[1].Host = in.Sites[0].Host },
		"dupattest": func(in *Input) { in.Sites[0].Host = in.AttestHost },
		"duppath":   func(in *Input) { in.Sites[1].Routes[1].Path = "" },
		"noroutes":  func(in *Input) { in.Sites[0].Routes = nil },
		"socket":    func(in *Input) { in.AdminSocket = "localhost:2019" },
		"env":       func(in *Input) { in.GateEnv = "x}" },
	}
	for name, mut := range mutations {
		in := testInput()
		mut(&in)
		if _, err := Render(in, false); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPaymentPage(t *testing.T) {
	page := string(PaymentNeededHTML)
	for _, banned := range []string{"\u2014", "no breaches", "unbreakable", "zero-knowledge", "http://", "https://", "<script"} {
		if strings.Contains(strings.ToLower(page), banned) {
			t.Errorf("page contains %q", banned)
		}
	}
	if !strings.Contains(page, "Your data stays in your cloud account") || !strings.Contains(page, "<title>Payment needed</title>") {
		t.Error("page copy changed")
	}
}
