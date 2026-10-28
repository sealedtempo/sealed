package caddy

import (
	"bytes"
	"encoding/base64"
	"regexp"
	"strings"
	"testing"
)

func testInput() Input {
	return Input{
		ComposerVersion: "1.0.0",
		AdminSocket:     DefaultAdminSocket,
		AdminSocketMode: DefaultAdminSocketMode,
		GateUpstream:    "sealed-agent:7070",
		GatePath:        DefaultGatePath,
		PageDir:         DefaultPageDir,
		PageFile:        DefaultPageFile,
		AttestHost:      "attest.34-1-2-3.sslip.io",
		AttestUpstream:  "sealed-agent:7070",
		Sites: []Site{
			{Host: "crm.34-1-2-3.sslip.io", Routes: []Route{{Name: "crm", Upstream: "crm-server:3000", Auth: AuthGate}}},
			{Host: "gateway.34-1-2-3.sslip.io", Routes: []Route{
				{Name: "gateway", Upstream: "llm-gateway-proxy:4000", Auth: AuthBearerPassthrough},
				{Name: "gateway", Path: "/ui", Upstream: "llm-gateway-proxy:4000", Auth: AuthGate},
			}},
			{Host: "tools.34-1-2-3.sslip.io", Routes: []Route{{Name: "tools", Path: "/api", Upstream: "tools-api:8080", Auth: AuthPublic}}},
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

// site returns one site block of a rendered Caddyfile.
func site(t *testing.T, cf, host string) string {
	t.Helper()
	i := strings.Index(cf, "\n"+host+" {\n")
	if i < 0 {
		t.Fatalf("no site %s in\n%s", host, cf)
	}
	rest := cf[i+1:]
	j := strings.Index(rest, "\n}\n")
	return rest[:j+3]
}

func TestRenderNormal(t *testing.T) {
	cf, err := Render(testInput(), false)
	if err != nil {
		t.Fatal(err)
	}
	checkBalanced(t, cf)
	s := string(cf)
	for _, want := range []string{
		"admin unix//run/sealed/caddy-admin/admin.sock|0660",
		"persist_config off",
		"protocols h1 h2",
		"\ncrm.34-1-2-3.sslip.io {",
		"forward_auth sealed-agent:7070 {\n\t\t\t\turi /v1/gate?route=crm\n",
		"copy_headers Set-Cookie>X-Sealed-Gate-Set-Cookie X-Sealed-Gate-Strip-Authorization",
		"@sealed_gate_strip header X-Sealed-Gate-Strip-Authorization 1",
		"request_header @sealed_gate_strip -Authorization",
		"header @sealed_gate_cookie Set-Cookie {http.request.header.X-Sealed-Gate-Set-Cookie}",
		"request_header @sealed_gate_basic -Authorization",
		`@sealed_gate_basic header_regexp Authorization "^[Bb][Aa][Ss][Ii][Cc][ \t]+c2VhbGVkO"`,
		"network_proxy none",
		"@r0 path /ui /ui/*",
		"@r1_bearer {\n\t\theader Authorization \"Bearer *\"\n\t}",
		"handle @r1_bearer {",
		"@r0 path /api /api/*",
		"respond \"Not found\" 404",
		"rewrite * /attest?{query}",
		"reverse_proxy sealed-agent:7070",
		`@sealed_gate_no_cookie header Cookie ""`,
		`request_header Cookie "(^|;\s*)sealed_gate=[^;]*" ""`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
	// Every proxied app request loses the gate cookie, gated or not.
	if n, m := strings.Count(s, "sealed_gate=[^;]*"), strings.Count(s, "reverse_proxy ")-strings.Count(s, "reverse_proxy sealed-agent"); n != m {
		t.Errorf("%d cookie strips for %d app proxies", n, m)
	}
	// basic_auth is gone: the gate is sealed-agent (D-044), and the gate
	// password never reaches Caddy.
	if strings.Contains(s, "basic_auth") || strings.Contains(s, "GATE_PASSWORD_BCRYPT") || strings.Contains(s, "header_up -Authorization") {
		t.Errorf("old basic_auth gate still rendered:\n%s", s)
	}
	// Inside each gated handle, client copies of the relay headers go first,
	// then the gate, then the cookie copy, then the strip of the gate's
	// Basic credentials (on the agent's signal, then by prefix) and of the
	// strip signal itself, then the app.
	crm := site(t, s, "crm.34-1-2-3.sslip.io")
	order := []string{"route {", "request_header -X-Sealed-Gate-Set-Cookie", "request_header -X-Sealed-Gate-Strip-Authorization", "forward_auth",
		"header @sealed_gate_cookie", "request_header -X-Sealed-Gate-Set-Cookie", "request_header @sealed_gate_strip -Authorization",
		"request_header -X-Sealed-Gate-Strip-Authorization", "request_header @sealed_gate_basic", "reverse_proxy crm-server:3000"}
	last := 0
	for _, o := range order {
		i := strings.Index(crm[last:], o)
		if i < 0 {
			t.Fatalf("%q missing or out of order in\n%s", o, crm)
		}
		last += i + len(o)
	}
	// The gate path route (/ui) must come before the whole-host bearer route,
	// and the gateway route's non-bearer requests go through the gate.
	gw := site(t, s, "gateway.34-1-2-3.sslip.io")
	if strings.Index(gw, "handle @r0") > strings.Index(gw, "handle @r1_bearer") {
		t.Error("path route must precede the whole-host route")
	}
	if strings.Count(gw, "uri /v1/gate?route=gateway") != 2 {
		t.Errorf("gateway: both the /ui route and non-bearer requests must be gated:\n%s", gw)
	}
	// The public tools route has no gate.
	if tools := site(t, s, "tools.34-1-2-3.sslip.io"); strings.Contains(tools, "forward_auth") || strings.Contains(tools, "sealed_gate_basic") {
		t.Errorf("public route gated:\n%s", tools)
	}
	if strings.Contains(s, "\u2014") || bytes.ContainsRune(cf, '\r') {
		t.Error("em-dash or CR in output")
	}
	again, _ := Render(testInput(), false)
	if !bytes.Equal(cf, again) {
		t.Fatal("not deterministic")
	}
}

// TestGateBasicPrefix pins that every Basic credential of the gate user, and
// no other user, starts with the prefix Caddy strips.
func TestGateBasicPrefix(t *testing.T) {
	for _, pw := range []string{"", "x", "pw", "correct horse battery staple", ":::", "\u00e9t\u00e9"} {
		enc := base64.StdEncoding.EncodeToString([]byte(DefaultGateUser + ":" + pw))
		if !strings.HasPrefix(enc, gateBasicPrefix) {
			t.Errorf("%q encodes to %s, not prefixed by %s", pw, enc, gateBasicPrefix)
		}
	}
	re := regexp.MustCompile(GateBasicRegexp)
	for _, user := range []string{"sealedx", "seale", "admin", "Sealed"} {
		enc := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":pw"))
		if re.MatchString(enc) {
			t.Errorf("user %q would be stripped: %s", user, enc)
		}
	}
	// Review C-3: sealed-agent accepts spaces or tabs after "Basic".
	cred := base64.StdEncoding.EncodeToString([]byte("sealed:pw"))
	for _, h := range []string{"Basic " + cred, "basic  " + cred, "Basic\t" + cred, "BASIC \t " + cred} {
		if !re.MatchString(h) {
			t.Errorf("%q not stripped", h)
		}
	}
	if re.MatchString("Bearer c2VhbGVkOnB3") {
		t.Error("a bearer token would be stripped")
	}
}

func TestRenderAttestHostRoutes(t *testing.T) {
	in := testInput()
	in.AttestRoutes = []Route{{Name: "relay", Path: "/v1", Upstream: "inference-relay-front:8080", Auth: AuthPublic}}
	cf, err := Render(in, false)
	if err != nil {
		t.Fatal(err)
	}
	checkBalanced(t, cf)
	attest := site(t, string(cf), in.AttestHost)
	for _, want := range []string{"@attest path / /attest", "@r0 path /v1 /v1/*", "handle @r0 {\n\t\troute {", "reverse_proxy inference-relay-front:8080 {", "respond \"Not found\" 404"} {
		if !strings.Contains(attest, want) {
			t.Errorf("attest site lacks %q:\n%s", want, attest)
		}
	}
	if strings.Index(attest, "handle @attest") > strings.Index(attest, "handle @r0") {
		t.Error("/attest must come first")
	}
	pn, err := Render(in, true)
	if err != nil {
		t.Fatal(err)
	}
	attest = site(t, string(pn), in.AttestHost)
	if strings.Contains(attest, "inference-relay-front") || !strings.Contains(attest, "handle @r0 {\n\t\trespond \""+PaymentMessage+"\" 402") {
		t.Errorf("payment-needed attest host must answer 402 on the relay route:\n%s", attest)
	}
	if !strings.Contains(attest, "reverse_proxy sealed-agent:7070") {
		t.Error("attest must stay up in payment-needed mode")
	}
	for name, bad := range map[string]Route{
		"no path":        {Name: "relay", Upstream: "a-b:1", Auth: AuthPublic},
		"attest path":    {Name: "relay", Path: "/attest", Upstream: "a-b:1", Auth: AuthPublic},
		"under attest":   {Name: "relay", Path: "/attest/x", Upstream: "a-b:1", Auth: AuthPublic},
		"bad route name": {Name: "Relay", Path: "/v1", Upstream: "a-b:1", Auth: AuthPublic},
	} {
		in := testInput()
		in.AttestRoutes = []Route{bad}
		if _, err := Render(in, false); err == nil {
			t.Errorf("%s: accepted", name)
		}
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
	if strings.Contains(app, "reverse_proxy") || strings.Contains(app, "forward_auth") {
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
		"host":        func(in *Input) { in.Sites[0].Host = "Bad Host" },
		"inject":      func(in *Input) { in.Sites[0].Host = "a.example.com {\n}\nevil.example.com" },
		"upstream":    func(in *Input) { in.Sites[0].Routes[0].Upstream = "crm-server" },
		"path":        func(in *Input) { in.Sites[1].Routes[1].Path = "/ui {" },
		"auth":        func(in *Input) { in.Sites[0].Routes[0].Auth = "none" },
		"duphost":     func(in *Input) { in.Sites[1].Host = in.Sites[0].Host },
		"dupattest":   func(in *Input) { in.Sites[0].Host = in.AttestHost },
		"duppath":     func(in *Input) { in.Sites[1].Routes[1].Path = "" },
		"noroutes":    func(in *Input) { in.Sites[0].Routes = nil },
		"socket":      func(in *Input) { in.AdminSocket = "localhost:2019" },
		"socket mode": func(in *Input) { in.AdminSocketMode = "666" },
		"gate path":   func(in *Input) { in.GatePath = "/v1/gate?x" },
		"gate host":   func(in *Input) { in.GateUpstream = "sealed-agent" },
		"route name":  func(in *Input) { in.Sites[0].Routes[0].Name = "crm}" },
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
