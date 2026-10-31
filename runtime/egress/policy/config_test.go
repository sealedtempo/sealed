package policy

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sampleConfig() *Config {
	return &Config{
		Listen:      &Listen{Proxy: ":3128", DNS: ":53", Stats: ":9100"},
		UpstreamDNS: []string{"8.8.8.8:53"},
		Callers: []Caller{
			{Name: "sealed-agent", IP: "172.30.0.3", Allow: []string{"sealed-key-broker-xyz.a.run.app:443", "rpc.tempo.xyz:443"}},
			{Name: "scraper", IP: "172.30.0.16", Allow: []string{"*.example.com:443", "example.com:443"}},
		},
		AllowedPrivateCIDRs: []string{},
		StatsReaders:        []string{"172.30.0.3"},
	}
}

func encode(t *testing.T, v any) []byte {
	t.Helper()
	b, err := EncodeCanonical(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseInterfacesExample(t *testing.T) {
	// The INTERFACES section 12 example, canonicalized.
	data := []byte(`{"allowedPrivateCidrs":[],"callers":[{"allow":["sealed-key-broker-xyz.a.run.app:443"],"ip":"172.30.0.3","name":"sealed-agent"}],"listen":{"dns":":53","proxy":":3128","stats":":9100"},"statsReaders":["172.30.0.3"],"upstreamDns":["8.8.8.8:53"]}`)
	cfg, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	agent, ok := p.CallerByIP(netip.MustParseAddr("172.30.0.3"))
	if !ok || agent.Name != "sealed-agent" {
		t.Fatalf("CallerByIP = %v, %v", agent, ok)
	}
	if _, ok := agent.Allow.Match("sealed-key-broker-xyz.a.run.app", 443); !ok {
		t.Error("agent cannot reach the key broker")
	}
	if !p.IsStatsReader(netip.MustParseAddr("172.30.0.3")) || p.IsStatsReader(netip.MustParseAddr("172.30.0.16")) {
		t.Error("stats readers wrong")
	}
	if _, ok := p.CallerByIP(netip.MustParseAddr("172.30.0.99")); ok {
		t.Error("unknown IP resolved to a caller")
	}
}

func TestParseRoundTrip(t *testing.T) {
	data := encode(t, sampleConfig())
	cfg, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Callers) != 2 || cfg.Callers[1].Allow[0] != "*.example.com:443" {
		t.Fatalf("unexpected config %+v", cfg)
	}
	path := filepath.Join(t.TempDir(), "egress.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, raw, err := Load(path); err != nil || string(raw) != string(data) {
		t.Fatalf("Load: %v", err)
	}
	if _, _, err := Load(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("Load of a missing file succeeded")
	}
}

func TestParseRejectsNonCanonical(t *testing.T) {
	good := string(encode(t, sampleConfig()))
	cases := map[string]string{
		"two newlines":   good + "\n\n",
		"crlf":           good + "\r\n",
		"whitespace":     strings.Replace(good, `"listen":`, `"listen": `, 1),
		"unsorted keys":  strings.Replace(good, `{"dns":":53","proxy":":3128","stats":":9100"}`, `{"proxy":":3128","dns":":53","stats":":9100"}`, 1),
		"duplicate key":  strings.Replace(good, `"statsReaders":["172.30.0.3"]`, `"statsReaders":["172.30.0.3"],"statsReaders":["172.30.0.3"]`, 1),
		"escaped slash":  strings.Replace(good, `"8.8.8.8:53"`, `"8.8.8.8:53\/"`, 1),
		"unicode escape": strings.Replace(good, `"scraper"`, `"scr\u0061per"`, 1),
		"trailing data":  good + "{}",
		"not json":       "listen: :3128",
		"empty":          "",
	}
	for name, data := range cases {
		if _, err := Parse([]byte(data)); err == nil {
			t.Errorf("%s: Parse succeeded", name)
		}
	}
}

func TestCheckCanonicalNumbers(t *testing.T) {
	if err := CheckCanonical([]byte(`{"a":1,"b":-2,"c":[0]}`)); err != nil {
		t.Errorf("integers rejected: %v", err)
	}
	for _, bad := range []string{`{"a":1.5}`, `{"a":1e3}`, `{"a":9007199254740993}`, `{"a":01}`, `{"é":1}`} {
		if err := CheckCanonical([]byte(bad)); err == nil {
			t.Errorf("CheckCanonical(%s) accepted", bad)
		}
	}
	if err := CheckCanonical([]byte("\"\\u0001\\n\"")); err != nil {
		t.Errorf("control escapes rejected: %v", err)
	}
	if err := CheckCanonical([]byte("\"\\u000A\"")); err == nil {
		t.Error("\\u000A accepted where \\n is canonical")
	}
}

func TestParseRejectsBadFields(t *testing.T) {
	cases := map[string]func(c *Config){
		"missing listen":          func(c *Config) { c.Listen = nil },
		"bad proxy listen":        func(c *Config) { c.Listen.Proxy = "3128" },
		"hostname listen":         func(c *Config) { c.Listen.Proxy = "localhost:3128" },
		"listen port reused":      func(c *Config) { c.Listen.Stats = ":3128" },
		"no upstream":             func(c *Config) { c.UpstreamDNS = []string{} },
		"null upstream":           func(c *Config) { c.UpstreamDNS = nil },
		"hostname upstream":       func(c *Config) { c.UpstreamDNS = []string{"dns.google:53"} },
		"upstream without port":   func(c *Config) { c.UpstreamDNS = []string{"8.8.8.8"} },
		"duplicate upstream":      func(c *Config) { c.UpstreamDNS = []string{"8.8.8.8:53", "8.8.8.8:53"} },
		"null callers":            func(c *Config) { c.Callers = nil },
		"bad caller name":         func(c *Config) { c.Callers[0].Name = "Sealed Agent" },
		"reserved unknown name":   func(c *Config) { c.Callers[0].Name = UnknownCaller },
		"duplicate caller name":   func(c *Config) { c.Callers[1].Name = c.Callers[0].Name },
		"duplicate caller ip":     func(c *Config) { c.Callers[1].IP = c.Callers[0].IP },
		"caller ip not canonical": func(c *Config) { c.Callers[0].IP = "172.030.0.3" },
		"caller ip unspecified":   func(c *Config) { c.Callers[0].IP = "0.0.0.0" },
		"null allow":              func(c *Config) { c.Callers[0].Allow = nil },
		"bad allow entry":         func(c *Config) { c.Callers[0].Allow = []string{"example.com"} },
		"duplicate allow entry":   func(c *Config) { c.Callers[0].Allow = []string{"example.com:443", "example.com:443"} },
		"wildcard public suffix":  func(c *Config) { c.Callers[0].Allow = []string{"*.com:443"} },
		"private ip entry":        func(c *Config) { c.Callers[0].Allow = []string{"10.0.0.5:443"} },
		"metadata ip entry":       func(c *Config) { c.Callers[0].Allow = []string{"169.254.169.254:80"} },
		"loopback ip entry":       func(c *Config) { c.Callers[0].Allow = []string{"127.0.0.1:443"} },
		"null private cidrs":      func(c *Config) { c.AllowedPrivateCIDRs = nil },
		"public cidr":             func(c *Config) { c.AllowedPrivateCIDRs = []string{"8.8.8.0/24"} },
		"link-local cidr":         func(c *Config) { c.AllowedPrivateCIDRs = []string{"169.254.0.0/16"} },
		"non-canonical cidr":      func(c *Config) { c.AllowedPrivateCIDRs = []string{"10.0.0.1/8"} },
		"duplicate cidr":          func(c *Config) { c.AllowedPrivateCIDRs = []string{"10.0.0.0/8", "10.0.0.0/8"} },
		"overlapping cidrs":       func(c *Config) { c.AllowedPrivateCIDRs = []string{"10.0.0.0/8", "10.1.0.0/16"} },
		"cidr inside apps net":    func(c *Config) { c.AllowedPrivateCIDRs = []string{"172.30.0.0/25"} },
		"cidr is edge net":        func(c *Config) { c.AllowedPrivateCIDRs = []string{"172.31.0.0/24"} },
		"cidr is an app net":      func(c *Config) { c.AllowedPrivateCIDRs = []string{"172.30.1.0/24"} },
		"cidr in app net space":   func(c *Config) { c.AllowedPrivateCIDRs = []string{"172.30.128.0/20"} },
		"cidr is verifier net":    func(c *Config) { c.AllowedPrivateCIDRs = []string{"172.30.250.0/24"} },
		"cidr is all of 172.30":   func(c *Config) { c.AllowedPrivateCIDRs = []string{"172.30.0.0/16"} },
		"app-net ip entry": func(c *Config) {
			c.AllowedPrivateCIDRs = []string{"172.16.0.0/12"}
			c.Callers[0].Allow = []string{"172.30.2.17:5432"}
		},
		"vm-internal ip entry": func(c *Config) {
			c.AllowedPrivateCIDRs = []string{"172.16.0.0/12"}
			c.Callers[0].Allow = []string{"172.30.0.1:22"}
		},
		"null stats readers":     func(c *Config) { c.StatsReaders = nil },
		"bad stats reader":       func(c *Config) { c.StatsReaders = []string{"agent"} },
		"duplicate stats reader": func(c *Config) { c.StatsReaders = []string{"172.30.0.3", "172.30.0.3"} },
	}
	for name, mutate := range cases {
		c := sampleConfig()
		mutate(c)
		if _, err := Parse(encode(t, c)); err == nil {
			t.Errorf("%s: Parse succeeded", name)
		}
	}
}

func TestParseAllowsPrivateIPEntryInsideAllowedCIDR(t *testing.T) {
	c := sampleConfig()
	c.AllowedPrivateCIDRs = []string{"10.0.0.0/8"}
	c.Callers[0].Allow = append(c.Callers[0].Allow, "10.0.0.5:5432")
	if _, err := Parse(encode(t, c)); err != nil {
		t.Fatal(err)
	}
}

func TestParseRejectsKeyCaseAndExtras(t *testing.T) {
	good := string(encode(t, sampleConfig()))
	cases := map[string]string{
		"capitalized key": strings.Replace(good, `"callers"`, `"Callers"`, 1),
		"unknown key":     strings.Replace(good, `"upstreamDns":`, `"upstreamDnz":[],"upstreamDns":`, 1),
		"caller extra":    strings.Replace(good, `"name":"scraper"`, `"name":"scraper","role":"x"`, 1),
		"proxyAuth false": strings.Replace(good, `"name":"scraper"`, `"name":"scraper","proxyAuth":false`, 1),
		"proxyAuth case":  strings.Replace(good, `"name":"scraper"`, `"name":"scraper","proxyauth":true`, 1),
		"proxyAuth type":  strings.Replace(good, `"name":"scraper"`, `"name":"scraper","proxyAuth":"yes"`, 1),
		"listen missing":  strings.Replace(good, `"proxy":":3128",`, ``, 1),
		"wrong type":      strings.Replace(good, `"statsReaders":["172.30.0.3"]`, `"statsReaders":"172.30.0.3"`, 1),
	}
	for name, data := range cases {
		if _, err := Parse([]byte(data)); err == nil {
			t.Errorf("%s: Parse succeeded", name)
		}
	}
}

func TestValidateReportsEveryProblem(t *testing.T) {
	c := sampleConfig()
	c.UpstreamDNS = []string{"nope"}
	c.Callers[0].Allow = []string{"bad"}
	err := c.Validate()
	if err == nil {
		t.Fatal("Validate succeeded")
	}
	for _, want := range []string{"upstreamDns[0]", "callers[0].allow[0]"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %s", err, want)
		}
	}
}

func TestParseAcceptsOneTrailingNewline(t *testing.T) {
	data := encode(t, sampleConfig())
	if _, err := Parse(append(append([]byte(nil), data...), '\n')); err != nil {
		t.Fatalf("one trailing LF (YAML block scalar) rejected: %v", err)
	}
	path := filepath.Join(t.TempDir(), "egress.json")
	if err := os.WriteFile(path, append(append([]byte(nil), data...), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, raw, err := Load(path); err != nil || string(raw) != string(data) {
		t.Fatalf("Load = %q, %v; want the canonical bytes without the LF", raw, err)
	}
}

func TestProxyAuthIsOptionalAndCanonical(t *testing.T) {
	c := sampleConfig()
	c.Callers[0].ProxyAuth = true
	data := encode(t, c)
	if !strings.Contains(string(data), `"name":"sealed-agent","proxyAuth":true}`) {
		t.Fatalf("encoding = %s", data)
	}
	parsed, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Compile(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.ProxyAuthCallers(); len(got) != 1 || got[0] != "sealed-agent" {
		t.Errorf("ProxyAuthCallers = %v", got)
	}
	if agent, _ := p.CallerByName("sealed-agent"); !agent.ProxyAuth {
		t.Error("CallerPolicy.ProxyAuth not set")
	}
	if scraper, _ := p.CallerByName("scraper"); scraper.ProxyAuth {
		t.Error("ProxyAuth set for a caller without the key")
	}
	// Configs without the key keep their bytes.
	if strings.Contains(string(encode(t, sampleConfig())), "proxyAuth") {
		t.Error("proxyAuth emitted when false")
	}
}

func TestBroadPrivateCIDRDoesNotOpenVMNetworks(t *testing.T) {
	c := sampleConfig()
	c.AllowedPrivateCIDRs = []string{"172.16.0.0/12"}
	p, err := Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"172.30.0.1", "172.30.0.3", "172.31.0.1", "172.31.0.2"} {
		if p.IP().Check(netip.MustParseAddr(ip)) == nil {
			t.Errorf("%s reachable through allowedPrivateCidrs 172.16.0.0/12", ip)
		}
	}
	if p.IP().Check(netip.MustParseAddr("172.20.1.5")) != nil {
		t.Error("VPC address inside 172.16.0.0/12 denied")
	}
}

func TestCompileLocalDeny(t *testing.T) {
	c := sampleConfig()
	c.AllowedPrivateCIDRs = []string{"10.0.0.0/8"}
	p, err := Compile(c, netip.MustParsePrefix("10.9.0.0/16"), netip.MustParsePrefix("203.0.113.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"10.9.0.1", "203.0.113.7"} {
		if p.IP().Check(netip.MustParseAddr(ip)) == nil {
			t.Errorf("%s on a local network was allowed", ip)
		}
	}
	if p.IP().Check(netip.MustParseAddr("10.8.0.1")) != nil {
		t.Error("allowed private address denied")
	}
	denied := p.IP().DeniedPrefixes()
	if denied[len(denied)-1] != netip.MustParsePrefix("203.0.113.0/24") {
		t.Errorf("DeniedPrefixes does not end with the local networks: %v", denied[len(denied)-2:])
	}
}

// TestPrivateDestinationsArePerCallerAndRawIPOnly is the runtime-1 rule at
// the policy level: allowedPrivateCidrs is stack-wide, but a private
// address is reached only by the caller that lists it as a raw IP entry,
// on that entry's port, and never through a hostname.
func TestPrivateDestinationsArePerCallerAndRawIPOnly(t *testing.T) {
	c := sampleConfig()
	c.AllowedPrivateCIDRs = []string{"10.20.0.0/16"}
	c.Callers[0].Allow = append(c.Callers[0].Allow, "10.20.0.5:443", "10.20.0.7:5432", "10.20.9.9:443", "198.51.100.7:443")
	c.Callers[1].Allow = append(c.Callers[1].Allow, "10.20.0.7:5432")
	p, err := Compile(c, netip.MustParsePrefix("10.20.9.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	agent, _ := p.CallerByName("sealed-agent")
	scraper, _ := p.CallerByName("scraper")
	// 10.20.9.9 sits on a local network, so it opens nothing; the public
	// raw IP is not a private entry.
	if got := fmt.Sprint(agent.PrivateEntries()); got != "[10.20.0.5:443 10.20.0.7:5432]" {
		t.Errorf("agent private entries = %s", got)
	}
	if got := fmt.Sprint(scraper.PrivateEntries()); got != "[10.20.0.7:5432]" {
		t.Errorf("scraper private entries = %s", got)
	}
	if got := fmt.Sprint(p.PrivateEntries()); got != "[10.20.0.5:443 10.20.0.7:5432]" {
		t.Errorf("all private entries = %s", got)
	}

	ap := netip.MustParseAddrPort
	allowed := []struct {
		c    *CallerPolicy
		host string
		addr string
	}{
		{agent, "10.20.0.5", "10.20.0.5:443"},
		{agent, "10.20.0.7", "10.20.0.7:5432"},
		{scraper, "10.20.0.7", "10.20.0.7:5432"},
		{agent, "198.51.100.7", "198.51.100.7:443"},
		{scraper, "example.com", "203.0.113.10:443"},
	}
	for _, a := range allowed {
		if err := p.CheckDial(a.c, a.host, ap(a.addr)); err != nil {
			t.Errorf("CheckDial(%s, %s, %s) = %v", a.c.Name, a.host, a.addr, err)
		}
	}
	denied := []struct {
		c    *CallerPolicy
		host string
		addr string
	}{
		{scraper, "10.20.0.5", "10.20.0.5:443"},        // another caller's raw IP entry
		{agent, "10.20.0.5", "10.20.0.5:80"},           // another port
		{agent, "10.20.0.6", "10.20.0.6:443"},          // inside the range, but no entry
		{agent, "10.20.9.9", "10.20.9.9:443"},          // a local network
		{scraper, "example.com", "10.20.0.7:5432"},     // a name, rebinding onto the caller's own entry
		{agent, "rpc.tempo.xyz", "10.20.0.5:443"},      // a name, rebinding onto the caller's own entry
		{scraper, "example.com", "10.99.0.1:443"},      // a name onto a private address outside the range
		{scraper, "example.com", "169.254.169.254:80"}, // a name onto metadata
		{agent, "10.20.0.5", "10.20.0.7:443"},          // dialed address differs from the requested one
		{nil, "10.20.0.5", "10.20.0.5:443"},            // no caller
	}
	for _, d := range denied {
		name := "<nil>"
		if d.c != nil {
			name = d.c.Name
		}
		if err := p.CheckDial(d.c, d.host, ap(d.addr)); err == nil {
			t.Errorf("CheckDial(%s, %s, %s) allowed", name, d.host, d.addr)
		}
	}

	// The DNS-facing check refuses every private answer.
	for _, s := range []string{"10.20.0.5", "10.20.0.6", "10.99.0.1", "fd12::1", "100.64.0.1"} {
		if p.IP().CheckResolved(netip.MustParseAddr(s)) == nil {
			t.Errorf("CheckResolved(%s) allowed", s)
		}
	}
	if err := p.IP().CheckResolved(netip.MustParseAddr("203.0.113.10")); err != nil {
		t.Errorf("CheckResolved(public) = %v", err)
	}
}
