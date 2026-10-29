package composer

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestParseConfigExample(t *testing.T) {
	raw, err := os.ReadFile("testdata/config.json")
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if c.Hostnames.Scheme != SchemeSslip || len(c.Apps) != 2 || c.EgressAdditions["notes"][0] != "smtp.example.com:587" {
		t.Fatalf("%+v", c)
	}
	host, _ := c.Hostname("gateway")
	if host != "gateway.34-1-2-3.sslip.io" {
		t.Fatalf("host %s", host)
	}
	canon, err := c.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	again, err := ParseConfig(canon)
	if err != nil {
		t.Fatal(err)
	}
	canon2, _ := again.CanonicalJSON()
	if string(canon) != string(canon2) {
		t.Fatal("canonical config is not a fixed point")
	}
}

func TestParseConfigNormalizesOptionalFields(t *testing.T) {
	raw, _ := os.ReadFile("testdata/config.json")
	s := strings.Replace(string(raw), `"egressAdditions": { "notes": ["smtp.example.com:587"] },`, "", 1)
	s = strings.Replace(s, `"allowedVpcRanges": [],`, "", 1)
	c, err := ParseConfig([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	canon, _ := c.CanonicalJSON()
	if !strings.Contains(string(canon), `"allowedVpcRanges":[]`) || !strings.Contains(string(canon), `"egressAdditions":{}`) {
		t.Fatalf("not normalized: %s", canon)
	}
}

func TestParseConfigRejects(t *testing.T) {
	raw, _ := os.ReadFile("testdata/config.json")
	base := string(raw)
	cases := map[string][2]string{
		"unknown field":         {`"chainId": 4217,`, `"chainId": 4217, "extra": 1,`},
		"case-folded key":       {`"customer"`, `"Customer"`},
		"duplicate key":         {`"chainId": 4217,`, `"chainId": 4217, "chainId": 1,`},
		"float":                 {`"intervalMinutes": 60`, `"intervalMinutes": 60.5`},
		"checksummed address":   {`0x00000000000000000000000000000000000000c1`, `0x00000000000000000000000000000000000000C1`},
		"short salt":            {`"salt": "0x5a5a`, `"salt": "0x5a`},
		"zero image":            {`"imageId": "0x1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d"`, `"imageId": "0x0000000000000000000000000000000000000000000000000000000000000000"`},
		"composer version":      {`"composerVersion": "1.4.0"`, `"composerVersion": "0.9.0"`},
		"unsorted apps":         {`{ "id": "llm-gateway"`, `{ "id": "zz-gateway"`},
		"bad scheme":            {`"scheme": "sslip"`, `"scheme": "nip"`},
		"bad ip":                {`"ip": "34.1.2.3"`, `"ip": "34.1.2"`},
		"additions unknown app": {`"egressAdditions": { "notes"`, `"egressAdditions": { "crm"`},
		"bad addition":          {`smtp.example.com:587`, `smtp.example.com`},
		"public vpc range":      {`"allowedVpcRanges": []`, `"allowedVpcRanges": ["8.8.8.0/24"]`},
		"overlapping range":     {`"allowedVpcRanges": []`, `"allowedVpcRanges": ["172.30.0.0/16"]`},
		"range beyond private":  {`"allowedVpcRanges": []`, `"allowedVpcRanges": ["10.0.0.0/7"]`},
		"metadata addition":     {`smtp.example.com:587`, `169.254.169.254:80`},
		"loopback addition":     {`smtp.example.com:587`, `127.0.0.1:25`},
		"private addition":      {`smtp.example.com:587`, `10.1.2.3:25`},
		"cgnat endpoint":        {`https://rpc.tempo.xyz`, `https://100.64.1.1`},
		"settlement mode":       {`"mode": "access-key"`, `"mode": "card"`},
		"spend limit":           {`"spendLimitPerDay": "2000000"`, `"spendLimitPerDay": "2.5"`},
		"endpoint creds":        {`https://rpc.tempo.xyz`, `https://user:pw@rpc.tempo.xyz`},
		"endpoint scheme":       {`https://rpc.tempo.xyz`, `ftp://rpc.tempo.xyz`},
		// Review C-4: every endpoint is https.
		"http rpc":          {`https://rpc.tempo.xyz`, `http://rpc.tempo.xyz`},
		"http key broker":   {`https://sealed-key-broker-xyz.a.run.app`, `http://sealed-key-broker-xyz.a.run.app`},
		"http platform api": {`https://api.sealed.example`, `http://api.sealed.example`},
		"http relay attest": {`"https://attest.relay.sealed.example/attest"`, `"http://attest.relay.sealed.example/attest"`},
		"opaque endpoint":   {`https://rpc.tempo.xyz`, `https:rpc.tempo.xyz`},
		// Review C-11: relayAttest is the relay agent's /attest.
		"relay attest path":     {`relay.sealed.example/attest"`, `relay.sealed.example/v1/attest"`},
		"relay attest slash":    {`relay.sealed.example/attest"`, `relay.sealed.example/attest/"`},
		"relay attest query":    {`relay.sealed.example/attest"`, `relay.sealed.example/attest?x=1"`},
		"relay attest empty q":  {`relay.sealed.example/attest"`, `relay.sealed.example/attest?"`},
		"relay attest fragment": {`relay.sealed.example/attest"`, `relay.sealed.example/attest#x"`},
		"relay attest root":     {`relay.sealed.example/attest"`, `relay.sealed.example"`},
		"schema":                {`"sealed-config/v1"`, `"sealed-config/v2"`},
	}
	for name, c := range cases {
		mut := strings.Replace(base, c[0], c[1], 1)
		if mut == base {
			t.Fatalf("%s: replacement did not apply", name)
		}
		if _, err := ParseConfig([]byte(mut)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCustomHostnames(t *testing.T) {
	c := testConfig()
	c.Hostnames = Hostnames{Scheme: SchemeCustom, Domains: map[string]string{"gateway": "llm.example.com", "attest": "attest.example.com"}}
	if err := c.validateHostnames(); err != nil {
		t.Fatal(err)
	}
	if h, _ := c.Hostname("gateway"); h != "llm.example.com" {
		t.Fatal(h)
	}
	if _, err := c.Hostname("crm"); err == nil {
		t.Fatal("missing domain accepted")
	}
	c.Hostnames.Domains["crm"] = "llm.example.com"
	if err := c.validateHostnames(); err == nil {
		t.Fatal("duplicate domain accepted")
	}
	c.Hostnames.Domains = map[string]string{"bogus": "x.example.com"}
	if err := c.validateHostnames(); err == nil {
		t.Fatal("unknown route accepted")
	}
}

func TestGoBuiltConfigMatchesParsed(t *testing.T) {
	c := testConfig()
	c.Apps = []ConfigApp{{ID: "notes", ReleaseID: "0x" + strings.Repeat("ab", 32)}}
	c.EgressAdditions, c.AllowedVpcRanges = nil, nil
	a, err := c.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseConfig(a)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := parsed.CanonicalJSON()
	if string(a) != string(b) || !strings.Contains(string(a), `"egressAdditions":{}`) {
		t.Fatalf("%s\n%s", a, b)
	}
	c.EgressAdditions = map[string][]string{"notes": nil}
	d, _ := c.CanonicalJSON()
	if !strings.Contains(string(d), `"notes":[]`) {
		t.Fatalf("nil list must encode as []: %s", d)
	}
}

func TestPrivateAdditionsNeedVpcRange(t *testing.T) {
	c := testConfig()
	c.Apps = []ConfigApp{{ID: "notes", ReleaseID: "0x" + strings.Repeat("ab", 32)}}
	c.EgressAdditions = map[string][]string{"notes": {"10.10.3.4:5432"}}
	if err := c.Validate(); err == nil {
		t.Fatal("private addition without allowedVpcRanges accepted")
	}
	c.AllowedVpcRanges = []string{"10.10.0.0/16"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.EgressAdditions["notes"] = []string{"10.20.3.4:5432"}
	if err := c.Validate(); err == nil {
		t.Fatal("private addition outside allowedVpcRanges accepted")
	}
}

func TestConfigCounts(t *testing.T) {
	c := testConfig()
	for i := 0; i <= MaxConfigApps; i++ {
		c.Apps = append(c.Apps, ConfigApp{ID: fmt.Sprintf("app%02d", i), ReleaseID: "0x" + strings.Repeat("ab", 32)})
	}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "apps") {
		t.Fatalf("too many apps: %v", err)
	}
	c.Apps = c.Apps[:5]
	c.EgressAdditions = map[string][]string{}
	for i, a := range c.Apps {
		for j := 0; j < MaxEgressAdditionsPerApp; j++ {
			c.EgressAdditions[a.ID] = append(c.EgressAdditions[a.ID], fmt.Sprintf("h%d-%d.example.com:443", i, j))
		}
	}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "in total") {
		t.Fatalf("too many additions in total: %v", err)
	}
	c.AllowedVpcRanges = nil
	for i := 0; i <= MaxAllowedVpcRanges; i++ {
		c.AllowedVpcRanges = append(c.AllowedVpcRanges, fmt.Sprintf("10.%d.0.0/16", i))
	}
	c.EgressAdditions = nil
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "allowedVpcRanges") {
		t.Fatalf("too many ranges: %v", err)
	}
}

// The TypeScript twin (@sealed/core sealedConfigSchema) must accept every settlement block this accepts, or a stack
// composes and is approved but the agent refuses its config at boot (found by make devnet-e2e).
func TestSettlementGracePeriodZeroIsValid(t *testing.T) {
	raw, _ := os.ReadFile("testdata/config.json")
	base := string(raw)
	grace := `"gracePeriodMinutes": 1440`
	if !strings.Contains(base, grace) {
		t.Fatalf("fixture changed: no %s", grace)
	}
	if _, err := ParseConfig([]byte(strings.Replace(base, grace, `"gracePeriodMinutes": 0`, 1))); err != nil {
		t.Fatalf("grace period 0: %v", err)
	}
	if _, err := ParseConfig([]byte(strings.Replace(base, grace, `"gracePeriodMinutes": -1`, 1))); err == nil {
		t.Fatal("a negative grace period must be refused")
	}
}
