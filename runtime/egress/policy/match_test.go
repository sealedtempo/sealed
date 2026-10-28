package policy

import (
	"strings"
	"testing"
)

func mustEntries(t *testing.T, ss ...string) []Entry {
	t.Helper()
	var out []Entry
	for _, s := range ss {
		e, err := ParseEntry(s)
		if err != nil {
			t.Fatalf("ParseEntry(%q): %v", s, err)
		}
		out = append(out, e)
	}
	return out
}

func TestParseEntryValid(t *testing.T) {
	cases := []struct {
		in       string
		host     string
		port     uint16
		wildcard bool
		ip       bool
	}{
		{"api.example.com:443", "api.example.com", 443, false, false},
		{"example.com:80", "example.com", 80, false, false},
		{"*.example.com:443", "example.com", 443, true, false},
		{"*.s3.amazonaws.com:443", "s3.amazonaws.com", 443, true, false},
		{"xn--bcher-kva.example:443", "xn--bcher-kva.example", 443, false, false},
		{"_acme.example.com:443", "_acme.example.com", 443, false, false},
		{"api.example.com:8443", "api.example.com", 8443, false, false},
		{"198.51.100.7:443", "198.51.100.7", 443, false, true},
		{"sealed-key-broker-xyz.a.run.app:443", "sealed-key-broker-xyz.a.run.app", 443, false, false},
	}
	for _, c := range cases {
		e, err := ParseEntry(c.in)
		if err != nil {
			t.Errorf("ParseEntry(%q): %v", c.in, err)
			continue
		}
		if e.Host != c.host || e.Port != c.port || e.Wildcard != c.wildcard || e.IsIP() != c.ip {
			t.Errorf("ParseEntry(%q) = %+v", c.in, e)
		}
		if e.String() != c.in {
			t.Errorf("String() = %q, want %q", e.String(), c.in)
		}
	}
}

func TestParseEntryInvalid(t *testing.T) {
	for _, in := range []string{
		"example.com",          // no port
		"example.com:",         // empty port
		"example.com:0",        // zero port
		"example.com:65536",    // out of range
		"example.com:0443",     // leading zero
		"example.com:+443",     // sign
		"Example.com:443",      // uppercase
		"example.com.:443",     // trailing dot
		"localhost:443",        // single label
		"*.com:443",            // wildcard over a public suffix
		"*.co.uk:443",          // wildcard over a multi-label public suffix
		"*.localhost:443",      // single-label wildcard base
		"**.example.com:443",   // double star
		"*example.com:443",     // star without dot
		"a.*.example.com:443",  // star inside
		"[2001:db8::1]:443",    // IPv6 literal
		"exa mple.com:443",     // space
		"-bad.example.com:443", // leading hyphen
		"bad-.example.com:443", // trailing hyphen
		"a..example.com:443",   // empty label
		"1.2.3:443",            // numeric last label, not an IP
		"010.1.1.1:443",        // non-canonical IP
		"bücher.example:443",   // unicode, must be punycode
		strings.Repeat("a", 64) + ".example.com:443", // long label
		"",
	} {
		if _, err := ParseEntry(in); err == nil {
			t.Errorf("ParseEntry(%q) succeeded, want error", in)
		}
	}
}

func TestAllowlistMatch(t *testing.T) {
	a := NewAllowlist(mustEntries(t,
		"api.example.com:443",
		"api.example.com:80",
		"*.cdn.example.net:443",
		"198.51.100.7:443",
	))
	cases := []struct {
		host string
		port uint16
		want string // matched entry, "" for no match
	}{
		{"api.example.com", 443, "api.example.com:443"},
		{"api.example.com", 80, "api.example.com:80"},
		{"api.example.com", 8443, ""},                         // port not listed
		{"api.example.com", 22, ""},                           // ssh never implied
		{"www.example.com", 443, ""},                          // sibling
		{"example.com", 443, ""},                              // parent
		{"x.api.example.com", 443, ""},                        // exact does not imply subdomains
		{"img.cdn.example.net", 443, "*.cdn.example.net:443"}, // one label
		{"a.b.cdn.example.net", 443, ""},                      // two labels
		{"cdn.example.net", 443, ""},                          // apex not covered by wildcard
		{"img.cdn.example.net", 80, ""},                       // wildcard port
		{"198.51.100.7", 443, "198.51.100.7:443"},
		{"198.51.100.7", 80, ""},
		{"198.51.100.8", 443, ""},
		{"::ffff:198.51.100.7", 443, "198.51.100.7:443"}, // mapped form is the same IP
		{".cdn.example.net", 443, ""},                    // empty first label
		{"img.cdn.example.net.", 443, ""},                // callers must normalize first
	}
	for _, c := range cases {
		e, ok := a.Match(c.host, c.port)
		got := ""
		if ok {
			got = e.String()
		}
		if got != c.want {
			t.Errorf("Match(%q, %d) = %q, want %q", c.host, c.port, got, c.want)
		}
	}
}

func TestAllowlistMatchName(t *testing.T) {
	a := NewAllowlist(mustEntries(t, "api.example.com:443", "api.example.com:80", "*.cdn.example.net:443", "198.51.100.7:443"))
	cases := map[string]string{
		"api.example.com":           "api.example.com:443", // first entry wins as representative
		"img.cdn.example.net":       "*.cdn.example.net:443",
		"cdn.example.net":           "",
		"a.b.cdn.example.net":       "",
		"random.example.com":        "",
		"198.51.100.7":              "", // IP entries are not names
		"7.100.51.198.in-addr.arpa": "",
	}
	for name, want := range cases {
		e, ok := a.MatchName(name)
		got := ""
		if ok {
			got = e.String()
		}
		if got != want {
			t.Errorf("MatchName(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestNormalizeHostname(t *testing.T) {
	got, err := NormalizeHostname("API.Example.COM.")
	if err != nil || got != "api.example.com" {
		t.Fatalf("NormalizeHostname = %q, %v", got, err)
	}
	for _, bad := range []string{"", ".", "localhost", "a..b", "x\\000.example.com", "1.2.3.4"} {
		if _, err := NormalizeHostname(bad); err == nil {
			t.Errorf("NormalizeHostname(%q) succeeded", bad)
		}
	}
}

func TestBlockedKeyNeverCarriesChosenData(t *testing.T) {
	a := NewAllowlist(mustEntries(t, "api.example.com:443", "api.example.com:8443", "*.cdn.example.net:443", "198.51.100.7:443"))
	cases := []struct {
		host   string
		port   uint16
		want   string
		listed bool
	}{
		{"api.example.com", 443, "api.example.com:443", true},
		{"API.Example.COM.", 443, "api.example.com:443", true},
		{"198.51.100.7", 443, "198.51.100.7:443", true},
		{"x1.cdn.example.net", 443, "*.cdn.example.net:443", true},
		// On the allowlist by name, wrong port: the pattern plus a port token.
		{"api.example.com", 22, "api.example.com:other", false},
		{"api.example.com", 80, "api.example.com:80", false},
		{"x1.cdn.example.net", 8443, "*.cdn.example.net:8443", false},
		// Everything else collapses into the fixed vocabulary.
		{"thisisexfiltrateddata0123456789abcdef.github.io", 443, "unlisted:443", false},
		{"secretpayload42.com", 443, "unlisted:443", false},
		{"a.b.cdn.example.net", 443, "unlisted:443", false},
		{"cdn.example.net", 443, "unlisted:443", false},
		{"x.y.unknowntld", 31337, "unlisted:other", false},
		{"secret.bd", 443, "unlisted:443", false},
		{"203.0.113.9", 443, "ip-public:443", false},
		{"203.0.113.9", 8443, "ip-public:8443", false},
		{"203.0.113.9", 6553, "ip-public:other", false},
		{"::ffff:203.0.113.9", 443, "ip-public:443", false},
		{"[2001:db8::1]", 443, "ip-public:443", false},
		{"169.254.169.254", 80, "ip-metadata:80", false},
		{"127.0.0.1", 443, "ip-loopback:443", false},
		{"10.1.2.3", 443, "ip-private:443", false},
		{"172.30.0.3", 7070, "ip-vm-internal:other", false},
		{"com", 443, "invalid:443", false},
		{"bad host", 443, "invalid:443", false},
	}
	for _, c := range cases {
		got, listed := a.BlockedKey(c.host, c.port)
		if got != c.want || listed != c.listed {
			t.Errorf("BlockedKey(%q, %d) = %q, %v; want %q, %v", c.host, c.port, got, listed, c.want, c.listed)
		}
	}
	var unknown *Allowlist
	if got, listed := unknown.BlockedKey("api.example.com", 8443); got != "unlisted:other" || listed {
		t.Errorf("nil allowlist: %q %v", got, listed)
	}
}

func TestBlockedDNSKey(t *testing.T) {
	a := NewAllowlist(mustEntries(t, "api.example.com:443", "*.cdn.example.net:443"))
	cases := map[string]string{
		"api.example.com.":                "api.example.com:53",
		"x1.cdn.example.net":              "*.cdn.example.net:53",
		"aGVsbG8gd29ybGQ.evil.test":       "unlisted:53",
		"exfil.cdn.example.net.evil.test": "unlisted:53",
		"bad name":                        "invalid:53",
	}
	for name, want := range cases {
		if got, _ := a.BlockedDNSKey(name); got != want {
			t.Errorf("BlockedDNSKey(%q) = %q, want %q", name, got, want)
		}
	}
}
