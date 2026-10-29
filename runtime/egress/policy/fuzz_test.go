package policy

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Fuzz targets for the egress allowlist matcher, the stats key grammar and the
// config parser. Each checks a property against an independent reference
// written here, not just "no panic".

// fuzzEntries parses one allowlist entry per line (or comma) and drops the
// invalid ones, like Validate would refuse them.
func fuzzEntries(list string) []Entry {
	var out []Entry
	for _, s := range strings.FieldsFunc(list, func(r rune) bool { return r == '\n' || r == ',' }) {
		if e, err := ParseEntry(s); err == nil {
			out = append(out, e)
		}
	}
	return out
}

// refAllows is the allowlist rule written out directly: an IP entry allows its
// exact address and port, a host entry its exact (already normalized) name and
// port, and "*.base" a name with exactly one more label than base.
func refAllows(e Entry, host string, port uint16) bool {
	if e.Port != port {
		return false
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return e.IsIP() && e.IP == ip.Unmap().WithZone("")
	}
	if e.IsIP() || ValidateHostname(host) != nil {
		return false
	}
	return refNameAllows(e, host)
}

func refNameAllows(e Entry, name string) bool {
	if e.IsIP() || ValidateHostname(name) != nil {
		return false
	}
	if !e.Wildcard {
		return name == e.Host
	}
	label, ok := strings.CutSuffix(name, "."+e.Host)
	return ok && label != "" && !strings.Contains(label, ".")
}

var ipClassNames = []string{"public", "private", "metadata", "loopback", "link-local", "unspecified", "multicast", "ipv4-embedding", "reserved", "vm-internal"}

// statsVocabulary is every key BlockedKey and BlockedDNSKey may return for an
// allowlist: its entries, its patterns with a port token, and the fixed words.
// Nothing outside it may appear (P5: stats keys leave the VM).
func statsVocabulary(entries []Entry) (all map[string]bool, listed map[string]bool) {
	tokens := []string{"80", "443", PortOther}
	for _, e := range entries {
		tokens = append(tokens, strconv.Itoa(int(e.Port)))
	}
	all, listed = map[string]bool{}, map[string]bool{}
	for _, tok := range tokens {
		all[KeyUnlisted+":"+tok] = true
		all[KeyInvalid+":"+tok] = true
		for _, c := range ipClassNames {
			all["ip-"+c+":"+tok] = true
		}
		for _, e := range entries {
			all[e.HostPattern()+":"+tok] = true
		}
	}
	for _, e := range entries {
		all[e.String()] = true
		listed[e.String()] = true
		all[DNSKey(e)] = true
	}
	all[KeyUnlisted+":53"] = true
	all[KeyInvalid+":53"] = true
	return all, listed
}

func FuzzAllowlist(f *testing.F) {
	entries := "api.example.com:443\n*.wild.example.com:443\nexample.org:80\n198.51.100.7:443\n_acme.example.net:8443"
	for _, host := range []string{
		"api.example.com", "API.EXAMPLE.COM.", "a.wild.example.com", "wild.example.com", "a.b.wild.example.com",
		"198.51.100.7", "::ffff:198.51.100.7", "[198.51.100.7]", "198.51.100.007", "example.org.", "xn--bcher-kva.example",
		"bücher.example", "1.2.3.4.", "_acme.example.net", "api.example.com..", "", ".", "*.wild.example.com",
	} {
		f.Add(entries, host, uint16(443))
		f.Add(entries, host, uint16(80))
	}
	f.Add("*.co.uk:443,a.co.uk:443", "b.co.uk", uint16(443))
	f.Fuzz(func(t *testing.T, list, host string, port uint16) {
		es := fuzzEntries(list)
		for _, e := range es {
			back, err := ParseEntry(e.String())
			if err != nil || back != e {
				t.Fatalf("entry %+v does not round-trip: %+v %v", e, back, err)
			}
		}
		a := NewAllowlist(es)

		e, ok := a.Match(host, port)
		want := slices.ContainsFunc(es, func(x Entry) bool { return refAllows(x, host, port) })
		if ok != want {
			t.Fatalf("Match(%q, %d) = %v, reference %v (entries %v)", host, port, ok, want, es)
		}
		if ok && (!slices.Contains(es, e) || !refAllows(e, host, port)) {
			t.Fatalf("Match(%q, %d) returned %v, which does not allow it", host, port, e)
		}

		ne, nok := a.MatchName(host)
		nwant := slices.ContainsFunc(es, func(x Entry) bool { return refNameAllows(x, host) })
		if nok != nwant {
			t.Fatalf("MatchName(%q) = %v, reference %v (entries %v)", host, nok, nwant, es)
		}
		if nok && (!slices.Contains(es, ne) || !refNameAllows(ne, host)) {
			t.Fatalf("MatchName(%q) returned %v, which does not allow it", host, ne)
		}

		if n, err := NormalizeHostname(host); err == nil {
			if again, err := NormalizeHostname(n); err != nil || again != n {
				t.Fatalf("NormalizeHostname not idempotent: %q -> %q -> %q (%v)", host, n, again, err)
			}
		}

		all, listed := statsVocabulary(es)
		key, isListed := a.BlockedKey(host, port)
		if !all[key] || len(key) > 260 {
			t.Fatalf("BlockedKey(%q, %d) = %q is outside the stats vocabulary of %v", host, port, key, es)
		}
		if isListed != listed[key] {
			t.Fatalf("BlockedKey(%q, %d) = %q listed=%v, want listed=%v", host, port, key, isListed, listed[key])
		}
		if ok && (!isListed || key != e.String()) {
			t.Fatalf("BlockedKey(%q, %d) = %q, but Match allowed it by %v", host, port, key, e)
		}
		dkey, dlisted := a.BlockedDNSKey(host)
		if !all[dkey] || (dlisted != slices.ContainsFunc(es, func(x Entry) bool { return DNSKey(x) == dkey })) {
			t.Fatalf("BlockedDNSKey(%q) = %q (listed %v) is outside the stats vocabulary of %v", host, dkey, dlisted, es)
		}
		var nilList *Allowlist
		if k, l := nilList.BlockedKey(host, port); l || !all[k] {
			t.Fatalf("nil allowlist BlockedKey(%q, %d) = %q, %v", host, port, k, l)
		}
	})
}

// FuzzEgressConfig: Parse never panics; a config it accepts is canonical
// (re-encoding gives the same bytes), validates and compiles, and every
// caller's compiled allowlist allows exactly its listed entries.
func FuzzEgressConfig(f *testing.F) {
	for _, p := range []string{"../../composer/testdata/golden/egress.json"} {
		if b, err := os.ReadFile(p); err == nil {
			f.Add(bytes.TrimRight(b, "\n"))
		}
	}
	cfg := &Config{
		Listen:              &Listen{Proxy: ":3128", DNS: ":53", Stats: ":9090"},
		UpstreamDNS:         []string{"169.254.169.254:53"},
		Callers:             []Caller{{Name: "app", IP: "172.30.0.16", Allow: []string{"api.example.com:443", "*.example.org:443", "198.51.100.7:443"}, ProxyAuth: true}},
		AllowedPrivateCIDRs: []string{"10.8.0.0/16"},
		StatsReaders:        []string{"172.30.0.2"},
	}
	if b, err := EncodeCanonical(cfg); err == nil {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := Parse(data)
		if err != nil {
			return
		}
		canon, err := EncodeCanonical(c)
		if err != nil {
			t.Fatalf("accepted config does not re-encode: %v", err)
		}
		if !bytes.Equal(canon, bytes.TrimSuffix(data, []byte("\n"))) {
			t.Fatalf("accepted config is not its own canonical form:\n in %q\nout %q", data, canon)
		}
		if err := CheckCanonical(canon); err != nil {
			t.Fatalf("CheckCanonical refuses what Parse accepted: %v", err)
		}
		p, err := Compile(c)
		if err != nil {
			t.Fatalf("Compile refuses what Parse accepted: %v", err)
		}
		for _, caller := range c.Callers {
			cp, ok := p.CallerByIP(netip.MustParseAddr(caller.IP))
			if !ok || cp.Name != caller.Name {
				t.Fatalf("caller %q not found by IP", caller.Name)
			}
			for _, s := range caller.Allow {
				e, err := ParseEntry(s)
				if err != nil {
					t.Fatalf("accepted entry %q does not parse: %v", s, err)
				}
				host := e.Host
				if e.Wildcard {
					host = "x." + e.Host
				}
				if _, ok := cp.Allow.Match(host, e.Port); !ok {
					t.Fatalf("caller %q: entry %q does not allow %s:%d", caller.Name, s, host, e.Port)
				}
			}
		}
		// The parsed tree and encoding/json agree on the document.
		var std Config
		if err := json.Unmarshal(canon, &std); err != nil {
			t.Fatalf("encoding/json refuses the canonical config: %v", err)
		}
		again, _ := EncodeCanonical(&std)
		if !bytes.Equal(again, canon) {
			t.Fatalf("encoding/json reads a different config:\n%q\n%q", canon, again)
		}
	})
}
