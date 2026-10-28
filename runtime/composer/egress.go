package composer

import (
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/sealed-dev/sealed/runtime/composer/cjson"
)

// EgressPolicy is a release's egress.yaml (INTERFACES section 7).
type EgressPolicy struct {
	Version                  int      `json:"version"`
	DefaultAllow             []string `json:"default_allow"`
	CustomerAdditionsAllowed bool     `json:"customer_additions_allowed"`
	Notes                    string   `json:"notes,omitempty"`
}

// ParseEgressPolicy parses and validates egress.yaml and returns the policy
// with its egressPolicyHash, sha256(CJSON(parsed document)).
func ParseEgressPolicy(data []byte) (*EgressPolicy, Hash, error) {
	v, err := decodeYAML("egress.yaml", data)
	if err != nil {
		return nil, Hash{}, err
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, Hash{}, fmt.Errorf("egress.yaml: top level must be a mapping")
	}
	for _, k := range []string{"version", "default_allow", "customer_additions_allowed"} {
		if _, ok := obj[k]; !ok {
			return nil, Hash{}, fmt.Errorf("egress.yaml: %s is required", k)
		}
	}
	var p EgressPolicy
	if err := strictDecode(obj, &p); err != nil {
		return nil, Hash{}, fmt.Errorf("egress.yaml: %v", err)
	}
	if p.Version != 1 {
		return nil, Hash{}, fmt.Errorf("egress.yaml: version must be 1")
	}
	if p.DefaultAllow == nil {
		return nil, Hash{}, fmt.Errorf("egress.yaml: default_allow must be a list")
	}
	seen := map[string]bool{}
	for i, e := range p.DefaultAllow {
		if _, err := ParseHostPort(e); err != nil {
			return nil, Hash{}, fmt.Errorf("egress.yaml: default_allow[%d]: %v", i, err)
		}
		if seen[e] {
			return nil, Hash{}, fmt.Errorf("egress.yaml: default_allow[%d]: duplicate %q", i, e)
		}
		seen[e] = true
	}
	canon, err := cjson.Encode(obj)
	if err != nil {
		return nil, Hash{}, fmt.Errorf("egress.yaml: %v", err)
	}
	return &p, SHA256(canon), nil
}

// HostPort is a parsed egress allow entry: exact host, one-label wildcard
// (*.example.com) or IPv4 literal, plus a port.
type HostPort struct {
	Host     string
	Port     int
	Wildcard bool
	IP       bool
}

func (h HostPort) String() string { return h.Host + ":" + strconv.Itoa(h.Port) }

var dnsLabelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ParseHostPort validates an allow entry. Hosts must be lowercase; DNS names
// need at least two labels; wildcards cover exactly one label and need at
// least two labels after "*.".
func ParseHostPort(s string) (HostPort, error) {
	i := strings.LastIndexByte(s, ':')
	if i <= 0 || i == len(s)-1 {
		return HostPort{}, fmt.Errorf("%q must be host:port", s)
	}
	host, portStr := s[:i], s[i+1:]
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != portStr {
		return HostPort{}, fmt.Errorf("%q has an invalid port", s)
	}
	if strings.ContainsAny(host, "[]:") {
		return HostPort{}, fmt.Errorf("%q: IPv6 destinations are not supported", s)
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if !addr.Is4() {
			return HostPort{}, fmt.Errorf("%q: only IPv4 literals are supported", s)
		}
		return HostPort{Host: host, Port: port, IP: true}, nil
	}
	hp := HostPort{Host: host, Port: port}
	name := host
	if strings.HasPrefix(host, "*.") {
		hp.Wildcard = true
		name = host[2:]
	}
	if len(name) > 253 {
		return HostPort{}, fmt.Errorf("%q: host name too long", s)
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return HostPort{}, fmt.Errorf("%q: host must be a fully qualified name with at least two labels", s)
	}
	for _, l := range labels {
		if !dnsLabelRe.MatchString(l) {
			return HostPort{}, fmt.Errorf("%q: invalid host label %q (lowercase letters, digits and hyphens only)", s, l)
		}
	}
	if _, err := strconv.Atoi(labels[len(labels)-1]); err == nil {
		return HostPort{}, fmt.Errorf("%q: numeric top-level label", s)
	}
	return hp, nil
}

// endpointHostPort turns an https or http URL into an allow entry.
func endpointHostPort(field, raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%s: %v", field, err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("%s: %q must be an http or https URL", field, raw)
	}
	if u.User != nil {
		return "", fmt.Errorf("%s: credentials in URLs are not allowed", field)
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	entry := host + ":" + port
	if _, err := ParseHostPort(entry); err != nil {
		return "", fmt.Errorf("%s: %v", field, err)
	}
	return entry, nil
}
