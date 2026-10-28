package verify

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// nonPublic are the destination ranges a live attestation fetch refuses unless AllowPrivateAddresses is set:
// everything an attacker could use to reach the verifier's own network instead of a customer VM's public address.
var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// isPublicAddr reports whether ip is a globally routable unicast address.
func isPublicAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// refuseNonPublic is a net.Dialer Control hook: it runs on the resolved address of every connection attempt, so DNS
// names that resolve (or rebind) to internal addresses are refused too.
func refuseNonPublic(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("destination %q is not an IP address", host)
	}
	if !isPublicAddr(ip) {
		return fmt.Errorf("destination %s is not a public address (live attestation only fetches public hosts)", ip)
	}
	return nil
}

// hostAllowed matches host against patterns: an exact name or address, or "*.domain" for any name below domain.
// An empty pattern list allows every host.
func hostAllowed(host string, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, p := range patterns {
		p = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(p)), ".")
		if suffix, ok := strings.CutPrefix(p, "*."); ok {
			if strings.HasSuffix(host, "."+suffix) && len(host) > len(suffix)+1 {
				return true
			}
			continue
		}
		if host == p {
			return true
		}
	}
	return false
}

// liveTransport returns an HTTP transport for one /attest fetch of req. Direct connections go only to public
// addresses unless allowPrivate. When HTTPS_PROXY applies (inside a CVM, sealed-egress), the connection goes to
// the configured proxy, which applies its own destination rules (INTERFACES.md section 12).
func liveTransport(req *http.Request, tlsConf *tls.Config, allowPrivate bool) (*http.Transport, error) {
	proxyURL, err := http.ProxyFromEnvironment(req)
	if err != nil {
		return nil, fmt.Errorf("proxy configuration: %w", err)
	}
	proxyAddr := ""
	if proxyURL != nil {
		proxyAddr = hostPort(proxyURL)
	}
	t := &http.Transport{
		Proxy:               http.ProxyURL(proxyURL),
		TLSClientConfig:     tlsConf,
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 10 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := &net.Dialer{Timeout: 10 * time.Second}
			if !allowPrivate && addr != proxyAddr {
				d.Control = refuseNonPublic
			}
			return d.DialContext(ctx, network, addr)
		},
	}
	return t, nil
}

// hostPort is u's host:port with the scheme's default port filled in.
func hostPort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	return net.JoinHostPort(u.Hostname(), port)
}
