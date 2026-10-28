package composer

import (
	"fmt"
	"net/netip"
)

// hostRulesTemplate is the pre_launch_script (INTERFACES section 15). dstack
// runs it on the host after dockerd starts and before docker compose up,
// under "set -euo pipefail". Only the edge subnet and the egress IP vary.
// It is idempotent: the SEALED-EDGE chain is rebuilt on every boot and the
// jump from DOCKER-USER is inserted only once.
const hostRulesTemplate = `#!/bin/bash
# Sealed host rules v1 (composer %s). Measured into stackHash.
# Traffic forwarded from the edge network to anything outside it is dropped
# unless it comes from sealed-egress; replies to inbound connections to Caddy
# (ESTABLISHED,RELATED) are allowed.
set -euo pipefail
EDGE_SUBNET=%s
EGRESS_IP=%s
iptables -w -N DOCKER-USER 2>/dev/null || true
iptables -w -N SEALED-EDGE 2>/dev/null || true
iptables -w -F SEALED-EDGE
iptables -w -A SEALED-EDGE -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
iptables -w -A SEALED-EDGE -s "$EGRESS_IP" -j RETURN
iptables -w -A SEALED-EDGE -d "$EDGE_SUBNET" -j RETURN
iptables -w -A SEALED-EDGE -j DROP
if ! iptables -w -C DOCKER-USER -s "$EDGE_SUBNET" -j SEALED-EDGE 2>/dev/null; then
  iptables -w -I DOCKER-USER 1 -s "$EDGE_SUBNET" -j SEALED-EDGE
fi
`

// HostRulesScript renders the pre_launch_script for an edge subnet and
// egress edge IP.
func HostRulesScript(edgeSubnet, egressIP string) (string, error) {
	p, err := netip.ParsePrefix(edgeSubnet)
	if err != nil || !p.Addr().Is4() || p.Masked() != p {
		return "", fmt.Errorf("host rules: invalid edge subnet %q", edgeSubnet)
	}
	ip, err := netip.ParseAddr(egressIP)
	if err != nil || !p.Contains(ip) {
		return "", fmt.Errorf("host rules: egress IP %q is not in %s", egressIP, edgeSubnet)
	}
	return fmt.Sprintf(hostRulesTemplate, Version, p.String(), ip.String()), nil
}
