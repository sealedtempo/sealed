package composer

import (
	"fmt"
	"net/netip"
)

// hostRulesTemplate is the pre_launch_script (INTERFACES section 15). dstack
// runs it on the host after dockerd starts and before docker compose up,
// under "set -euo pipefail". Only the edge subnet and the egress IP vary.
//
// The SEALED-EDGE chain is rebuilt on every boot. It is jumped from the top
// of FORWARD, which holds when Docker programs nftables or no firewall at
// all (a DROP in any base chain is final), and, when Docker's iptables
// backend is active, from DOCKER-USER, which Docker keeps first in FORWARD
// whenever it adds its own ACCEPT rules. The script fails closed: it exits
// non-zero unless the jumps are in place and FORWARD reaches DOCKER-USER.
const hostRulesTemplate = `#!/bin/bash
# Sealed host rules v2 (composer %s). Measured into stackHash.
# Traffic forwarded from the edge network to anything outside it is dropped
# unless it comes from sealed-egress; replies to inbound connections to Caddy
# (ESTABLISHED,RELATED) are allowed. Exits non-zero if the rules are not hooked.
set -euo pipefail
EDGE_SUBNET=%s
EGRESS_IP=%s
iptables -w -N SEALED-EDGE 2>/dev/null || true
iptables -w -F SEALED-EDGE
iptables -w -A SEALED-EDGE -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
iptables -w -A SEALED-EDGE -s "$EGRESS_IP" -j RETURN
iptables -w -A SEALED-EDGE -d "$EDGE_SUBNET" -j RETURN
iptables -w -A SEALED-EDGE -j DROP
iptables -w -C SEALED-EDGE -j DROP
ensure_jump() {
  if ! iptables -w -C "$1" -s "$EDGE_SUBNET" -j SEALED-EDGE 2>/dev/null; then
    iptables -w -I "$1" 1 -s "$EDGE_SUBNET" -j SEALED-EDGE
  fi
  iptables -w -C "$1" -s "$EDGE_SUBNET" -j SEALED-EDGE
}
ensure_jump FORWARD
if iptables -w -n -L DOCKER-USER >/dev/null 2>&1; then
  if ! iptables -w -C FORWARD -j DOCKER-USER 2>/dev/null; then
    echo "sealed host rules: DOCKER-USER exists but FORWARD does not jump to it" >&2
    exit 1
  fi
  ensure_jump DOCKER-USER
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
