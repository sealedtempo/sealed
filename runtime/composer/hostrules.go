package composer

import (
	"fmt"
	"net/netip"
	"strings"
)

// hostRulesTemplate is the pre_launch_script (INTERFACES section 15). dstack
// runs it on the host after dockerd starts and before docker compose up,
// under "set -euo pipefail". Only the edge subnet, the egress IP, the edge
// bridge, the container ranges and the bridge pattern vary.
//
// SEALED-EDGE (FORWARD): traffic forwarded from the edge network to
// anything outside it is dropped unless it comes from sealed-egress. It is
// hooked by source subnet and by the edge bridge, so a packet some edge
// member forwards with another source cannot bypass it (review ws-int-agent
// 4). The chain is jumped from the top of FORWARD, which holds when Docker
// programs nftables or no firewall at all (a DROP in any base chain is
// final), and, when Docker's iptables backend is active, from DOCKER-USER,
// which Docker keeps first in FORWARD whenever it adds its own ACCEPT rules.
//
// SEALED-INPUT (INPUT, D-064): traffic from any container to the VM itself
// (a bridge gateway address or any other VM address) is dropped, except
// replies to connections the VM opened. Without it every container reaches
// every 0.0.0.0 listener of the CVM through its bridge gateway, the dstack
// guest agent's 8090 included (docker-checks bug 2, review C-10). The stack
// needs nothing on INPUT: Docker's embedded DNS (127.0.0.11) answers inside
// each container's namespace and forwards to sealed-egress from there,
// published ports arrive through DNAT and FORWARD, and container-to-container
// traffic is bridged. It is hooked by every composer bridge and by every
// container source range.
//
// The script fails closed: it exits non-zero unless every jump is in place
// and FORWARD reaches DOCKER-USER.
const hostRulesTemplate = `#!/bin/bash
# Sealed host rules v3 (composer %s). Measured into stackHash.
# FORWARD: traffic forwarded from the edge network (source subnet or edge
# bridge) to anything outside it is dropped unless it comes from
# sealed-egress; replies to inbound connections to Caddy are allowed.
# INPUT: traffic from the containers (any sealed bridge, or a source in the
# container ranges) to the VM itself is dropped, except replies to
# connections the VM opened. Exits non-zero if the rules are not hooked.
set -euo pipefail
EDGE_SUBNET=%s
EDGE_BRIDGE=%s
EGRESS_IP=%s
CONTAINER_RANGES="%s"
CONTAINER_BRIDGES=%s
ensure_jump() { # ensure_jump CHAIN TARGET MATCH...
  local chain=$1 target=$2
  shift 2
  if ! iptables -w -C "$chain" "$@" -j "$target" 2>/dev/null; then
    iptables -w -I "$chain" 1 "$@" -j "$target"
  fi
  iptables -w -C "$chain" "$@" -j "$target"
}
iptables -w -N SEALED-EDGE 2>/dev/null || true
iptables -w -F SEALED-EDGE
iptables -w -A SEALED-EDGE -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
iptables -w -A SEALED-EDGE -s "$EGRESS_IP" -j RETURN
iptables -w -A SEALED-EDGE -d "$EDGE_SUBNET" -j RETURN
iptables -w -A SEALED-EDGE -j DROP
iptables -w -C SEALED-EDGE -j DROP
iptables -w -N SEALED-INPUT 2>/dev/null || true
iptables -w -F SEALED-INPUT
iptables -w -A SEALED-INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
iptables -w -A SEALED-INPUT -j DROP
iptables -w -C SEALED-INPUT -j DROP
for range in $CONTAINER_RANGES; do
  ensure_jump INPUT SEALED-INPUT -s "$range"
done
ensure_jump INPUT SEALED-INPUT -i "$CONTAINER_BRIDGES"
hook_edge() {
  ensure_jump "$1" SEALED-EDGE -i "$EDGE_BRIDGE"
  ensure_jump "$1" SEALED-EDGE -s "$EDGE_SUBNET"
}
hook_edge FORWARD
if iptables -w -n -L DOCKER-USER >/dev/null 2>&1; then
  if ! iptables -w -C FORWARD -j DOCKER-USER 2>/dev/null; then
    echo "sealed host rules: DOCKER-USER exists but FORWARD does not jump to it" >&2
    exit 1
  fi
  hook_edge DOCKER-USER
fi
`

// HostRulesScript renders the pre_launch_script for an edge subnet and
// egress edge IP. The container ranges are VMRanges.
func HostRulesScript(edgeSubnet, egressIP string) (string, error) {
	p, err := netip.ParsePrefix(edgeSubnet)
	if err != nil || !p.Addr().Is4() || p.Masked() != p {
		return "", fmt.Errorf("host rules: invalid edge subnet %q", edgeSubnet)
	}
	ip, err := netip.ParseAddr(egressIP)
	if err != nil || !p.Contains(ip) {
		return "", fmt.Errorf("host rules: egress IP %q is not in %s", egressIP, edgeSubnet)
	}
	ranges := make([]string, len(VMRanges))
	covered := false
	for i, r := range VMRanges {
		rp, err := netip.ParsePrefix(r)
		if err != nil || !rp.Addr().Is4() || rp.Masked() != rp {
			return "", fmt.Errorf("host rules: invalid container range %q", r)
		}
		covered = covered || rp.Contains(p.Addr())
		ranges[i] = rp.String()
	}
	if !covered {
		return "", fmt.Errorf("host rules: edge subnet %s is not inside the container ranges %v", edgeSubnet, VMRanges)
	}
	return fmt.Sprintf(hostRulesTemplate, Version, p.String(), EdgeBridge, ip.String(), strings.Join(ranges, " "), ContainerBridgePattern), nil
}
