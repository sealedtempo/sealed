#!/bin/bash
# Sealed host rules v2 (composer 1.1.1). Measured into stackHash.
# Traffic forwarded from the edge network to anything outside it is dropped
# unless it comes from sealed-egress; replies to inbound connections to Caddy
# (ESTABLISHED,RELATED) are allowed. Exits non-zero if the rules are not hooked.
set -euo pipefail
EDGE_SUBNET=172.31.0.0/24
EGRESS_IP=172.31.0.2
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
