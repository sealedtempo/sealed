#!/bin/bash
# Sealed host rules v3 (composer 1.6.0). Measured into stackHash.
# FORWARD: traffic forwarded from the edge network (source subnet or edge
# bridge) to anything outside it is dropped unless it comes from
# sealed-egress; replies to inbound connections to Caddy are allowed.
# INPUT: traffic from the containers (any sealed bridge, or a source in the
# container ranges) to the VM itself is dropped, except replies to
# connections the VM opened. Exits non-zero if the rules are not hooked.
set -euo pipefail
EDGE_SUBNET=172.31.0.0/24
EDGE_BRIDGE=sealed-edge
EGRESS_IP=172.31.0.2
CONTAINER_RANGES="172.30.0.0/16 172.31.0.0/24"
CONTAINER_BRIDGES=sealed-+
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
