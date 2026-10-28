#!/bin/bash
# Sealed host rules v1 (composer 1.0.0). Measured into stackHash.
# Traffic forwarded from the edge network to anything outside it is dropped
# unless it comes from sealed-egress; replies to inbound connections to Caddy
# (ESTABLISHED,RELATED) are allowed.
set -euo pipefail
EDGE_SUBNET=172.31.0.0/24
EGRESS_IP=172.31.0.2
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
