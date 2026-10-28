#!/usr/bin/env bash
# Real-Docker checks of sealed-egress and the per-app network layout
# (D-041, INTERFACES sections 12 and 14, acceptance test A8).
#
# Builds sealed-egress, sealed-init (envexec) and a stand-in app image from
# source for the local platform, composes a two-app fixture stack with the
# real composer, swaps only the VM-specific pieces for stand-ins
# (mkstack.py), starts it with docker compose and probes it from inside the
# containers. Prints PASS, FAIL, WARN or INFO per check and exits 1 when any
# check fails.
#
# usage: scripts/docker-checks/run.sh [--keep] [--no-host-rules] [--skip-stock]
#   --keep           leave the stack running afterwards (docker compose -p sealed-dc ...)
#   --no-host-rules  do not install the composer's pre_launch_script in the Docker VM
#   --skip-stock     do not build the unpatched Dockerfiles first
# env:
#   SRC_REF   git ref for runtime/egress, runtime/envexec and the composer
#             (default ws/int-composer, else HEAD)
#   WORK      scratch directory (default: a new mktemp -d)
#   HOST_PORT port of the 0.0.0.0 listener that stands for dstack's 8090 (default 47090)
#
# Needs: docker with buildx and compose, go, git, jq, python3, internet access
# from the Docker VM (example.com, example.org, 8.8.8.8). The host-rules part
# changes iptables in the Docker VM (a disposable local VM such as colima) and
# removes its rules again at the end.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(git -C "$HERE" rev-parse --show-toplevel)
PROJECT=sealed-dc
HOST_PORT=${HOST_PORT:-47090}
KEEP=0
HOST_RULES=1
STOCK=1
for arg in "$@"; do
  case "$arg" in
    --keep) KEEP=1 ;;
    --no-host-rules) HOST_RULES=0 ;;
    --skip-stock) STOCK=0 ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

if [ -z "${SRC_REF:-}" ]; then
  if git -C "$REPO" rev-parse -q --verify ws/int-composer >/dev/null; then SRC_REF=ws/int-composer; else SRC_REF=HEAD; fi
fi
WORK=${WORK:-$(mktemp -d "${TMPDIR:-/tmp}/sealed-docker-checks.XXXXXX")}
mkdir -p "$WORK"
LOG="$WORK/log"
mkdir -p "$LOG"

N_PASS=0; N_FAIL=0; N_WARN=0
FAILS=""
pass() { N_PASS=$((N_PASS+1)); printf 'PASS  %-6s %s\n' "$1" "$2"; }
fail() { N_FAIL=$((N_FAIL+1)); FAILS="$FAILS $1"; printf 'FAIL  %-6s %s\n' "$1" "$2"; [ -n "${3:-}" ] && printf '        %s\n' "$3"; return 0; }
warn() { N_WARN=$((N_WARN+1)); printf 'WARN  %-6s %s\n' "$1" "$2"; [ -n "${3:-}" ] && printf '        %s\n' "$3"; return 0; }
info() { printf 'INFO  %-6s %s\n' "$1" "$2"; }
section() { printf '\n== %s\n' "$1"; }
die() { echo "FATAL: $*" >&2; teardown; exit 2; }

ctr() { echo "${PROJECT}-$1-1"; }

# probe_in SERVICE ARGS... -> prints the probe's result line
probe_in() {
  local svc=$1; shift
  docker exec "$(ctr "$svc")" /probe "$@" 2>&1 | head -n 1
}

# expect ID SERVICE "word1|word2" DESCRIPTION -- probe args...
expect() {
  local id=$1 svc=$2 want=$3 desc=$4; shift 5
  local out word
  out=$(probe_in "$svc" "$@")
  word=$(printf '%s' "$out" | sed -n 's/^result=\([^ ]*\).*/\1/p')
  if printf '%s' "$word" | grep -Eqx "$want"; then
    pass "$id" "$svc: $desc [$word]"
  else
    fail "$id" "$svc: $desc (want $want)" "probe $* -> ${out:-no output}"
  fi
}

stats() { # prints the stats JSON as read by the agent stand-in (172.30.0.3)
  docker exec "$(ctr sealed-agent)" /probe http -noproxy -body http://172.30.0.2:9100/v1/stats 2>/dev/null | sed 1d
}
stat_count() { # stat_count CALLER allowed|blocked KEY
  stats | jq -r --arg c "$1" --arg v "$2" --arg k "$3" '.callers[$c][$v][$k] // 0'
}

elf_arch() { # elf_arch IMAGE PATH -> amd64|arm64|other
  local cid f="$WORK/elf.bin"
  cid=$(docker create "$1" 2>/dev/null) || { echo none; return; }
  docker cp -q "$cid:$2" "$f" >/dev/null 2>&1
  docker rm -f "$cid" >/dev/null 2>&1
  python3 -I -c 'import sys;b=open(sys.argv[1],"rb").read(20);print({62:"amd64",183:"aarch64"}.get(int.from_bytes(b[18:20],"little"),"other").replace("aarch64","arm64"))' "$f" 2>/dev/null || echo none
}

host_sh() { # run a bash script (stdin) in the Docker VM's host namespaces
  docker run --rm -i --privileged --pid host --network host "$STANDIN" \
    nsenter -t 1 -m -u -n -i -p -- /bin/bash -s
}

RULES_INSTALLED=0
remove_host_rules() {
  [ "$RULES_INSTALLED" = 1 ] || return 0
  host_sh >/dev/null 2>&1 <<'EOF'
for c in FORWARD DOCKER-USER; do
  while iptables -w -D "$c" -s 172.31.0.0/24 -j SEALED-EDGE 2>/dev/null; do :; done
done
while iptables -w -D INPUT -i sealed-+ -j SEALED-INPUT 2>/dev/null; do :; done
for c in SEALED-EDGE SEALED-INPUT; do iptables -w -F "$c" 2>/dev/null; iptables -w -X "$c" 2>/dev/null; done
true
EOF
  RULES_INSTALLED=0
}

teardown() {
  remove_host_rules
  if [ "$KEEP" = 0 ] && [ -f "$WORK/stack/test-compose.json" ]; then
    docker compose -f "$WORK/stack/test-compose.json" -p "$PROJECT" down -v -t 2 >"$LOG/down.log" 2>&1
  fi
}
trap 'teardown; exit 130' INT TERM

wait_healthy() { # wait_healthy SECONDS SERVICE...
  local deadline=$(( $(date +%s) + $1 )); shift
  local s st
  for s in "$@"; do
    while :; do
      st=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$(ctr "$s")" 2>/dev/null)
      case "$st" in healthy|running) break ;; esac
      [ "$(date +%s)" -ge "$deadline" ] && return 1
      sleep 1
    done
  done
}

# ---------------------------------------------------------------------------
section "Setup"
for t in docker git go jq python3; do command -v "$t" >/dev/null || { echo "missing $t" >&2; exit 2; }; done
docker info >/dev/null 2>&1 || { echo "docker daemon not reachable" >&2; exit 2; }
docker buildx version >/dev/null 2>&1 || { echo "docker buildx missing" >&2; exit 2; }
docker compose version >/dev/null 2>&1 || { echo "docker compose missing" >&2; exit 2; }
ARCH=$(docker version -f '{{.Server.Arch}}')
PLATFORM=linux/$ARCH
info setup "repo $REPO, sources from $SRC_REF ($(git -C "$REPO" rev-parse --short "$SRC_REF")), platform $PLATFORM"
info setup "docker $(docker version -f '{{.Server.Version}}'), compose $(docker compose version --short), work dir $WORK"

# A leftover stack from an earlier run would hold the fixed subnets.
if [ -n "$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT")" ] || docker network inspect "${PROJECT}_apps" >/dev/null 2>&1; then
  docker compose -p "$PROJECT" down -v -t 2 >/dev/null 2>&1
  for n in apps edge app-alpha app-bravo; do docker network rm "${PROJECT}_$n" >/dev/null 2>&1; done
fi
for net in $(docker network ls -q); do
  if docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}' "$net" | grep -Eq '172\.(30|31)\.'; then
    die "another Docker network already uses 172.30/16 or 172.31/16: $(docker network inspect -f '{{.Name}}' "$net")"
  fi
done

rm -rf "$WORK/src" "$WORK/ctx"; mkdir -p "$WORK/src" "$WORK/ctx"
git -C "$REPO" archive "$SRC_REF" | tar -x -C "$WORK/src" || die "git archive $SRC_REF failed"
(cd "$WORK/src" && tar -cf - go.mod go.sum runtime/egress runtime/envexec runtime/composer/cjson) | tar -x -C "$WORK/ctx"
(cd "$WORK/src" && GOFLAGS=-mod=readonly go build -o "$WORK/sealed-compose" ./runtime/composer/cmd/sealed-compose) >"$LOG/sealed-compose.log" 2>&1 \
  || die "building sealed-compose failed, see $LOG/sealed-compose.log"
info setup "composer $("$WORK/sealed-compose" version)"

# ---------------------------------------------------------------------------
section "Images (built from source for $PLATFORM)"
build() { # build TAG DOCKERFILE CONTEXT LOGNAME
  docker buildx build --load --platform "$PLATFORM" -f "$2" -t "$1" "$3" >"$LOG/$4.log" 2>&1
}

if [ "$STOCK" = 1 ]; then
  if build sealed-dc/sealed-egress:stock "$WORK/ctx/runtime/egress/Dockerfile" "$WORK/ctx" egress-stock; then
    a=$(elf_arch sealed-dc/sealed-egress:stock /sealed-egress)
    if [ "$a" = "$ARCH" ]; then pass B1 "runtime/egress/Dockerfile builds at $SRC_REF for $PLATFORM"
    else warn B1 "runtime/egress/Dockerfile builds, but the binary is $a in a $PLATFORM image" "ARG TARGETARCH=amd64 overrides BuildKit's platform value"; fi
  else
    fail B1 "runtime/egress/Dockerfile does not build at $SRC_REF" "$(grep -m1 -E 'cannot find|error|ERROR' "$LOG/egress-stock.log")"
  fi
  if build sealed-dc/sealed-init:stock "$WORK/ctx/runtime/envexec/Dockerfile" "$WORK/ctx" init-stock; then
    a=$(elf_arch sealed-dc/sealed-init:stock /envexec)
    if [ "$a" = "$ARCH" ]; then pass B2 "runtime/envexec/Dockerfile builds a $ARCH binary"
    else warn B2 "runtime/envexec/Dockerfile puts a $a binary into a $PLATFORM image" "GOARCH=amd64 is hard-coded (fine for the amd64 VMs, wrong for any other platform)"; fi
  else
    fail B2 "runtime/envexec/Dockerfile does not build at $SRC_REF" "$(grep -m1 -E 'error|ERROR' "$LOG/init-stock.log")"
  fi
fi

# Patched copies: only the known problems are changed, everything else is the
# owners' Dockerfile at SRC_REF.
EGRESS_DF="$WORK/Dockerfile.egress"
sed -e 's/^ARG TARGETARCH=amd64$/ARG TARGETARCH/' -e 's/^ARG TARGETOS=linux$/ARG TARGETOS/' "$WORK/ctx/runtime/egress/Dockerfile" > "$EGRESS_DF"
if ! grep -q 'runtime/composer/cjson' "$EGRESS_DF" && grep -rq 'runtime/composer/cjson' "$WORK/ctx/runtime/egress"; then
  awk '{print} /^COPY runtime\/egress\/ runtime\/egress\/$/ {print "COPY runtime/composer/cjson/ runtime/composer/cjson/"}' "$EGRESS_DF" > "$EGRESS_DF.tmp" && mv "$EGRESS_DF.tmp" "$EGRESS_DF"
  info B3 "patched egress Dockerfile: COPY runtime/composer/cjson/ added, TARGETARCH left to BuildKit"
fi
INIT_DF="$WORK/Dockerfile.init"
awk '{ if ($0 ~ /GOARCH=amd64/) { sub(/GOARCH=amd64/, "GOARCH=$TARGETARCH") } print; if ($0 ~ /^FROM golang/) print "ARG TARGETARCH" }' "$WORK/ctx/runtime/envexec/Dockerfile" > "$INIT_DF"

EGRESS=sealed-dc/sealed-egress:local
INIT=sealed-dc/sealed-init:local
STANDIN=sealed-dc/standin:local
build "$EGRESS" "$EGRESS_DF" "$WORK/ctx" egress || die "patched sealed-egress build failed, see $LOG/egress.log"
build "$INIT" "$INIT_DF" "$WORK/ctx" init || die "patched sealed-init build failed, see $LOG/init.log"
build "$STANDIN" "$HERE/images/standin/Dockerfile" "$HERE/probe" standin || die "stand-in build failed, see $LOG/standin.log"
for pair in "$EGRESS:/sealed-egress" "$INIT:/envexec" "$STANDIN:/probe"; do
  a=$(elf_arch "${pair%%:/*}" "/${pair#*:/}")
  if [ "$a" = "$ARCH" ]; then pass B4 "${pair%%:/*} carries a $ARCH binary"; else fail B4 "${pair%%:/*} carries a $a binary"; fi
done
EGRESS_ID=$(docker image inspect -f '{{.Id}}' "$EGRESS")
info B4 "sealed-egress image $EGRESS_ID"

# ---------------------------------------------------------------------------
section "Composed stack"
rm -rf "$WORK/stack"
# The fixture config follows the composer version at SRC_REF.
jq --arg v "$("$WORK/sealed-compose" version)" '.composerVersion = $v' "$HERE/fixtures/config.json" > "$WORK/config.json"
(cd "$HERE/fixtures" && "$WORK/sealed-compose" compose --config "$WORK/config.json" --app-dir apps/alpha --app-dir apps/bravo \
  --fill-release-ids --out "$WORK/stack") >"$LOG/compose.log" 2>&1 || die "sealed-compose compose failed, see $LOG/compose.log"
info C1 "stackHash $(jq -r .stackHash "$LOG/compose.log" 2>/dev/null || sed -n 's/.*"stackHash": "\(0x[0-9a-f]*\)".*/\1/p' "$LOG/compose.log")"
TC="$WORK/stack/test-compose.json"
mkstack() {
  python3 -I "$HERE/mkstack.py" "$WORK/stack/docker-compose.json" "$TC" \
    --egress "$EGRESS" --init "$INIT" --standin "$STANDIN" --host-port "$HOST_PORT" --project "$PROJECT" "$@" || die "mkstack failed"
}
mkstack
if docker compose -f "$TC" -p "$PROJECT" config --quiet >"$LOG/config.log" 2>&1; then pass C2 "docker compose config accepts the composed stack"; else fail C2 "docker compose config" "$(head -3 "$LOG/config.log")"; fi
if docker compose -f "$TC" -p "$PROJECT" up -d >"$LOG/up.log" 2>&1; then
  pass C3 "docker compose up starts the composed stack as written"
else
  msg=$(grep -m1 -E 'read-only|rootfs|Error|error' "$LOG/up.log")
  fail C3 "docker compose up refuses the composed stack" "$msg"
  ro=$(printf '%s' "$msg" | sed -n 's/.*in read-only service \([a-z0-9-]*\).*/\1/p')
  [ -n "$ro" ] || die "compose up failed, see $LOG/up.log"
  info C3 "workaround for the rest of the run: $ro without read_only (inline configs are copied into the container at create time)"
  docker compose -f "$TC" -p "$PROJECT" down -v -t 2 >/dev/null 2>&1
  mkstack --writable "$ro"
  docker compose -f "$TC" -p "$PROJECT" up -d >"$LOG/up2.log" 2>&1 || die "compose up failed again, see $LOG/up2.log"
fi
if wait_healthy 120 sealed-egress sealed-agent alpha-db bravo-db alpha-web bravo-web caddy dc-spoofer dc-router dc-egress2 dc-hostsvc; then
  pass C4 "stack is up: egress and agent healthy, app services healthy behind the envexec ready gate"
else
  docker compose -f "$TC" -p "$PROJECT" ps -a > "$LOG/ps.log" 2>&1
  die "stack did not become healthy in 120s, see $LOG/ps.log and docker logs"
fi

APPS="alpha-web alpha-db bravo-web bravo-db"
appnet() { case "$1" in alpha-*) echo 1 ;; bravo-*) echo 2 ;; esac; }

# ---------------------------------------------------------------------------
section "Layout (D-041, INTERFACES 14)"
for n in apps app-alpha app-bravo; do
  if [ "$(docker network inspect -f '{{.Internal}}' "${PROJECT}_$n")" = true ]; then pass L1 "network $n is internal"; else fail L1 "network $n is not internal"; fi
done
e=$(docker network inspect -f '{{.Internal}} {{index .Options "com.docker.network.bridge.enable_icc"}}' "${PROJECT}_edge")
if [ "$e" = "false false" ]; then pass L1 "network edge is external with inter-container traffic off"; else fail L1 "network edge: internal/icc = $e"; fi
for s in $APPS sealed-agent caddy; do
  r=$(docker exec "$(ctr "$s")" ip route 2>&1)
  if printf '%s\n' "$r" | grep -q '^default'; then
    if [ "$s" = caddy ]; then info L2 "caddy has a default route via edge (only the host rules stop direct egress)"; else fail L2 "$s has a default route" "$r"; fi
  else
    pass L2 "$s has no default route ($(printf '%s' "$r" | awk '{print $1}' | tr '\n' ' '))"
  fi
done
f=$(docker run --rm --network "container:$(ctr sealed-egress)" "$STANDIN" cat /proc/sys/net/ipv4/ip_forward 2>&1)
if [ "$f" = 0 ]; then pass L3 "sealed-egress does not forward packets (ip_forward=0 in its namespace)"
else warn L3 "sealed-egress has ip_forward=$f in its namespace (inherited from the host)" "an explicit sysctls: {net.ipv4.ip_forward: 0} on sealed-egress would not depend on the bridge rules below"; fi
expect L5 dc-router "timeout|unreachable" "NET_ADMIN control routing via sealed-egress cannot reach 9.9.9.9" -- tcp 9.9.9.9:443
expect L5 dc-router "timeout|unreachable" "NET_ADMIN control routing via sealed-egress cannot reach the edge gateway" -- tcp "172.31.0.1:$HOST_PORT"
bnf=$(echo 'cat /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null || echo absent' | host_sh 2>/dev/null)
info L5 "bridge-nf-call-iptables=$bnf in the Docker VM: Docker's DOCKER-INTERNAL rules then drop bridged packets that leave an internal subnet, which is what stops routing through egress and cross-subnet source spoofing"
for s in $APPS; do
  n=$(appnet "$s")
  rc=$(docker exec "$(ctr "$s")" cat /etc/resolv.conf 2>&1)
  if printf '%s' "$rc" | grep -q '^nameserver 127.0.0.11' && printf '%s' "$rc" | grep -q "ExtServers: \[172.30.$n.2\]"; then
    pass L4 "$s resolv.conf: Docker's embedded DNS forwarding to 172.30.$n.2 only"
  else
    fail L4 "$s resolv.conf" "$(printf '%s' "$rc" | tr '\n' ' ')"
  fi
done

for s in $APPS; do
  v6=$(docker exec "$(ctr "$s")" ip -6 addr 2>&1 | grep inet6 | grep -v '::1/128' | head -1)
  if [ -z "$v6" ]; then pass L6 "$s has no IPv6 address besides ::1"; else fail L6 "$s has IPv6: $v6"; fi
done

# ---------------------------------------------------------------------------
section "A8 from every app container"
for s in $APPS; do
  n=$(appnet "$s")
  case "$s" in alpha-*) own=example.com; other=example.org ;; bravo-*) own=example.org; other=example.com ;; esac
  expect A8.1 "$s" blocked "non-allowlisted host over CONNECT" -- http https://example.net/
  expect A8.1 "$s" blocked "non-allowlisted host over plain HTTP" -- http http://example.net/
  expect A8.1 "$s" blocked "another app's allowlisted host ($other)" -- http "https://$other/"
  expect A8.1 "$s" dns-error "non-allowlisted host without the proxy" -- tcp example.net:443
  expect A8.2 "$s" blocked "raw IP over CONNECT" -- http https://1.1.1.1/
  expect A8.2 "$s" blocked "raw IP over plain HTTP" -- http http://1.1.1.1/
  expect A8.2 "$s" "unreachable|timeout" "raw IP without the proxy" -- tcp 1.1.1.1:443
  expect A8.3 "$s" blocked "metadata server through the proxy" -- http http://169.254.169.254/computeMetadata/v1/
  expect A8.3 "$s" blocked "metadata.google.internal through the proxy" -- http http://metadata.google.internal/computeMetadata/v1/
  expect A8.3 "$s" "unreachable|timeout" "metadata server without the proxy" -- tcp 169.254.169.254:80
  expect A8.4 "$s" nxdomain "random subdomain of an allowed name (embedded DNS)" -- dns "{rand}.$own"
  expect A8.4 "$s" nxdomain "random subdomain, TXT, straight to sealed-egress" -- dns -type TXT -server "172.30.$n.2:53" "{rand}.t.example.net"
  expect A8.4 "$s" "unreachable|timeout" "public resolver 8.8.8.8 directly" -- dns -server 8.8.8.8:53 example.com
  expect A8.5 "$s" ok "allowlisted host over CONNECT ($own)" -- http "https://$own/"
  [ "$own" = example.com ] && expect A8.5 "$s" ok "allowlisted host over plain HTTP" -- http http://example.com/
  expect A8.5 "$s" answer "allowlisted name resolves through sealed-egress directly" -- dns -server "172.30.$n.2:53" "$own"
  expect A8.6 "$s" answer "allowlisted name resolves through Docker's embedded DNS" -- dns "$own"
done

# ---------------------------------------------------------------------------
section "Isolation between apps (D-041)"
expect I1 alpha-web ok "primary reaches the other app's primary on apps (by design)" -- http -noproxy http://bravo:8080/
expect I1 bravo-web ok "primary reaches the other app's primary on apps (by design)" -- http -noproxy http://alpha:8080/
expect I2 alpha-web dns-error "bravo-db does not resolve" -- http -noproxy http://bravo-db:5432/
expect I2 alpha-web "unreachable|timeout" "bravo-db by IP" -- tcp 172.30.2.17:5432
expect I2 alpha-web "unreachable|timeout" "bravo-web's app-network address" -- tcp 172.30.2.16:8080
expect I2 alpha-web "unreachable|timeout" "sealed-egress on app-bravo" -- tcp 172.30.2.2:3128
expect I2 alpha-web blocked "bravo-db by IP through the proxy" -- http -proxy http://172.30.1.2:3128 http://172.30.2.17:5432/
expect I2 alpha-web blocked "bravo-db by name through the proxy" -- http -proxy http://172.30.1.2:3128 http://bravo-db:5432/
expect I2 bravo-web dns-error "alpha-db does not resolve" -- http -noproxy http://alpha-db:5432/
expect I2 bravo-web "unreachable|timeout" "alpha-db by IP" -- tcp 172.30.1.17:5432
expect I3 alpha-db dns-error "non-primary cannot resolve the other app's primary" -- http -noproxy http://bravo:8080/
expect I3 alpha-db "unreachable|timeout" "non-primary cannot reach bravo-web on apps" -- tcp 172.30.0.17:8080
expect I3 alpha-db "unreachable|timeout" "non-primary cannot reach caddy" -- tcp 172.30.0.4:8081
expect I3 bravo-db "unreachable|timeout" "non-primary cannot reach alpha-db" -- tcp 172.30.1.17:5432
expect I4 alpha-db ok "same-app service reachable" -- http -noproxy http://alpha-web:8080/
expect I4 alpha-db ok "sealed-agent reachable on the app network" -- http -noproxy http://sealed-agent:7070/v1/ready
expect I4 bravo-db ok "sealed-agent reachable on the app network" -- http -noproxy http://sealed-agent:7070/v1/ready

# ---------------------------------------------------------------------------
section "Embedded DNS on internal networks"
expect D1 alpha-db answer "own service name" -- dns alpha-web
expect D1 alpha-db answer "sealed-egress name" -- dns sealed-egress
expect D1 alpha-web answer "other primary's alias on apps" -- dns bravo
expect D1 alpha-db nxdomain "other app's service name" -- dns bravo-db
b0=$(stat_count alpha-db blocked unlisted:53)
probe_in alpha-db dns "{rand}.example.net" >/dev/null
probe_in alpha-db dns "{rand}.example.net" >/dev/null
b1=$(stat_count alpha-db blocked unlisted:53)
u=$(stats | jq -r '.callers["(unknown)"].blocked["unlisted:53"] // 0')
if [ $((b1 - b0)) -ge 2 ]; then
  pass D2 "embedded DNS forwards from the container's own address: lookups count for caller alpha-db ($b0 -> $b1)"
else
  fail D2 "lookups through 127.0.0.11 did not count for caller alpha-db ($b0 -> $b1, unknown source $u)"
fi

# ---------------------------------------------------------------------------
section "Source address spoofing (NET_RAW dropped)"
for s in $APPS; do
  n=$(appnet "$s")
  expect S1 "$s" denied "raw and packet sockets" -- rawsock
  expect S1 "$s" denied "IP_TRANSPARENT" -- transparent
  expect S1 "$s" denied "IP_FREEBIND send as the agent (172.30.$n.3)" -- freebind-dns "172.30.$n.3" "172.30.$n.2:53" "{rand}.spoof.example.net"
  expect S1 "$s" denied "forged IPv4 header as the agent" -- spoof-dns "172.30.$n.3" "172.30.$n.2:53" "{rand}.spoof.example.net"
  out=$(docker exec "$(ctr "$s")" ip addr add "172.30.$n.99/32" dev lo 2>&1)
  if [ $? -ne 0 ]; then pass S1 "$s: cannot add an address ($(printf '%s' "$out" | head -1))"; else fail S1 "$s: added 172.30.$n.99 to lo"; fi
done
c0=$(stat_count sealed-agent--app-alpha blocked unlisted:53)
expect S2 dc-spoofer allowed "control with Docker's default capabilities opens a raw socket" -- rawsock
expect S2 dc-spoofer sent "control forges a DNS query from 172.30.1.3" -- spoof-dns 172.30.1.3 172.30.1.2:53 "{rand}.spoof.example.net"
sleep 1
c1=$(stat_count sealed-agent--app-alpha blocked unlisted:53)
if [ $((c1 - c0)) -ge 1 ]; then
  pass S2 "the forged query counts for sealed-agent--app-alpha ($c0 -> $c1): without the NET_RAW drop, source IPs are spoofable"
else
  warn S2 "the forged query did not show up for sealed-agent--app-alpha ($c0 -> $c1)"
fi
a0=$(stat_count sealed-agent blocked unlisted:53)
probe_in dc-spoofer spoof-dns 172.30.0.3 172.30.1.2:53 "{rand}.spoof.example.net" >/dev/null
sleep 1
a1=$(stat_count sealed-agent blocked unlisted:53)
if [ "$a1" = "$a0" ]; then
  pass S3 "a source outside the app subnet (172.30.0.3, the agent's apps address) forged on app-alpha never reaches egress ($a0 -> $a1)"
else
  warn S3 "forged 172.30.0.3 arriving on app-alpha counted for sealed-agent ($a0 -> $a1)"
fi

# ---------------------------------------------------------------------------
section "Stats (/v1/stats readable by sealed-agent only)"
ST="$WORK/stats.json"
out=$(docker exec "$(ctr sealed-agent)" /probe http -noproxy -body http://172.30.0.2:9100/v1/stats 2>&1)
printf '%s\n' "$out" | sed 1d > "$ST"
if printf '%s' "$out" | head -1 | grep -q '^result=ok status=200' && jq -e . "$ST" >/dev/null 2>&1; then
  pass T1 "sealed-agent (172.30.0.3) reads /v1/stats"
else
  fail T1 "sealed-agent cannot read /v1/stats" "$(printf '%s' "$out" | head -1)"
fi
for k in unlisted:443 unlisted:80 ip-public:443 ip-public:80 ip-metadata:80 unlisted:53; do
  v=$(jq -r --arg k "$k" '.blocked[$k] // 0' "$ST")
  if [ "$v" -gt 0 ]; then pass T2 "blocked[$k] = $v"; else fail T2 "blocked[$k] missing"; fi
done
for k in example.com:443 example.com:80 example.org:443; do
  v=$(jq -r --arg k "$k" '.allowed[$k] // 0' "$ST")
  if [ "$v" -gt 0 ]; then pass T3 "allowed[$k] = $v"; else fail T3 "allowed[$k] missing"; fi
done
for s in $APPS; do
  case "$s" in alpha-*) own=example.com:443 ;; bravo-*) own=example.org:443 ;; esac
  al=$(jq -r --arg c "$s" --arg k "$own" '.callers[$c].allowed[$k] // 0' "$ST")
  bl=$(jq -r --arg c "$s" '[.callers[$c].blocked // {} | .[]] | add // 0' "$ST")
  if [ "$al" -gt 0 ] && [ "$bl" -gt 0 ]; then pass T4 "per-caller counts for $s: allowed $own=$al, blocked total $bl"; else fail T4 "per-caller counts for $s: allowed=$al blocked=$bl"; fi
done
# Counter keys only (caller names are config values): no name or address a
# container chose may appear unless an allowlist already lists it.
leak=$(jq -r '[.allowed, .blocked, (.callers[] | .allowed, .blocked)] | map(keys) | add | unique | .[]' "$ST" \
  | grep -E 'example\.net|spoof|1\.1\.1\.1|9\.9\.9\.9|169\.254|bravo|alpha|metadata\.google|172\.3[01]\.|[0-9a-f]{12}' | sort -u | tr '\n' ' ')
if [ -z "$leak" ]; then pass T5 "no client-chosen names or addresses in the counts (P5)"; else fail T5 "client-chosen strings in /v1/stats: $leak"; fi
info T5 "stats keys: blocked $(jq -c '.blocked | keys' "$ST"), allowed $(jq -c '.allowed | keys' "$ST")"
k=$(jq -r '.callers["alpha-web"].blocked | keys[] | select(startswith("ip-private") or startswith("ip-vm-internal"))' "$ST" | tr '\n' ' ')
case "$k" in
  *ip-vm-internal*) pass T7 "an app network address through the proxy counts as ip-vm-internal ($k)" ;;
  *ip-private*) warn T7 "an app network address (bravo-db 172.30.2.17) through the proxy counts as $k, not ip-vm-internal" "policy.VMInternalPrefixes lists only 172.30.0.0/24 and 172.31.0.0/24; the D-041 app networks 172.30.1-16.0/24 are denied only as the egress container's own interface networks" ;;
  *) fail T7 "no ip-private or ip-vm-internal count for alpha-web's proxy request to bravo-db" ;;
esac
expect T6 sealed-agent "status|error" "agent's app-network address 172.30.1.3 is not a stats reader" -- http -noproxy http://172.30.1.2:9100/v1/stats
expect T6 alpha-web "status|error" "app primary on apps" -- http -noproxy http://172.30.0.2:9100/v1/stats
expect T6 alpha-web "status|error" "app primary on its app network" -- http -noproxy http://172.30.1.2:9100/v1/stats
expect T6 alpha-db "status|error" "non-primary" -- http -noproxy http://172.30.1.2:9100/v1/stats
expect T6 bravo-db "status|error" "non-primary" -- http -noproxy http://172.30.2.2:9100/v1/stats
expect T6 caddy "status|error" "caddy" -- http -noproxy http://172.30.0.2:9100/v1/stats
expect T6 dc-spoofer "status|error" "unknown source" -- http -noproxy http://172.30.1.2:9100/v1/stats

# ---------------------------------------------------------------------------
section "Egress denies its own app networks even when allowedPrivateCidrs covers them"
expect E1 dc-router blocked "dc-egress2 (allowedPrivateCidrs 172.16.0.0/12, allow 172.30.2.17:5432) refuses bravo-db" -- http -proxy http://172.30.1.50:3128 http://172.30.2.17:5432/
expect E1 dc-router blocked "dc-egress2 refuses the app-bravo gateway" -- http -proxy http://172.30.1.50:3128 "http://172.30.2.1:$HOST_PORT/"

# ---------------------------------------------------------------------------
section "Gateways and host listeners (no other route out)"
info H0 "dc-hostsvc listens on 0.0.0.0:$HOST_PORT in the Docker VM, standing in for the dstack guest agent's 0.0.0.0:8090"
for s in $APPS; do
  n=$(appnet "$s")
  expect H1 "$s" "unreachable|timeout" "host listener via its app network gateway 172.30.$n.1" -- tcp "172.30.$n.1:$HOST_PORT"
  info H1 "$s to the Docker VM's sshd at 172.30.$n.1:22: $(probe_in "$s" tcp "172.30.$n.1:22")"
done
expect H1 alpha-web "unreachable|timeout" "host listener via the apps gateway 172.30.0.1" -- tcp "172.30.0.1:$HOST_PORT"
expect H1 sealed-agent "unreachable|timeout" "host listener via the apps gateway 172.30.0.1" -- tcp "172.30.0.1:$HOST_PORT"
expect H1 caddy "unreachable|timeout" "host listener via the edge gateway 172.31.0.1" -- tcp "172.31.0.1:$HOST_PORT"
expect H1 alpha-web blocked "host listener through the proxy" -- http -proxy http://172.30.1.2:3128 "http://172.30.1.1:$HOST_PORT/"
out=$(probe_in caddy tcp 1.1.1.1:443)
info H2 "caddy direct to 1.1.1.1:443 without host rules: $out"

if [ "$HOST_RULES" = 1 ]; then
  if host_sh < "$WORK/stack/pre-launch.sh" >"$LOG/prelaunch1.log" 2>&1; then
    RULES_INSTALLED=1
    pass H3 "pre_launch_script installs in the Docker VM"
    if host_sh < "$WORK/stack/pre-launch.sh" >"$LOG/prelaunch2.log" 2>&1; then pass H3 "pre_launch_script is idempotent (second run exits 0)"; else fail H3 "second run failed" "$(head -2 "$LOG/prelaunch2.log")"; fi
    j=$(echo 'iptables -w -S FORWARD | grep -c SEALED-EDGE; iptables -w -S DOCKER-USER 2>/dev/null | grep -c SEALED-EDGE' | host_sh 2>/dev/null | tr '\n' ' ')
    if [ "$j" = "1 1 " ]; then pass H3 "one jump each from FORWARD and DOCKER-USER"; else fail H3 "jump counts FORWARD/DOCKER-USER: $j"; fi
    expect H4 caddy "unreachable|timeout" "with host rules, caddy cannot leave the VM directly" -- tcp 1.1.1.1:443
    expect H4 alpha-web ok "with host rules, egress still reaches an allowlisted host" -- http https://example.com/
    expect H4 caddy blocked "caddy through the proxy to a non-ACME host" -- http https://example.com/
    expect H4 caddy "unreachable|timeout" "with host rules, caddy to the host listener on 172.31.0.1" -- tcp "172.31.0.1:$HOST_PORT"
    # Proposed addition to the host rules: drop new connections from the
    # container bridges to the VM itself (INPUT), which FORWARD rules never see.
    if host_sh >"$LOG/input-rule.log" 2>&1 <<'EOF'
iptables -w -N SEALED-INPUT 2>/dev/null || true
iptables -w -F SEALED-INPUT
iptables -w -A SEALED-INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
iptables -w -A SEALED-INPUT -j DROP
iptables -w -C INPUT -i sealed-+ -j SEALED-INPUT 2>/dev/null || iptables -w -I INPUT 1 -i sealed-+ -j SEALED-INPUT
EOF
    then
      info H5 "proposed rule installed: iptables -I INPUT -i sealed-+ -j SEALED-INPUT (ESTABLISHED,RELATED return, else DROP)"
      for s in alpha-web alpha-db bravo-db; do
        n=$(appnet "$s")
        expect H5 "$s" "unreachable|timeout" "with the proposed INPUT rule, host listener via 172.30.$n.1" -- tcp "172.30.$n.1:$HOST_PORT"
      done
      expect H5 caddy "unreachable|timeout" "with the proposed INPUT rule, host listener via 172.31.0.1" -- tcp "172.31.0.1:$HOST_PORT"
      expect H5 alpha-web ok "with the proposed INPUT rule, the proxy still works" -- http https://example.com/
      expect H5 alpha-db answer "with the proposed INPUT rule, DNS still works" -- dns example.com
    else
      fail H5 "could not install the proposed INPUT rule" "$(head -2 "$LOG/input-rule.log")"
    fi
  else
    fail H3 "pre_launch_script failed in the Docker VM" "$(head -3 "$LOG/prelaunch1.log")"
  fi
else
  info H3 "host rules skipped (--no-host-rules)"
fi

# ---------------------------------------------------------------------------
section "Fail closed when sealed-egress is down (last: a restart resets the counts)"
docker stop -t 2 "$(ctr sealed-egress)" >/dev/null
expect D3 alpha-db "servfail|refused|timeout|nxdomain" "with sealed-egress stopped, an allowed name does not resolve (no fallback)" -- dns example.com
expect D3 alpha-db "unreachable|timeout|error|status" "with sealed-egress stopped, nothing gets out" -- http https://example.com/
docker start "$(ctr sealed-egress)" >/dev/null
wait_healthy 60 sealed-egress || die "sealed-egress did not come back"
expect D3 alpha-db answer "after restart, resolution works again" -- dns example.com

# ---------------------------------------------------------------------------
docker logs "$(ctr sealed-egress)" > "$LOG/sealed-egress.log" 2>&1
teardown
printf '\n== Summary: %d PASS, %d FAIL, %d WARN (logs in %s)\n' "$N_PASS" "$N_FAIL" "$N_WARN" "$LOG"
[ "$N_FAIL" = 0 ] || { printf 'failed:%s\n' "$FAILS"; exit 1; }
