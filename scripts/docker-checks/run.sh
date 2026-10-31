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
# usage: scripts/docker-checks/run.sh [--keep] [--no-host-rules] [--skip-stock] [--openhands]
#   --keep           leave the stack running afterwards (docker compose -p sealed-dc ...)
#   --no-host-rules  do not install the composer's pre_launch_script in the Docker VM
#   --skip-stock     do not build the unpatched Dockerfiles first
#   --openhands      instead of the egress checks, run the coding-agent app's pinned OpenHands
#                    agent-server with its composed services and A6's coding-agent step
#                    (G20, spec 6.5.4; project sealed-dc-oh, pulls about 260 MB)
# env:
#   SRC_REF   git ref for runtime/egress, runtime/envexec, the composer and (--openhands) the
#             coding-agent and llm-gateway apps (default HEAD, the commit this script is checked out at)
#   WORK      scratch directory (default: a new mktemp -d)
#   HOST_PORT port of the 0.0.0.0 listener that stands for dstack's 8090 (default 47090)
#   OH_PLATFORM  --openhands: platform of the agent-server image to run (default the Docker
#             engine's; the VMs run linux/amd64, which an arm64 engine can only emulate)
#   OH_START_S   --openhands: seconds to wait for coding-agent-server to become healthy (default 240)
#
# Needs: docker with buildx and compose, go, git, jq, python3, internet access
# from the Docker VM (example.com, example.org, 8.8.8.8; --openhands: ghcr.io). The
# host-rules part changes iptables in the Docker VM (a disposable local VM such as
# colima) and removes its rules again at the end; --openhands does not touch the VM.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(git -C "$HERE" rev-parse --show-toplevel)
PROJECT=sealed-dc
HOST_PORT=${HOST_PORT:-47090}
KEEP=0
HOST_RULES=1
STOCK=1
MODE=egress
for arg in "$@"; do
  case "$arg" in
    --keep) KEEP=1 ;;
    --no-host-rules) HOST_RULES=0 ;;
    --skip-stock) STOCK=0 ;;
    --openhands) MODE=openhands ;;
    -h|--help) sed -n '2,31p' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done
# The OpenHands case has its own project; both use the composer's fixed subnets and bridge names,
# so only one of them can run at a time.
if [ "$MODE" = openhands ]; then PROJECT=sealed-dc-oh; STOCK=0; HOST_RULES=0; fi

# The checks test the tree they are in. (They used to prefer ws/int-composer while that branch was ahead; since it
# merged, that default built composer 1.2.0 without the D-063 and D-064 fixes.)
SRC_REF=${SRC_REF:-HEAD}
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
  # Every jump host rules v3 adds (runtime/composer TestDockerChecksHostRules runs this against them).
  host_sh >/dev/null 2>&1 <<'EOF'
for c in FORWARD DOCKER-USER; do
  while iptables -w -D "$c" -s 172.31.0.0/24 -j SEALED-EDGE 2>/dev/null; do :; done
  while iptables -w -D "$c" -i sealed-edge -j SEALED-EDGE 2>/dev/null; do :; done
done
while iptables -w -D INPUT -i sealed-+ -j SEALED-INPUT 2>/dev/null; do :; done
for r in 172.30.0.0/16 172.31.0.0/24; do while iptables -w -D INPUT -s "$r" -j SEALED-INPUT 2>/dev/null; do :; done; done
for c in SEALED-EDGE SEALED-INPUT; do iptables -w -F "$c" 2>/dev/null; iptables -w -X "$c" 2>/dev/null; done
true
EOF
  RULES_INSTALLED=0
}

TC=""  # the laptop stack docker compose runs (set once it is written)
teardown() {
  remove_host_rules
  if [ "$KEEP" = 0 ] && [ -n "$TC" ] && [ -f "$TC" ]; then
    docker compose -f "$TC" -p "$PROJECT" down -v -t 2 >"$LOG/down.log" 2>&1
  fi
  if [ "$KEEP" = 0 ] && [ "$MODE" = openhands ]; then
    docker volume rm "$PROJECT-secrets" "$PROJECT-data" >/dev/null 2>&1
  fi
  return 0
}
trap 'teardown; exit 130' INT TERM

finish() {
  teardown
  printf '\n== Summary: %d PASS, %d FAIL, %d WARN (logs in %s)\n' "$N_PASS" "$N_FAIL" "$N_WARN" "$LOG"
  [ "$N_FAIL" = 0 ] || { printf 'failed:%s\n' "$FAILS"; exit 1; }
  exit 0
}

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
  for n in apps edge verifier app-alpha app-bravo app-coding-agent app-llm-gateway; do docker network rm "${PROJECT}_$n" >/dev/null 2>&1; done
fi
if [ "$MODE" = openhands ]; then docker volume rm "$PROJECT-secrets" "$PROJECT-data" >/dev/null 2>&1; fi
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
# --openhands (G20, spec 6.5.4): the coding-agent app's pinned OpenHands agent-server with the
# services the composer writes for it, then A6's coding-agent step against a fake llm-gateway.
# coding-agent is composed together with llm-gateway, as a deployment must be: its LLM_GATEWAY_KEY
# refers to llm-gateway (same_as), and only then does NO_PROXY cover llm-gateway. oh_mkstack keeps
# coding-agent-server and coding-agent-bootstrap as composed (user, capabilities, no-new-privileges,
# networks, fixed IPs, dns, proxy env, tmpfs, healthcheck, envexec, the embedded prepdirs and seed
# scripts) and changes only this:
#   - images: the upstream repository for the same pinned digest (the catalog registry mirror is
#     filled by the release pipeline), the local sealed-egress and sealed-init builds, and the
#     stand-in for sealed-agent and caddy (as mkstack.py does);
#   - the secret and data-disk binds become subpaths of two Docker volumes, which a prep container
#     fills the way sealed-agent fills the host paths (secret files 0444, data directories 0755 owned
#     by each volume's x-sealed-owner), so nothing is written to the Docker VM itself;
#   - llm-gateway-litellm runs fixtures/openhands/fake_gateway.py at its composed addresses; the
#     other llm-gateway services and the relay sidecars (sealed-mpp-payer, sealed-verifierd) are
#     left out;
#   - logging local and short stop grace periods;
#   - dc-a6, a control on the apps network (where Caddy sits), runs the A6 helper.
# Variants change coding-agent-server only: read-only (read_only: true), tmp-exec (exec added to
# its /tmp tmpfs), tmpdir (TMPDIR on the workspace volume) and tmpdir-ro (tmpdir plus read_only).
OH_DIR="$WORK/oh"
OH_START_S=${OH_START_S:-240}
OH_WHY=""

oh_mkstack() { # oh_mkstack VARIANT OUT [PREP]: write the laptop stack for VARIANT (and the prep script)
  python3 -I - "$OH_DIR/stack/docker-compose.json" "$OH_DIR/stack/stack.json" "$2" "$1" "$EGRESS" "$INIT" \
    "$STANDIN" "$OH_IMAGE" "$PROJECT" "$HERE/fixtures/openhands/fake_gateway.py" "$OH_RUN_PLATFORM" "${3:--}" <<'PY'
import json
import os
import shlex
import sys

(inp, info_path, out, variant, egress, init, standin, image, project, fake_path, platform,
 prep_out) = sys.argv[1:13]
SECRETS, DATA = "/run/sealed/secrets/", "/mnt/sealed-data/"
APP = ("coding-agent-server", "coding-agent-bootstrap")
FAKE = "llm-gateway-litellm"
SIDECARS = ("sealed-init", "sealed-egress", "sealed-agent", "caddy")
DROPPED = ("llm-gateway-db", "llm-gateway-keys", "llm-gateway-ollama", "sealed-mpp-payer", "sealed-verifierd")


def fail(msg):
    print("oh_mkstack: " + msg, file=sys.stderr)
    sys.exit(1)


with open(inp) as f:
    d = json.load(f)
with open(info_path) as f:
    info = json.load(f)
d["name"] = project
services = d["services"]
missing = [n for n in APP + (FAKE,) + SIDECARS + DROPPED if n not in services]
extra = sorted(set(services) - set(APP + (FAKE,) + SIDECARS + DROPPED))
if missing or extra:
    fail("composed services changed (missing %s, unexpected %s); update oh_mkstack" % (missing, extra))
for name in DROPPED:
    del services[name]
secrets, data = set(), set()


def subpath(volume, rel, target, read_only):
    m = {"type": "volume", "source": volume, "target": target, "volume": {"nocopy": True, "subpath": rel}}
    if read_only:
        m["read_only"] = True
    return m


def secret_mount(rel, target):
    secrets.add(rel)
    return subpath("dc-secrets", rel, target, True)


def rebind(name, svc):
    mounts = []
    for v in svc.get("volumes", []):
        if v.get("type") != "bind":
            mounts.append(v)
        elif v["source"].startswith(SECRETS) and v.get("read_only"):
            mounts.append(secret_mount(v["source"][len(SECRETS):], v["target"]))
        elif v["source"].startswith(DATA):
            data.add(v["source"][len(DATA):])
            mounts.append(subpath("dc-data", v["source"][len(DATA):], v["target"], v.get("read_only", False)))
        else:
            fail("%s binds %s; only read-only secret files and data-disk directories are expected" % (name, v["source"]))
    svc["volumes"] = mounts


def standin_for(svc, entrypoint):
    svc["image"] = standin
    svc["entrypoint"] = entrypoint
    for k in ("command", "devices", "user", "ports"):
        svc.pop(k, None)
    svc["volumes"] = [v for v in svc.get("volumes", []) if v.get("type") != "bind"]


services["sealed-init"]["image"] = init
services["sealed-egress"]["image"] = egress
standin_for(services["sealed-agent"], ["/bin/sh", "-c", "touch /run/sealed/ready/ok && exec /probe serve :7070"])
standin_for(services["caddy"], ["/probe", "serve", ":8081"])

digest = image.rsplit("@", 1)[1]
for name in APP:
    svc = services[name]
    if not svc["image"].endswith("/openhands-agent-server@" + digest):
        fail("%s runs %s, not openhands-agent-server@%s" % (name, svc["image"], digest))
    svc["image"] = image
    rebind(name, svc)

server = services["coding-agent-server"]
server["stop_grace_period"] = "5s"
if variant in ("read-only", "tmpdir-ro"):
    server["read_only"] = True
if variant == "tmp-exec":
    server["tmpfs"] = [t + ",exec" if t.startswith("/tmp:") else t for t in server.get("tmpfs", [])]
elif variant in ("tmpdir", "tmpdir-ro"):
    env = server["environment"]
    env["TMPDIR"] = "/workspace/.tmp"
    env["SEALED_OWNED_DIRS"] = env["SEALED_OWNED_DIRS"] + ",/workspace/.tmp"
elif variant not in ("composed", "read-only"):
    fail("unknown variant " + variant)

gw = services[FAKE]
with open(fake_path) as f:
    source = f.read().replace("$", "$$")  # compose interpolates $
gw.pop("command", None)
gw.update({
    "image": image,
    "user": "10002:10002",
    "entrypoint": ["/usr/local/bin/python3", "-I", "-c", source],
    "volumes": [secret_mount(n, SECRETS + n) for n in ("llm-gateway/APP_KEY_CODING_AGENT", "llm-gateway/LITELLM_MASTER_KEY")],
    "healthcheck": {"test": ["CMD", "/usr/local/bin/python3", "-I", "-c",
                             "import sys, urllib.request as u; o = u.build_opener(u.ProxyHandler({})); "
                             "sys.exit(0 if o.open('http://127.0.0.1:4000/health/liveliness', timeout=3).status == 200 else 1)"],
                    "interval": "2s", "timeout": "3s", "retries": 30},
})
gw["environment"] = dict(gw.get("environment", {}),
                         DC_APP_KEY_FILE=SECRETS + "llm-gateway/APP_KEY_CODING_AGENT",
                         DC_MASTER_KEY_FILE=SECRETS + "llm-gateway/LITELLM_MASTER_KEY")

# The A6 helper's seat: on the apps network like Caddy, no proxy, nothing but the two keys an
# operator has (the agent's session key and the gateway master key for the spend-log check).
services["dc-a6"] = {
    "image": image,
    "entrypoint": ["sleep", "infinity"],
    "user": "10009:10009",
    "networks": {"apps": {"ipv4_address": "172.30.0.40"}},
    "cap_drop": ["ALL"],
    "security_opt": ["no-new-privileges:true"],
    "read_only": True,
    "tmpfs": ["/tmp"],
    "volumes": [secret_mount("coding-agent/OH_SESSION_API_KEYS_0", "/run/dc/session-key"),
                secret_mount("llm-gateway/LITELLM_MASTER_KEY", "/run/dc/master-key")],
}

for name, svc in services.items():
    if isinstance(svc.get("depends_on"), dict):
        svc["depends_on"] = {k: v for k, v in svc["depends_on"].items() if k in services}
    svc["logging"] = {"driver": "local"}
    if name not in APP:
        svc["stop_grace_period"] = "2s"
    if platform and svc.get("image") == image:
        svc["platform"] = platform
vols = d.setdefault("volumes", {})
vols["dc-secrets"] = {"external": True, "name": project + "-secrets"}
vols["dc-data"] = {"external": True, "name": project + "-data"}
with open(out, "w") as f:
    json.dump(d, f, indent=1, sort_keys=True)
    f.write("\n")

if prep_out != "-":
    # What sealed-agent does before it opens the ready gate: every mounted secret file (a same_as
    # secret gets the value of the secret it refers to) and every data directory with its owner.
    # The values are made inside the prep container and never leave the volume.
    same, owners = {}, {}
    for app in info["apps"]:
        for sec in app.get("secrets", []):
            if sec.get("sameAs"):
                same[app["id"] + "/" + sec["name"]] = sec["sameAs"]
        for v in app.get("volumes", []):
            owners[v["path"][len(DATA):]] = v.get("owner", "0:0")  # no x-sealed-owner: root, as sealed-agent leaves it
    groups = {}
    for rel in sorted(secrets):
        groups.setdefault(same.get(rel, rel), set()).add(rel)
    lines = ["set -eu", "umask 022", "rnd() { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \\n'; }"]
    for key in sorted(groups):
        lines.append("v=$(rnd)")
        for rel in sorted(groups[key] | {key}):
            q = shlex.quote("/s/" + rel)
            lines.append("mkdir -p %s && printf %%s \"$v\" > %s && chmod 0444 %s" % (
                shlex.quote(os.path.dirname("/s/" + rel)), q, q))
    lines.append("unset v")
    for rel in sorted(data):
        if rel not in owners:
            fail("data directory %s is not among stack.json's volumes" % rel)
        q = shlex.quote("/d/" + rel)
        lines.append("mkdir -p %s && chown %s %s && chmod 0755 %s" % (q, owners[rel], q, q))
    lines.append("echo \"prepared %d secret files and %d data directories\"" % (
        sum(len(g | {k}) for k, g in groups.items()), len(data)))
    with open(prep_out, "w") as f:
        f.write("\n".join(lines) + "\n")
PY
}

oh_state() { # oh_state SERVICE -> "status exit-code restarts health"
  docker inspect -f '{{.State.Status}} {{.State.ExitCode}} {{.RestartCount}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' \
    "$(ctr "$1")" 2>/dev/null || echo "missing - - -"
}

oh_wait() { # oh_wait SECONDS SERVICE...: healthy (or running without a healthcheck); fails on a restart or exit
  local deadline=$(( $(date +%s) + $1 )); shift
  local s st ex rc hl
  for s in "$@"; do
    while :; do
      read -r st ex rc hl <<<"$(oh_state "$s")"
      case "$st/$hl" in running/healthy|running/none) break ;; esac
      case "$st" in exited|dead) return 1 ;; esac
      [ "$rc" = 0 ] || [ "$rc" = - ] || return 1
      [ "$(date +%s)" -ge "$deadline" ] && return 1
      sleep 1
    done
  done
}

oh_start() { # oh_start VARIANT: (re)create coding-agent-server from that variant's stack, wait until healthy
  TC="$OH_DIR/$1.json"
  OH_WHY=""
  if ! docker compose -f "$TC" -p "$PROJECT" up -d --no-deps coding-agent-server >"$LOG/oh-up-$1.log" 2>&1; then
    OH_WHY=$(grep -m1 -iE 'error|denied|invalid' "$LOG/oh-up-$1.log")
    return 1
  fi
  oh_wait "$OH_START_S" coding-agent-server && return 0
  docker logs "$(ctr coding-agent-server)" >"$LOG/oh-server-$1.log" 2>&1
  # envexec, prepdirs and the loader print plain lines; the agent-server logs JSON.
  OH_WHY="$(oh_state coding-agent-server) (status exit restarts health); $(grep -v '^{' "$LOG/oh-server-$1.log" | grep -m1 -iE 'error|denied|failed|refus' || tail -n 1 "$LOG/oh-server-$1.log" | cut -c1-300)"
  return 1
}

oh_bootstrap() { # oh_bootstrap ID: rerun the bootstrap job against the running server; exit 0 and the done file
  local id=$1 st ex rc hl deadline done_json
  docker compose -f "$TC" -p "$PROJECT" up -d --no-deps --force-recreate coding-agent-bootstrap >"$LOG/oh-boot.log" 2>&1 \
    || { fail "$id" "coding-agent-bootstrap does not start" "$(grep -m1 -i error "$LOG/oh-boot.log")"; return 1; }
  deadline=$(( $(date +%s) + 180 ))
  while :; do
    read -r st ex rc hl <<<"$(oh_state coding-agent-bootstrap)"
    [ "$st" = exited ] && [ "$ex" = 0 ] && break
    if [ "$rc" != 0 ] || [ "$(date +%s)" -ge "$deadline" ]; then
      fail "$id" "coding-agent-bootstrap did not finish ($st, exit $ex, $rc restarts)" "$(docker logs --tail 2 "$(ctr coding-agent-bootstrap)" 2>&1 | tr '\n' ' ')"
      return 1
    fi
    sleep 1
  done
  done_json=$(docker run --rm --network none -v "$PROJECT-data:/d:ro" "$STANDIN" cat "/d/$OH_DONE" 2>&1)
  if printf '%s' "$done_json" | jq -e '.model == "litellm_proxy/relay/default" and .base_url == "http://llm-gateway:4000"' >/dev/null 2>&1; then
    pass "$id" "coding-agent-bootstrap (uid 10003, read_only) seeded the agent's LLM settings and wrote its done file $(printf '%s' "$done_json" | jq -c '{model, base_url}')"
  else
    fail "$id" "coding-agent-bootstrap exited 0 but its done file is wrong" "$(printf '%s' "$done_json" | head -c 200)"
  fi
}

# What the running server's processes get, read inside the container (docker exec runs as the
# container's user). Proxy variables are the only environment values printed: envexec exports the
# app's secrets into the same environment.
read -r -d '' OH_PROC_PY <<'PY'
import json, os, shutil
procs = []
for pid in os.listdir("/proc"):
    if not pid.isdigit():
        continue
    try:
        with open("/proc/%s/status" % pid) as f:
            st = dict(l.split(":\t", 1) for l in f.read().splitlines() if ":\t" in l)
        with open("/proc/%s/cmdline" % pid, "rb") as f:
            cmd = f.read().split(b"\0")[0].decode("utf-8", "replace")
    except OSError:
        continue
    procs.append({"cmd": os.path.basename(cmd), "uid": st["Uid"].split(), "gid": st["Gid"].split(),
                  "capeff": st["CapEff"].strip(), "capprm": st["CapPrm"].strip(), "capbnd": st["CapBnd"].strip(),
                  "nnp": st.get("NoNewPrivs", "").strip(), "seccomp": st.get("Seccomp", "").strip()})
with open("/proc/1/environ", "rb") as f:
    env = dict(e.split("=", 1) for e in f.read().decode("utf-8", "replace").split("\0") if "=" in e)
with open("/proc/mounts") as f:
    mounts = {l.split()[1]: l.split()[3] for l in f}
with open("/proc/net/route") as f:
    routes = [l.split()[1] for l in f.read().splitlines()[1:] if l.split()]
with open("/etc/resolv.conf") as f:
    resolv = f.read()
print(json.dumps({
    "procs": procs,
    "proxy": {k: env.get(k, "") for k in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY")},
    "root": mounts.get("/", ""), "tmp": mounts.get("/tmp", ""),
    "default_route": "00000000" in routes,
    "resolv": " ".join(resolv.split()),
    "docker_socket": [p for p in ("/var/run/docker.sock", "/run/docker.sock") if os.path.exists(p)],
    "docker_cli": shutil.which("docker") or "",
    "writable": sorted(p for p in ("/", "/etc", "/usr", "/usr/local/bin", "/home/openhands", "/workspace", "/tmp")
                       if os.access(p, os.W_OK)),
}))
PY

oh_lockdown() { # oh_lockdown ID READ_ONLY: the running coding-agent-server, from docker inspect and from inside
  local id=$1 want_ro=$2 c ins p n
  c=$(ctr coding-agent-server)
  ins=$(docker inspect "$c" | jq '.[0]')
  q() { printf '%s' "$ins" | jq -r "$1"; }
  if [ "$(q .Config.User)" = 10001:10001 ]; then pass "$id" "runs as user 10001:10001"; else fail "$id" "user is $(q .Config.User)"; fi
  if [ "$(q '.HostConfig.Privileged')" = false ] && [ "$(q '.HostConfig.CapAdd // [] | length')" = 0 ]; then
    pass "$id" "not privileged, no cap_add"
  else
    fail "$id" "privileged $(q .HostConfig.Privileged), cap_add $(q '.HostConfig.CapAdd | tojson')"
  fi
  if [ "$(q '[.HostConfig.CapDrop // [] | .[] | select(test("NET_RAW$"))] | length')" = 1 ]; then
    pass "$id" "cap_drop $(q '.HostConfig.CapDrop | tojson')"
  else
    fail "$id" "NET_RAW is not dropped: $(q '.HostConfig.CapDrop | tojson')"
  fi
  if [ "$(q '.HostConfig.SecurityOpt // [] | index("no-new-privileges:true") != null')" = true ]; then
    pass "$id" "security_opt no-new-privileges"
  else
    fail "$id" "security_opt $(q '.HostConfig.SecurityOpt | tojson')"
  fi
  n=$(q '[.Mounts[] | select((.Source + .Destination) | test("docker\\.sock|dstack\\.sock"))] | length')
  if [ "$n" = 0 ] && [ "$(q '.HostConfig.Devices // [] | length')" = 0 ]; then
    pass "$id" "no Docker or dstack socket and no devices mounted (mounts: $(q '[.Mounts[].Destination] | join(" ")'))"
  else
    fail "$id" "a socket or device is mounted" "$(q '[.Mounts[].Destination] | tojson') devices $(q '.HostConfig.Devices | tojson')"
  fi
  if [ "$(q .HostConfig.PidMode)" != host ] && [ "$(q .HostConfig.IpcMode)" != host ] && [ "$(q .HostConfig.NetworkMode)" != host ]; then
    pass "$id" "own pid, ipc and network namespaces (ipc $(q .HostConfig.IpcMode), network $(q .HostConfig.NetworkMode))"
  else
    fail "$id" "shares a host namespace"
  fi
  if [ "$(q .HostConfig.ReadonlyRootfs)" = "$want_ro" ]; then
    pass "$id" "read_only $want_ro as written"
  else
    fail "$id" "ReadonlyRootfs is $(q .HostConfig.ReadonlyRootfs), want $want_ro"
  fi

  p=$(docker exec "$c" /usr/local/bin/python3 -I -c "$OH_PROC_PY" 2>&1 | tail -n 1)
  if ! printf '%s' "$p" | jq -e .procs >/dev/null 2>&1; then fail "$id" "cannot read /proc inside coding-agent-server" "$p"; return 1; fi
  pq() { printf '%s' "$p" | jq -r "$1"; }
  n=$(pq '.procs | length')
  if [ "$(pq '[.procs[] | select((.uid + .gid) | unique != ["10001"])] | length')" = 0 ]; then
    pass "$id" "all $n processes run as uid and gid 10001 (real, effective, saved, fs): $(pq '[.procs[].cmd] | unique | join(", ")')"
  else
    fail "$id" "a process runs as another user" "$(pq '[.procs[] | select((.uid + .gid) | unique != ["10001"])] | tojson')"
  fi
  if [ "$(pq '[.procs[] | select(.capeff != "0000000000000000" or .capprm != "0000000000000000")] | length')" = 0 ]; then
    pass "$id" "no process holds a capability (CapEff and CapPrm 0)"
  else
    fail "$id" "a process holds capabilities" "$(pq '[.procs[] | {cmd, capeff, capprm}] | tojson')"
  fi
  if [ "$(pq '[.procs[] | select(.nnp != "1" or .seccomp != "2")] | length')" = 0 ]; then
    pass "$id" "every process has no_new_privs and a seccomp filter (Docker's default profile)"
  else
    fail "$id" "no_new_privs or seccomp missing" "$(pq '[.procs[] | {cmd, nnp, seccomp}] | tojson')"
  fi
  if [ "$(pq .default_route)" = false ]; then pass "$id" "no default route"; else fail "$id" "coding-agent-server has a default route"; fi
  if pq .resolv | grep -q "nameserver 127.0.0.11.*ExtServers: \[$OH_EGRESS\]"; then
    pass "$id" "DNS: Docker's embedded DNS forwarding to sealed-egress $OH_EGRESS only"
  else
    fail "$id" "resolv.conf: $(pq .resolv)"
  fi
  if [ "$(pq .proxy.HTTPS_PROXY)" = "http://$OH_EGRESS:3128" ] && [ "$(pq .proxy.HTTP_PROXY)" = "http://$OH_EGRESS:3128" ] \
    && pq .proxy.NO_PROXY | tr ',' '\n' | grep -qx llm-gateway; then
    pass "$id" "HTTP(S)_PROXY http://$OH_EGRESS:3128 (sealed-egress), NO_PROXY covers llm-gateway"
  else
    fail "$id" "proxy environment" "$(pq '.proxy | tojson')"
  fi
  if [ "$(pq '(.docker_socket | length | tostring) + .docker_cli')" = 0 ]; then
    pass "$id" "no Docker socket and no docker CLI inside"
  else
    fail "$id" "Docker reachable inside" "$(pq '{docker_socket, docker_cli} | tojson')"
  fi
  case ",$(pq .root)," in
    *,ro,*) pass "$id" "root filesystem mounted read-only" ;;
    *) if [ "$want_ro" = true ]; then fail "$id" "root filesystem is not read-only ($(pq .root | cut -d, -f1))"
       else warn "$id" "root filesystem is writable ($(pq .root | cut -d, -f1))" "the fragment sets read_only only on coding-agent-bootstrap"; fi ;;
  esac
  info "$id" "writable for uid 10001: $(pq '.writable | join(" ")'); /tmp is $(pq .tmp)"
}

oh_gw_stats() {
  docker exec "$(ctr dc-a6)" /usr/local/bin/python3 -I -c 'import sys, urllib.request as u; sys.stdout.write(u.build_opener(u.ProxyHandler({})).open("http://llm-gateway:4000/dc/stats", timeout=5).read().decode())' 2>/dev/null
}

oh_a6() { # oh_a6 ID: catalog/apps/coding-agent/scripts/a6_coding_agent.py from dc-a6, as A6 runs it
  local id=$1 out res g0 g1 delta
  g0=$(oh_gw_stats); printf '%s' "$g0" | jq -e .chat >/dev/null 2>&1 || g0='{}'
  out=$(docker exec -i "$(ctr dc-a6)" sh -c 'export CODING_AGENT_API_KEY="$(cat /run/dc/session-key)" A6_GATEWAY_MASTER_KEY="$(cat /run/dc/master-key)"; exec /usr/local/bin/python3 -I - "$@"' a6 \
    --url http://coding-agent:8000 --gateway-check-url http://llm-gateway:4000 --timeout 600 --poll 2 \
    < "$WORK/src/catalog/apps/coding-agent/scripts/a6_coding_agent.py" 2>"$LOG/oh-a6-$id.log")
  res=$(printf '%s\n' "$out" | tail -n 1)
  if printf '%s' "$res" | jq -e '.ok == true and .test_exit_code == 0 and .prompt_tokens > 0 and .gateway_tokens > 0' >/dev/null 2>&1; then
    pass "$id" "A6: the agent wrote calc.py and test_calc.py, the test passes when rerun, tokens counted by the agent and the gateway $(printf '%s' "$res" | jq -c '{model, prompt_tokens, gateway_tokens, workdir}')"
  else
    fail "$id" "A6 coding-agent step failed" "$(grep -v '^$' "$LOG/oh-a6-$id.log" | tail -n 2 | tr '\n' ' ' | cut -c1-400)"
    return 1
  fi
  g1=$(oh_gw_stats)
  # Counts since this A6 run started (the fake gateway keeps running across variants).
  delta='{chat: (.chat - ($g0.chat // 0)), models, tools_offered,
          steps: (.steps | with_entries(.value -= ($g0.steps[.key] // 0)) | with_entries(select(.value > 0))),
          unauthorized: ((.unauthorized // {}) | with_entries(.value -= (($g0.unauthorized // {})[.key] // 0)) | with_entries(select(.value > 0)))}'
  g1=$(printf '%s' "$g1" | jq -c --argjson g0 "$g0" "$delta" 2>/dev/null)
  if printf '%s' "$g1" | jq -e '.chat >= 3 and .steps.finish >= 1 and (.unauthorized | keys | map(select(test("chat"))) | length) == 0 and .models == ["relay/default"]' >/dev/null 2>&1; then
    pass "$id" "the agent's LLM calls reached llm-gateway directly with coding-agent's virtual key: $(printf '%s' "$g1" | jq -r '"\(.chat) chat completions, model \(.models | join(" ")), steps \(.steps | to_entries | map("\(.key) \(.value)") | join(", "))"')"
  else
    fail "$id" "fake gateway counts" "$g1"
  fi
  info "$id" "fake gateway: tools offered $(printf '%s' "$g1" | jq -c .tools_offered), requests without the right key $(printf '%s' "$g1" | jq -c .unauthorized)"
}

# Runs as the agent inside coding-agent-server through POST /api/bash/execute_bash_command, the
# path A8's coding-agent driver uses. Prints one JSON line.
read -r -d '' OH_PROBE_PY <<'PY'
import json, os, socket, subprocess, urllib.error, urllib.request
EGRESS = os.environ["HTTP_PROXY"].split("//", 1)[1].split(":", 1)[0]
def http(url, proxy=True, headers=None):
    opener = urllib.request.build_opener() if proxy else urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        return "ok %d" % opener.open(urllib.request.Request(url, headers=headers or {}), timeout=20).status
    except urllib.error.HTTPError as e:
        return ("status %d %s" % (e.code, e.headers.get("X-Sealed-Egress") or "")).strip()
    except Exception as e:
        return "error %s" % str(getattr(e, "reason", e))[:160]
def tcp(host, port):
    try:
        socket.create_connection((host, port), timeout=8).close()
        return "connected"
    except Exception as e:
        return "error %s" % str(e)[:160]
def dns(name):
    try:
        return "answer %s" % socket.getaddrinfo(name, 443)[0][4][0]
    except Exception as e:
        return "error %s" % str(e)[:160]
def git(url):
    try:
        p = subprocess.run(["git", "ls-remote", url], capture_output=True, text=True, timeout=60)
        return "exit %d %s" % (p.returncode, (p.stderr.strip().splitlines() or [""])[-1][:160])
    except Exception as e:
        return "error %s" % str(e)[:160]
print(json.dumps({
    "https_proxy": http("https://example.com/"),
    "http_proxy": http("http://example.com/"),
    "metadata_proxy": http("http://169.254.169.254/computeMetadata/v1/", headers={"Metadata-Flavor": "Google"}),
    "metadata_direct": tcp("169.254.169.254", 80),
    "raw_ip_direct": tcp("1.1.1.1", 443),
    "dns": dns("example.com"),
    "git": git("https://github.com/OpenHands/software-agent-sdk"),
    "gateway": http("http://llm-gateway:4000/health/liveliness"),
    "egress_stats": http("http://%s:9100/v1/stats" % EGRESS, proxy=False),
}))
PY

# Runs in dc-a6: sends OH_PROBE_PY (argv[1]) to the agent's bash API with the session key.
read -r -d '' OH_CLIENT_PY <<'PY'
import base64, json, sys, urllib.request
cmd = "python3 -I -c \"import base64;exec(base64.b64decode('%s'))\"" % base64.b64encode(sys.argv[1].encode()).decode()
with open("/run/dc/session-key") as f:
    key = f.read().strip()
req = urllib.request.Request("http://coding-agent:8000/api/bash/execute_bash_command",
                             data=json.dumps({"command": cmd, "cwd": "/workspace/project", "timeout": 150}).encode(),
                             headers={"Content-Type": "application/json", "X-Session-API-Key": key})
res = json.loads(urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=200).read())
print(json.dumps({"exit_code": res.get("exit_code"), "stdout": (res.get("stdout") or "")[-4000:], "stderr": (res.get("stderr") or "")[-600:]}))
PY

oh_egress() { # oh_egress ID: nothing left the agent on its own; then A8's probes from inside it
  local id=$1 st n out r v b0 b1 k
  st=$(stats)
  n=$(printf '%s' "$st" | jq '[.callers | to_entries[] | select(.key | startswith("coding-agent")) | (.value.allowed // {}, .value.blocked // {}) | .[]] | add // 0')
  if [ "$n" = 0 ]; then
    pass "$id" "no outbound request or lookup by coding-agent-server or coding-agent-bootstrap during start, seeding and the A6 run"
  else
    warn "$id" "coding-agent made $n outbound attempts before the probes" "$(printf '%s' "$st" | jq -c '[.callers | to_entries[] | select(.key | startswith("coding-agent"))] | from_entries')"
  fi
  b0=$(printf '%s' "$st" | jq -c '.callers["coding-agent-server"].blocked // {}')
  out=$(docker exec -i "$(ctr dc-a6)" /usr/local/bin/python3 -I -c "$OH_CLIENT_PY" "$OH_PROBE_PY" 2>&1 | tail -n 1)
  printf '%s\n' "$out" > "$LOG/oh-probe-$id.json"
  # The probe's JSON object; the terminal may add lines or control sequences around it.
  r=$(printf '%s' "$out" | jq -r '.stdout // empty' 2>/dev/null \
    | jq -R -c '(capture("(?<j>[{].*[}])") | .j | fromjson?) // empty | select(type == "object" and has("gateway"))' 2>/dev/null | tail -n 1)
  if [ -z "$r" ]; then
    fail "$id" "the probe through execute_bash_command printed no result" "$(printf '%s' "$out" | cut -c1-300)"
    return 1
  fi
  oh_probe() { # oh_probe KEY REGEX DESCRIPTION
    v=$(printf '%s' "$r" | jq -r --arg k "$1" '.[$k]')
    if printf '%s' "$v" | grep -Eq "$2"; then pass "$id" "agent command: $3 [$v]"; else fail "$id" "agent command: $3" "$1 -> $v"; fi
  }
  oh_probe https_proxy '403' "HTTPS to example.com through the proxy is blocked"
  oh_probe http_proxy '^status 403 blocked' "plain HTTP to example.com through the proxy is blocked"
  oh_probe git '^exit [1-9]' "git ls-remote https://github.com/... fails (git hosts are customer additions)"
  oh_probe metadata_proxy '^status 403 blocked' "the metadata server through the proxy is blocked"
  oh_probe metadata_direct '^error .*([Uu]nreachable|timed out)' "the metadata server without the proxy is unreachable"
  oh_probe raw_ip_direct '^error .*([Uu]nreachable|timed out)' "1.1.1.1:443 without the proxy is unreachable"
  oh_probe dns '^error' "example.com does not resolve (not on coding-agent's allowlist)"
  oh_probe egress_stats '^(status|error)' "sealed-egress /v1/stats is refused to the app"
  oh_probe gateway '^ok 200' "llm-gateway is reached directly (NO_PROXY)"
  b1=$(stats | jq -c '.callers["coding-agent-server"].blocked // {}')
  for k in unlisted:443 unlisted:80 ip-metadata:80 unlisted:53; do
    if [ "$(jq -n --argjson a "$b0" --argjson b "$b1" --arg k "$k" '($b[$k] // 0) > ($a[$k] // 0)')" = true ]; then
      pass "$id" "sealed-egress counted blocked[$k] for caller coding-agent-server ($(jq -n --argjson a "$b0" --arg k "$k" '$a[$k] // 0') -> $(jq -n --argjson b "$b1" --arg k "$k" '$b[$k] // 0'))"
    else
      fail "$id" "no new blocked[$k] count for caller coding-agent-server" "$b0 -> $b1"
    fi
  done
  if [ "$(stats | jq '[.callers | to_entries[] | select(.key | startswith("coding-agent")) | .value.allowed // {} | .[]] | add // 0')" = 0 ]; then
    pass "$id" "sealed-egress allowed nothing for coding-agent (default_allow is empty)"
  else
    fail "$id" "sealed-egress allowed something for coding-agent"
  fi
}

oh_noexec_diag() { # why the one-file binary cannot start on the composed /tmp
  local kind mnt
  kind=$(docker run --rm --network none --platform "$OH_RUN_PLATFORM" --entrypoint /usr/local/bin/python3 "$OH_IMAGE" -I -c \
    'f = open("/usr/local/bin/openhands-agent-server", "rb"); f.seek(-4096, 2); print("PyInstaller one-file" if b"MEI\x0c\x0b\x0a\x0b\x0e" in f.read() else "unknown")' 2>&1)
  mnt=$(docker run --rm --network none --tmpfs "$(jq -r '.services["coding-agent-server"].tmpfs[0]' "$OH_DIR/stack/docker-compose.json")" "$STANDIN" \
    sh -c "grep ' /tmp ' /proc/mounts | cut -d' ' -f4" 2>&1)
  info O4 "/usr/local/bin/openhands-agent-server is a $kind build: at every start it unpacks its shared libraries into a new directory under \$TMPDIR (default /tmp) and loads them from there"
  info O4 "the composed tmpfs $(jq -r '.services["coding-agent-server"].tmpfs[0]' "$OH_DIR/stack/docker-compose.json") is mounted $mnt: Docker mounts a tmpfs noexec unless exec is given, and the composer accepts only size and mode"
}

openhands_case() {
  local man run="" ro_variant="" dc n
  rm -rf "$OH_DIR"; mkdir -p "$OH_DIR"
  section "OpenHands agent-server image (catalog/apps/coding-agent, G20)"
  man="$WORK/src/catalog/apps/coding-agent/manifest.yaml"
  OH_SOURCE=$(sed -n 's/^ *source: \(ghcr\.io\/openhands\/agent-server:[^ ]*\)$/\1/p' "$man")
  OH_DIGEST=$(sed -n 's/^ *digest: \(sha256:[0-9a-f]\{64\}\)$/\1/p' "$man")
  { [ -n "$OH_SOURCE" ] && [ "$(printf '%s\n' "$OH_DIGEST" | grep -c .)" = 1 ]; } || die "cannot read the openhands-agent-server pin from $man"
  OH_IMAGE="${OH_SOURCE%:*}@$OH_DIGEST"
  OH_RUN_PLATFORM=${OH_PLATFORM:-$PLATFORM}
  docker pull --platform "$OH_RUN_PLATFORM" "$OH_IMAGE" >"$LOG/oh-pull.log" 2>&1 || die "docker pull $OH_IMAGE failed, see $LOG/oh-pull.log"
  pass O1 "pulled $OH_IMAGE ($OH_SOURCE) for $OH_RUN_PLATFORM"
  info O1 "the manifest pins platform $(sed -n 's/^ *platform: \(.*\)$/\1/p' "$man" | head -n 1) (the VMs); this run uses the $OH_RUN_PLATFORM image of the same index (OH_PLATFORM=linux/amd64 runs the VMs' one, emulated on arm64)"
  if [ "$OH_RUN_PLATFORM" != "$PLATFORM" ]; then
    # Seen on colima: under qemu-user the emulator maps the guest's libraries itself, so a noexec
    # /tmp does not stop the one-file binary, and jemalloc's QEMU warnings on stderr make
    # POST /api/conversations fail with HTTP 500.
    warn O1 "emulated $OH_RUN_PLATFORM: O4 can pass here and still fail on a VM, and A6 can fail on QEMU-only jemalloc warnings" "judge the lockdown on the engine's own platform"
  fi

  section "Composed: coding-agent with llm-gateway"
  # The catalog apps carry no SBOMs in git (the release pipeline adds them), so --allow-missing-sbom;
  # it changes the bundle hashes, not the services.
  jq --arg v "$("$WORK/sealed-compose" version)" '.composerVersion = $v | .apps[0].releaseId as $z
    | .apps = [{id: "coding-agent", releaseId: $z}, {id: "llm-gateway", releaseId: $z}] | .egressAdditions = {}
    | .endpoints.relay = "https://attest.relay.sealed.example" | .endpoints.relayAttest = "https://attest.relay.sealed.example/attest"
    | .relayOwner = "0x00000000000000000000000000000000000000b1"' "$HERE/fixtures/config.json" > "$OH_DIR/config.json"
  (cd "$WORK/src/catalog/apps" && "$WORK/sealed-compose" compose --allow-missing-sbom --config "$OH_DIR/config.json" \
    --app-dir coding-agent --app-dir llm-gateway --fill-release-ids --out "$OH_DIR/stack") >"$LOG/oh-compose.log" 2>&1 \
    || die "sealed-compose compose failed, see $LOG/oh-compose.log"
  dc="$OH_DIR/stack/docker-compose.json"
  OH_EGRESS=$(jq -r '.apps[] | select(.id == "coding-agent") | .network.egress' "$OH_DIR/stack/stack.json")
  OH_DONE=$(jq -r '.apps[] | select(.id == "coding-agent") | .bootstrap.donePath | ltrimstr("/mnt/sealed-data/")' "$OH_DIR/stack/stack.json")
  info O2 "stackHash $(sed -n 's/.*"stackHash": "\(0x[0-9a-f]*\)".*/\1/p' "$LOG/oh-compose.log")"
  n=$(jq -r '.services["coding-agent-server"].image' "$dc")
  case "$n" in
    */openhands-agent-server@"$OH_DIGEST") pass O2 "composed coding-agent-server image is $n (the release mirror of the pinned digest)" ;;
    *) fail O2 "composed coding-agent-server image is $n, not the pinned digest" ;;
  esac
  info O2 "composed coding-agent-server: $(jq -c '.services["coding-agent-server"] | {user, cap_drop, security_opt, read_only, tmpfs, sysctls}' "$dc")"
  [ "$(jq -r '.services["coding-agent-server"].read_only // false' "$dc")" = true ] \
    || warn O2 "coding-agent-server is composed without read_only (the fragment sets it only on coding-agent-bootstrap)" "the read-only variant below runs it with read_only: true"
  oh_mkstack composed "$OH_DIR/composed.json" "$OH_DIR/prep.sh" || die "oh_mkstack failed"
  for v in read-only tmp-exec tmpdir tmpdir-ro; do oh_mkstack "$v" "$OH_DIR/$v.json" || die "oh_mkstack $v failed"; done
  TC="$OH_DIR/composed.json"
  if docker compose -f "$TC" -p "$PROJECT" config --quiet >"$LOG/oh-config.log" 2>&1; then pass O2 "docker compose config accepts the laptop stack"; else fail O2 "docker compose config" "$(head -3 "$LOG/oh-config.log")"; fi
  if ! docker volume create "$PROJECT-secrets" >/dev/null || ! docker volume create "$PROJECT-data" >/dev/null; then die "docker volume create failed"; fi
  n=$(docker run --rm -i --network none -v "$PROJECT-secrets:/s" -v "$PROJECT-data:/d" "$STANDIN" sh -s < "$OH_DIR/prep.sh" 2>&1) \
    || die "preparing the secret and data volumes failed: $n"
  info O2 "$n (as sealed-agent does before it opens the ready gate)"
  if docker compose -f "$TC" -p "$PROJECT" up -d sealed-egress sealed-agent caddy llm-gateway-litellm dc-a6 >"$LOG/oh-up.log" 2>&1 \
    && oh_wait 120 sealed-egress sealed-agent caddy llm-gateway-litellm dc-a6; then
    pass O3 "sidecars, the fake llm-gateway and dc-a6 are up"
  else
    docker compose -f "$TC" -p "$PROJECT" ps -a >"$LOG/oh-ps.log" 2>&1
    die "the base stack did not come up, see $LOG/oh-up.log and $LOG/oh-ps.log"
  fi

  section "coding-agent-server as composed"
  if oh_start composed; then
    pass O4 "coding-agent-server becomes healthy as composed"
    run=composed; ro_variant=read-only
  else
    fail O4 "coding-agent-server does not start as composed" "$OH_WHY"
    if grep -q 'failed to map segment from shared object' "$LOG/oh-server-composed.log" 2>/dev/null; then
      oh_noexec_diag
      section "One change each (coding-agent-server only)"
      if oh_start tmp-exec; then
        pass O5 "with exec added to its /tmp tmpfs, coding-agent-server becomes healthy (needs the composer to accept exec)"
      else
        fail O5 "with exec on /tmp, coding-agent-server still does not start" "$OH_WHY"
      fi
      if oh_start tmpdir; then
        pass O6 "with TMPDIR=/workspace/.tmp (a fragment-only change; the data disk is mounted nodev,nosuid, not noexec), coding-agent-server becomes healthy"
        info O6 "the unpacked binary takes $(docker exec "$(ctr coding-agent-server)" du -sh /workspace/.tmp 2>/dev/null | cut -f1) under /workspace/.tmp while it runs"
        run=tmpdir; ro_variant=tmpdir-ro
      else
        fail O6 "with TMPDIR on the workspace volume, coding-agent-server still does not start" "$OH_WHY"
      fi
    fi
  fi
  if [ -n "$run" ]; then
    section "Locked down at runtime ($run variant)"
    oh_bootstrap O7
    oh_lockdown O8 "$(jq -r '.services["coding-agent-server"].read_only // false' "$OH_DIR/$run.json")"
    oh_a6 O9
    section "Egress from the agent ($run variant)"
    oh_egress O10
    if [ "$(jq -r '.services["coding-agent-server"].read_only // false' "$OH_DIR/$run.json")" != true ]; then
      section "Read-only root filesystem ($ro_variant variant)"
      if oh_start "$ro_variant"; then
        pass O11 "with read_only: true, coding-agent-server becomes healthy"
        oh_bootstrap O11
        oh_lockdown O11 true
        oh_a6 O11
      else
        fail O11 "with read_only: true, coding-agent-server does not start" "$OH_WHY"
      fi
    fi
  else
    info O4 "coding-agent-server does not run, so the lockdown, A6 and egress checks were not reached"
  fi
  docker logs "$(ctr coding-agent-server)" > "$LOG/oh-server.log" 2>&1
  docker logs "$(ctr llm-gateway-litellm)" > "$LOG/oh-fake-gateway.log" 2>&1
  docker logs "$(ctr sealed-egress)" > "$LOG/sealed-egress.log" 2>&1
}

if [ "$MODE" = openhands ]; then
  openhands_case
  finish
fi

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
# dc-egress2 is not waited for: sealed-egress refuses its config at start (E1).
if wait_healthy 120 sealed-egress sealed-agent alpha-db bravo-db alpha-web bravo-web caddy dc-spoofer dc-router dc-hostsvc; then
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
# dc-egress2's config sets allowedPrivateCidrs 172.16.0.0/12 and allows dc-router bravo-db (172.30.2.17:5432) and the
# app-bravo gateway. Since the vm-internal class (D-064, docker-checks bug 6) sealed-egress refuses such a config when
# it starts, so the VM's own networks are closed before any request: the container exits 2 and names both entries.
# (Requests to them through the stack's egress are counted as ip-vm-internal, T7.)
e2st=$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$(ctr dc-egress2)" 2>&1)
e2log=$(docker logs "$(ctr dc-egress2)" 2>&1)
if [ "$e2st" = "exited 2" ] && printf '%s' "$e2log" | grep -q 'config rejected'; then
  pass E1 "dc-egress2 (allowedPrivateCidrs 172.16.0.0/12) refuses to start with a config that allows its app networks [$e2st]"
else
  fail E1 "dc-egress2 with a config that allows its app networks is $e2st (want exited 2, config rejected)" "$(printf '%s' "$e2log" | tail -n 2)"
fi
for dst in 172.30.2.17 172.30.2.1; do
  if printf '%s' "$e2log" | grep -q "destination $dst is a vm-internal address"; then
    pass E1 "dc-egress2 names $dst as vm-internal, so allowedPrivateCidrs cannot open it"
  else
    fail E1 "dc-egress2 does not refuse $dst as vm-internal" "$(printf '%s' "$e2log" | tail -n 1)"
  fi
done

# ---------------------------------------------------------------------------
section "Gateways and host listeners (no other route out)"
info H0 "dc-hostsvc listens on 0.0.0.0:$HOST_PORT in the Docker VM, standing in for the dstack guest agent's 0.0.0.0:8090"
# Without host rules this is Docker's default (docker-checks bug 6): recorded, not judged. On the VM the composer's
# pre_launch_script installs the host rules before any container starts, so H5 below is what a deployment gets.
for s in $APPS; do
  n=$(appnet "$s")
  info H1 "$s without host rules: host listener via its app network gateway 172.30.$n.1: $(probe_in "$s" tcp "172.30.$n.1:$HOST_PORT")"
done
info H1 "alpha-web without host rules: host listener via the apps gateway 172.30.0.1: $(probe_in alpha-web tcp "172.30.0.1:$HOST_PORT")"
info H1 "caddy without host rules: host listener via the edge gateway 172.31.0.1: $(probe_in caddy tcp "172.31.0.1:$HOST_PORT")"
expect H1 alpha-web blocked "host listener through the proxy" -- http -proxy http://172.30.1.2:3128 "http://172.30.1.1:$HOST_PORT/"
out=$(probe_in caddy tcp 1.1.1.1:443)
info H2 "caddy direct to 1.1.1.1:443 without host rules: $out"

if [ "$HOST_RULES" = 1 ]; then
  if host_sh < "$WORK/stack/pre-launch.sh" >"$LOG/prelaunch1.log" 2>&1; then
    RULES_INSTALLED=1
    pass H3 "pre_launch_script installs in the Docker VM"
    if host_sh < "$WORK/stack/pre-launch.sh" >"$LOG/prelaunch2.log" 2>&1; then pass H3 "pre_launch_script is idempotent (second run exits 0)"; else fail H3 "second run failed" "$(head -2 "$LOG/prelaunch2.log")"; fi
    # Host rules v3 after two runs: FORWARD and DOCKER-USER jump to SEALED-EDGE for the edge bridge and the edge
    # subnet; INPUT jumps to SEALED-INPUT for the two container ranges and the sealed bridges.
    j=$(echo 'iptables -w -S FORWARD | grep -c -- "-j SEALED-EDGE"; iptables -w -S DOCKER-USER 2>/dev/null | grep -c -- "-j SEALED-EDGE"; iptables -w -S INPUT | grep -c -- "-j SEALED-INPUT"' | host_sh 2>/dev/null | tr '\n' ' ')
    if [ "$j" = "2 2 3 " ]; then pass H3 "after two runs, two jumps each from FORWARD and DOCKER-USER and three from INPUT"; else fail H3 "jump counts FORWARD/DOCKER-USER/INPUT: $j (want 2 2 3)"; fi
    expect H4 caddy "unreachable|timeout" "with host rules, caddy cannot leave the VM directly" -- tcp 1.1.1.1:443
    expect H4 alpha-web ok "with host rules, egress still reaches an allowlisted host" -- http https://example.com/
    expect H4 caddy blocked "caddy through the proxy to a non-ACME host" -- http https://example.com/
    # D-064: the composer's SEALED-INPUT chain drops new connections from every container to the VM itself.
    for s in $APPS; do
      n=$(appnet "$s")
      expect H5 "$s" "unreachable|timeout" "with host rules, host listener via its app network gateway 172.30.$n.1" -- tcp "172.30.$n.1:$HOST_PORT"
      expect H5 "$s" "unreachable|timeout" "with host rules, the Docker VM's sshd via 172.30.$n.1" -- tcp "172.30.$n.1:22"
    done
    expect H5 alpha-web "unreachable|timeout" "with host rules, host listener via the apps gateway 172.30.0.1" -- tcp "172.30.0.1:$HOST_PORT"
    expect H5 sealed-agent "unreachable|timeout" "with host rules, host listener via the apps gateway 172.30.0.1" -- tcp "172.30.0.1:$HOST_PORT"
    expect H5 caddy "unreachable|timeout" "with host rules, host listener via the edge gateway 172.31.0.1" -- tcp "172.31.0.1:$HOST_PORT"
    expect H5 alpha-web ok "with host rules, the proxy still works" -- http https://example.com/
    expect H5 alpha-db answer "with host rules, DNS still works" -- dns example.com
  else
    fail H3 "pre_launch_script failed in the Docker VM" "$(head -3 "$LOG/prelaunch1.log")"
  fi
else
  info H3 "host rules skipped (--no-host-rules); H5 not run"
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
finish
