# scripts/docker-checks

Real-Docker checks of sealed-egress and the per-app network layout (D-041, INTERFACES sections 12 and 14, acceptance test A8). `run.sh` builds the images from source for the local platform, composes a two-app fixture stack with the real composer, starts it with `docker compose` and probes it from inside the containers. Every check prints `PASS`, `FAIL`, `WARN` or `INFO`; the script exits 1 when any check fails.

```sh
colima start --cpu 4 --memory 6 --disk 60 --vm-type vz   # or any local Docker engine
scripts/docker-checks/run.sh                 # under 2 minutes with warm build caches
scripts/docker-checks/run.sh --keep          # leave the stack (project sealed-dc) running
SRC_REF=<ref> scripts/docker-checks/run.sh   # egress, envexec and composer from another ref (default HEAD)
scripts/docker-checks/run.sh --openhands     # the coding-agent lockdown case below instead (project sealed-dc-oh)
```

Needs docker with buildx and compose, go, git, jq, python3, and internet access from the Docker VM to example.com, example.org and 8.8.8.8. The host-rules checks run the composer's `pre_launch_script` in the Docker VM through `nsenter` from a privileged container and remove the rules again at the end, so use a disposable local VM, not a shared host. Both modes use the composer's fixed subnets and bridge names, so run one at a time.

| file | purpose |
|---|---|
| `run.sh` | the checks |
| `mkstack.py` | turns the composed `docker-compose.json` into a laptop stack: networks, IPs, dns, proxy env, capabilities and `security_opt` stay as composed; only the VM-specific pieces (agent, Caddy, devices, host binds) become stand-ins; adds the `dc-*` control containers |
| `fixtures/` | two stand-in apps (`alpha`, `bravo`, each a primary and a non-primary service) and the public config |
| `fixtures/openhands/fake_gateway.py` | `--openhands` only: a scripted LiteLLM-compatible gateway (chat completions with tool calls, model info, spend logs) |
| `images/standin/Dockerfile` | busybox by digest plus the probe and a CA bundle |
| `probe/` | the probe tool (its own Go module, stdlib only, linux only): `serve`, `http`, `tcp`, `dns`, `rawsock`, `transparent`, `freebind-dns`, `spoof-dns` |

## `--openhands`: the coding agent locked down (G20, spec 6.5.4)

Spec 6.5.4 gives OpenHands a time box to run fully locked down, with OpenCode as the fallback. This mode runs the pinned `openhands-agent-server` digest from `catalog/apps/coding-agent/manifest.yaml` with the services the composer writes for it, then A6's coding-agent step. It does not change the Docker VM (no host rules, no host paths) and pulls about 260 MB from ghcr.io.

What it composes: `catalog/apps/coding-agent` together with `catalog/apps/llm-gateway`, as a deployment must be (coding-agent's `LLM_GATEWAY_KEY` refers to llm-gateway's `APP_KEY_CODING_AGENT`, and only then does `NO_PROXY` cover `llm-gateway`). `coding-agent-server` and `coding-agent-bootstrap` keep everything the composer wrote: user, `cap_drop`, `no-new-privileges`, networks, fixed IPs, `dns`, proxy env, tmpfs, healthcheck, the envexec entrypoint with the embedded prepdirs and seed scripts. The differences from a VM:

- images: the upstream repository for the same pinned digest (the catalog registry mirror is filled by the release pipeline), the local sealed-egress and sealed-init builds, and the stand-in for sealed-agent and Caddy;
- the secret-file and data-disk binds become subpaths of two Docker volumes (`sealed-dc-oh-secrets`, `sealed-dc-oh-data`). A prep container fills them as sealed-agent fills the host paths: secret files mode 0444 with random values made inside the container (a `same_as` secret gets the value of the secret it refers to), data directories mode 0755 owned by each volume's `x-sealed-owner`;
- `llm-gateway-litellm` runs `fixtures/openhands/fake_gateway.py` at its composed addresses (alias `llm-gateway` on the apps network). It accepts only coding-agent's virtual key and scripts the model: write `calc.py` and `test_calc.py`, run the test, finish. The other llm-gateway services and the relay sidecars are left out;
- logging `local` and short stop grace periods;
- `dc-a6`, a control on the apps network where Caddy sits, holds the session key and the gateway master key and runs `catalog/apps/coding-agent/scripts/a6_coding_agent.py` as acceptance test A6 does (no gate in front).

Checks:

| id | what |
|---|---|
| O1 | the pinned digest pulls (the engine's platform; `OH_PLATFORM=linux/amd64` runs the VMs' image, emulated on arm64) |
| O2 | the composed image is the release mirror of that digest; the composed settings; `docker compose config` |
| O3 | sidecars, the fake gateway and `dc-a6` come up |
| O4 | `coding-agent-server` becomes healthy as composed; when it does not, the reason |
| O5, O6 | when O4 fails because the one-file binary cannot load its libraries from the noexec `/tmp`: the same stack with `exec` on that tmpfs (O5), and with `TMPDIR=/workspace/.tmp` (O6) |
| O7 | the bootstrap job (uid 10003, read-only) seeds the agent's LLM settings and writes its done file |
| O8 | at runtime: user 10001:10001 for every process, no capabilities, `no_new_privs`, seccomp, no Docker or dstack socket, no devices, no default route, DNS and proxy through sealed-egress, root filesystem state |
| O9 | A6: the agent writes the files and the test passes when rerun, tokens counted by the agent and by the gateway's spend logs, every LLM call made directly to llm-gateway with coding-agent's key |
| O10 | no outbound request from the agent or the bootstrap job during start and A6; then A8's probes as agent commands (`POST /api/bash/execute_bash_command`): HTTPS, HTTP, git and the metadata server through the proxy are blocked, direct connections are unreachable, `example.com` does not resolve, `/v1/stats` is refused, llm-gateway is reached; sealed-egress counts the blocked attempts for caller `coding-agent-server` |
| O11 | the same with `read_only: true` on `coding-agent-server` |

The first run's results and the time box decision: `sealed-platform/docs/notes/conf-c13.md`.

Results and findings: `sealed-platform/docs/notes/docker-checks.md`.
