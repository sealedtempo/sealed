# scripts/docker-checks

Real-Docker checks of sealed-egress and the per-app network layout (D-041, INTERFACES sections 12 and 14, acceptance test A8). `run.sh` builds the images from source for the local platform, composes a two-app fixture stack with the real composer, starts it with `docker compose` and probes it from inside the containers. Every check prints `PASS`, `FAIL`, `WARN` or `INFO`; the script exits 1 when any check fails.

```sh
colima start --cpu 4 --memory 6 --disk 60 --vm-type vz   # or any local Docker engine
scripts/docker-checks/run.sh                 # under 2 minutes with warm build caches
scripts/docker-checks/run.sh --keep          # leave the stack (project sealed-dc) running
SRC_REF=HEAD scripts/docker-checks/run.sh    # egress, envexec and composer from another ref
```

Needs docker with buildx and compose, go, git, jq, python3, and internet access from the Docker VM to example.com, example.org and 8.8.8.8. The host-rules checks run the composer's `pre_launch_script` in the Docker VM through `nsenter` from a privileged container and remove the rules again at the end, so use a disposable local VM, not a shared host.

| file | purpose |
|---|---|
| `run.sh` | the checks |
| `mkstack.py` | turns the composed `docker-compose.json` into a laptop stack: networks, IPs, dns, proxy env, capabilities and `security_opt` stay as composed; only the VM-specific pieces (agent, Caddy, devices, host binds) become stand-ins; adds the `dc-*` control containers |
| `fixtures/` | two stand-in apps (`alpha`, `bravo`, each a primary and a non-primary service) and the public config |
| `images/standin/Dockerfile` | busybox by digest plus the probe and a CA bundle |
| `probe/` | the probe tool (its own Go module, stdlib only, linux only): `serve`, `http`, `tcp`, `dns`, `rawsock`, `transparent`, `freebind-dns`, `spoof-dns` |

Results and findings: `sealed-platform/docs/notes/docker-checks.md`.
