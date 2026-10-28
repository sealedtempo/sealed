# coding-agent

A headless coding agent for your stack: OpenHands agent-server 1.58.2 (`python-minimal` flavor, MIT,
D-023) with the local runtime, so the agent's terminal and file editor run inside its own container
on the apps network. No Docker socket, no VS Code, no browser. Its LLM is `llm-gateway`, so tokens
are metered there and this app is metered per app hour. Spec 6.5.

Requires `llm-gateway` in the same stack.

## Services

| service | role |
|---|---|
| `coding-agent-server` (alias `coding-agent`) | agent-server on port 8000, uid 10001 from the start. `bootstrap/prepdirs.py` creates the workspace directories, checks no_new_privs (so setuid binaries in the image cannot regain root) and execs agent-server. |
| `coding-agent-bootstrap` | manifest bootstrap job (`bootstrap/seed.py`, uid 10003, `restart: on-failure` from the composer), run at every start of the stack: stores `{model, base_url, api_key}` with `PATCH /api/settings` (the key is `LLM_GATEWAY_KEY`), writes `coding-agent-bootstrap/done` (manifest `bootstrap.done_file`; the volume is not mounted into the agent's container, so the agent cannot forge or delete it) and exits. sealed-agent keeps the code route closed (503 `starting`) until the file exists. |

No service starts as root. Both volumes declare `x-sealed-owner` (`coding-agent-workspace` 10001:10001,
`coding-agent-bootstrap` 10003:10003), and sealed-agent creates them with that owner before the ready gate
opens (integration brief item 11). If a volume were not owned by the runtime user,
`prepdirs.py` stops with an error naming it.

Both scripts are embedded verbatim in `compose.fragment.yaml`, so they are part of the measured
stack. Edit `bootstrap/*.py` or `compose.fragment.in.yaml`, then run `python3 tools/build_fragment.py`
(the tests fail if the fragment is stale).

Persistence: everything lives on the `coding-agent-workspace` volume (encrypted data disk):
`/workspace/project` (code), `/workspace/conversations`, `/workspace/bash_events`, and
`/workspace/.openhands` (settings and secrets, encrypted with `OH_SECRET_KEY`).

## LLM wiring

This app never holds the gateway master key. llm-gateway's keys job (`llm-gateway-keys`,
`catalog/apps/llm-gateway/images/litellm/app_keys.yaml`) creates the virtual key with the value of
its secret `APP_KEY_CODING_AGENT`: alias `coding-agent`, models `relay/*` and `local/*` only (never
`byok/*` or `external/*`), type `llm_api`, rpm/tpm/parallel limits. It restores that scope if it
drifts and recreates the key after a gateway database reset. This app's `LLM_GATEWAY_KEY` declares
`same_as: llm-gateway/APP_KEY_CODING_AGENT` (D-043): the composer checks that llm-gateway is in the
stack and declares that secret, `sealed secrets` sets the value once, and the key broker returns it
under this app's name.

agent-server V1 does not read `LLM_BASE_URL`. At every start the bootstrap job seeds the settings
below. It never contacts llm-gateway itself: every service is on the app network `app-coding-agent`,
and only `coding-agent-server`, the primary service, also joins the shared `apps` network where
llm-gateway is (D-041). `same_as` makes the key the value llm-gateway's keys job provisions, and the A6
helper checks the whole path through the gateway.

```json
{"agent_settings_diff": {"llm": {"model": "litellm_proxy/relay/default", "base_url": "http://llm-gateway:4000",
  "api_key": "<LLM_GATEWAY_KEY>", "usage_id": "coding-agent"}}}
```

A `litellm_proxy/` model the customer chose earlier on this gateway is kept; the key is always
re-seeded. Relay-to-local fallback happens in the gateway (`router_settings.fallbacks`:
`relay/default` -> `local/qwen3-4b`), so it works whatever the client sends, for example when the
relay is unfunded, unattested or down. A client starting a conversation sends `agent.llm`; the A6
helper reads the stored settings with `X-Expose-Secrets: plaintext`.

## API

The `code` route (`https://code.<ip-with-dashes>.sslip.io`) sits behind Sealed's gate (Caddy
`forward_auth` to sealed-agent, D-044). Send Basic auth with user `sealed` and the gate password once; the
gate sets the `sealed_gate` cookie (12 hours), and later calls send only the cookie. Until the bootstrap
job is done the gate answers 503 `starting`. Every `/api/*` call also needs
`X-Session-API-Key: <OH_SESSION_API_KEYS_0>`. Swagger UI is at `/docs`, the schema at `/openapi.json`,
readiness at `/ready`.

```sh
jar="$(mktemp)"
curl -s -o /dev/null -c "$jar" -u "sealed:$GATE_PASSWORD" https://code.<ip>.sslip.io/ready   # gate login, once
curl -s -b "$jar" -H "X-Session-API-Key: $KEY" https://code.<ip>.sslip.io/api/settings
```

## Secrets

| name | generate | notes |
|---|---|---|
| `OH_SESSION_API_KEYS_0` | hex32 | API key; also makes agent-server bind 0.0.0.0 |
| `OH_SECRET_KEY` | hex32 | encrypts stored LLM key and secrets; never change it (or set `OH_PREVIOUS_SECRET_KEYS_0`) |
| `LLM_GATEWAY_KEY` | none, `same_as: llm-gateway/APP_KEY_CODING_AGENT` | this app's gateway virtual key, llm-gateway's `APP_KEY_CODING_AGENT` |

Each service gets bind mounts of exactly the secret files it lists (D-042): `coding-agent-server` sees
`OH_SESSION_API_KEYS_0` and `OH_SECRET_KEY`, `coding-agent-bootstrap` sees `LLM_GATEWAY_KEY` and
`OH_SESSION_API_KEYS_0`. The agent's shell runs in `coding-agent-server`, so the gateway key file is not
in its container; the key reaches the agent only through its stored settings, and grants no more than
the agent already has (its own scoped gateway key, rate limited, `relay/*` and `local/*` only).

## Egress

None by default (`egress.yaml`). The gateway is inside the VM. Add git hosts and package registries
(for example `github.com:443`, `pypi.org:443`, `files.pythonhosted.org:443`) as customer egress
additions for `coding-agent`.

## Acceptance test A6

`scripts/a6-coding-agent.sh` (Python standard library only) runs the headless flow through the gate
(with `SEALED_GATE_PASSWORD` it probes the route, sends Basic auth once if the gate asks for it, waits
while the gate answers 503 `starting`, then uses only the `sealed_gate` cookie; a gate that sets no
cookie gets Basic auth on every call): create a conversation that writes `calc.py` and `test_calc.py`
and runs the test, poll until `finished`, then
download `calc.py`, rerun the test through `/api/bash/execute_bash_command`, and check that the
conversation recorded token usage. With `--gateway-admin-key` (the gateway master key, from your
machine only) and `--gateway-check-url`, it also requires llm-gateway's spend logs to show tokens for
this app's key since the run started. That corroboration is mandatory when the conversation's usage
counters have an unknown shape.

```sh
A6_URL=https://code.<ip>.sslip.io CODING_AGENT_API_KEY=... SEALED_GATE_PASSWORD=... \
A6_GATEWAY_MASTER_KEY=... A6_GATEWAY_CHECK_URL=https://gateway.<ip>.sslip.io \
  catalog/apps/coding-agent/scripts/a6-coding-agent.sh
# local model instead of the relay:
catalog/apps/coding-agent/scripts/a6-coding-agent.sh --model litellm_proxy/local/qwen3-4b
```

A 4B local model may not drive tool calls well; run A6 against the relay (docs/notes/openhands.md 10.10).

## OpenCode fallback

`fallback-opencode/` packages OpenCode 1.19.5 (MIT) as a drop-in replacement with the same primary
service and route. It is not part of the default release. To switch:

```sh
catalog/apps/coding-agent/fallback-opencode/switch.sh   # copies its release files and README over this app's
# run the tests, build fallback-opencode/images/opencode, pin the digest in manifest.yaml, open a PR
```

To go back, revert that commit. See `fallback-opencode/README.md`.

## Tests

```sh
tmp/pyenv/bin/python -m unittest discover -s catalog/apps/coding-agent/tests -t catalog/apps/coding-agent/tests
```

`test_seed.py` and `test_a6.py` run the bootstrap job and the A6 helper over real HTTP against fake
LiteLLM (shared with llm-gateway), agent-server and OpenCode servers; one test provisions the key
with llm-gateway's real keys job first. `tests/fake_gate.py` stands in for the gate (cookie set on the
proxied response or on a redirect, the older Basic-only gate, 503 `starting`, a key rotation), and the
A6 tests run through it. `test_authproxy.py` covers the OpenCode session-key proxy, including the exact
embedded text as a supervising process. `test_prepdirs.py` covers the non-root directory setup.
`test_fragment.py` runs the real composer (`go run ./runtime/composer/cmd/sealed-compose lint` and
`compose`, through `llm-gateway/tests/sealed_compose.py`) on both variants together with llm-gateway,
checks per-service secrets, users, volume owners, the bootstrap job and the gated route, runs
`docker compose config` on the composed document, runs the embedded bootstrap text with `python3 -I -c`,
and runs `switch.sh` on a copy of the app followed by the whole suite on that copy. Tests that need
composer 1.2.0 (per-service mounts, recorded owners, `same_as` checks, the `forward_auth` route) skip
with the reason on an older composer.
