# coding-agent

A headless coding agent for your stack: OpenHands agent-server 1.58.2 (`python-minimal` flavor, MIT,
D-023) with the local runtime, so the agent's terminal and file editor run inside its own container
on the apps network. No Docker socket, no VS Code, no browser. Its LLM is `llm-gateway`, so tokens
are metered there and this app is metered per app hour. Spec 6.5.

Requires `llm-gateway` in the same stack.

## Services

| service | role |
|---|---|
| `coding-agent-server` (alias `coding-agent`) | agent-server on port 8000. Starts as root only to hand the workspace volume to uid 10001 (`bootstrap/dropuid.py`), then runs as 10001 with no_new_privs, so setuid binaries in the image cannot regain root. |
| `coding-agent-bootstrap` | manifest bootstrap job (`bootstrap/seed.py`), run at every start: waits until llm-gateway accepts this app's virtual key `LLM_GATEWAY_KEY`, then stores `{model, base_url, api_key}` with `PATCH /api/settings`. It starts as root only to hand its own state volume to uid 10003, writes `/var/lib/sealed-bootstrap/done` there (that volume is not mounted into the agent's container, so the agent cannot forge or delete it), then idles. |

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
drifts and recreates the key after a gateway database reset. This app stores the same value as
`LLM_GATEWAY_KEY`.

agent-server V1 does not read `LLM_BASE_URL`. At every start the bootstrap job seeds:

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

The `code` route (`https://code.<ip-with-dashes>.sslip.io`) sits behind the password gate. Every
`/api/*` call also needs `X-Session-API-Key: <OH_SESSION_API_KEYS_0>`. Swagger UI is at `/docs`,
the schema at `/openapi.json`, readiness at `/ready`.

```sh
curl -u "sealed:$GATE_PASSWORD" -H "X-Session-API-Key: $KEY" https://code.<ip>.sslip.io/api/settings
```

## Secrets

| name | generate | notes |
|---|---|---|
| `OH_SESSION_API_KEYS_0` | hex32 | API key; also makes agent-server bind 0.0.0.0 |
| `OH_SECRET_KEY` | hex32 | encrypts stored LLM key and secrets; never change it (or set `OH_PREVIOUS_SECRET_KEYS_0`) |
| `LLM_GATEWAY_KEY` | none | this app's gateway virtual key; must equal llm-gateway's `APP_KEY_CODING_AGENT` |

The composer mounts the whole `/run/sealed/secrets/coding-agent` directory into every service of
the app that has secrets, so the agent's shell can read all three. None of them grants more than the
agent already has: its own scoped gateway key (rate limited, `relay/*` and `local/*` only) and access
to itself.

## Egress

None by default (`egress.yaml`). The gateway is inside the VM. Add git hosts and package registries
(for example `github.com:443`, `pypi.org:443`, `files.pythonhosted.org:443`) as customer egress
additions for `coding-agent`.

## Acceptance test A6

`scripts/a6-coding-agent.sh` (Python standard library only) runs the headless flow: create a
conversation that writes `calc.py` and `test_calc.py` and runs the test, poll until `finished`, then
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
with llm-gateway's real keys job first. `test_authproxy.py` covers the OpenCode session-key proxy,
including the exact embedded text as a supervising process. `test_fragment.py` checks both fragments
against INTERFACES section 14, runs `docker compose config`, validates both manifests against the
schema, runs the embedded bootstrap text with `python3 -I -c`, and runs `switch.sh` on a copy of the
app followed by the whole suite on that copy.
