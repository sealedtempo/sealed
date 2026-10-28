# coding-agent

A headless coding agent for your stack: OpenHands agent-server 1.58.2 (`python-minimal` flavor, MIT,
D-023) with the local runtime, so the agent's terminal and file editor run inside its own container
on the apps network. No Docker socket, no VS Code, no browser. Its LLM is `llm-gateway`, so tokens
are metered there and this app is metered per app hour. Spec 6.5.

Requires `llm-gateway` in the same stack.

## Services

| service | role |
|---|---|
| `coding-agent-server` (alias `coding-agent`) | agent-server on port 8000. Starts as root only to hand the workspace volume to uid 10001 (`bootstrap/dropuid.py`), then runs as 10001. |
| `coding-agent-bootstrap` | manifest bootstrap job (`bootstrap/seed.py`): waits for llm-gateway, creates the LiteLLM virtual key `coding-agent` with the master key, and stores `{model, base_url, api_key}` with `PATCH /api/settings`. Writes `/workspace/.sealed/bootstrap.done`, then idles. |

Both scripts are embedded verbatim in `compose.fragment.yaml`, so they are part of the measured
stack. Edit `bootstrap/*.py` or `compose.fragment.in.yaml`, then run `python3 tools/build_fragment.py`
(the tests fail if the fragment is stale).

Persistence: everything lives on the `coding-agent-workspace` volume (encrypted data disk):
`/workspace/project` (code), `/workspace/conversations`, `/workspace/bash_events`, and
`/workspace/.openhands` (settings and secrets, encrypted with `OH_SECRET_KEY`).

## LLM wiring

agent-server V1 does not read `LLM_BASE_URL`. The bootstrap job seeds:

```json
{"agent_settings_diff": {"llm": {"model": "litellm_proxy/relay/default", "base_url": "http://llm-gateway:4000",
  "api_key": "<virtual key>", "usage_id": "coding-agent", "litellm_extra_body": {"fallbacks": ["local/qwen3-4b"]}}}}
```

If the gateway does not serve `relay/default`, it seeds `litellm_proxy/local/qwen3-4b` instead. With the
relay model, `litellm_extra_body.fallbacks` asks the gateway to answer from the local model when the
relay refuses a request (for example a failed relay attestation or the spend limit). If agent-server
rejects that field, the job stores the settings without it. A client starting a conversation sends
`agent.llm`; the A6 helper reads the stored settings with `X-Expose-Secrets: plaintext`.

The virtual key may use `relay/*` and `local/*`. The job deletes any older key with the same alias
first, so deleting the done file and restarting the job rotates the key.

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
| `LITELLM_MASTER_KEY` | none | must equal llm-gateway's master key; only the bootstrap job lists it |

Known limitation: the composer mounts the whole `/run/sealed/secrets/coding-agent` directory into
every service of the app, so the agent (which runs arbitrary commands) can read the gateway master key
file. Until per-service secret mounts exist, treat the master key as readable by the agent; see the
interface changes in `docs/notes/build-apps-ai.md`.

## Egress

None by default (`egress.yaml`). The gateway is inside the VM. Add git hosts and package registries
(for example `github.com:443`, `pypi.org:443`, `files.pythonhosted.org:443`) as customer egress
additions for `coding-agent`.

## Acceptance test A6

`scripts/a6-coding-agent.sh` (Python standard library only) runs the headless flow: create a
conversation that writes `calc.py` and `test_calc.py` and runs the test, poll until `finished`, then
download `calc.py`, rerun the test through `/api/bash/execute_bash_command`, and check that the
conversation recorded token usage.

```sh
A6_URL=https://code.<ip>.sslip.io CODING_AGENT_API_KEY=... SEALED_GATE_PASSWORD=... \
  catalog/apps/coding-agent/scripts/a6-coding-agent.sh
# local model instead of the relay:
catalog/apps/coding-agent/scripts/a6-coding-agent.sh --model litellm_proxy/local/qwen3-4b
```

A 4B local model may not drive tool calls well; run A6 against the relay (docs/notes/openhands.md 10.10).

## OpenCode fallback

`fallback-opencode/` packages OpenCode 1.19.5 (MIT) as a drop-in replacement with the same service
names and route. It is not part of the default release. To switch:

```sh
catalog/apps/coding-agent/fallback-opencode/switch.sh   # copies its release files over this app's
# build fallback-opencode/images/opencode, pin the digest in manifest.yaml, run the tests, open a PR
```

To go back, revert that commit. See `fallback-opencode/README.md`.

## Tests

```sh
tmp/pyenv/bin/python -m unittest discover -s catalog/apps/coding-agent/tests -t catalog/apps/coding-agent/tests
```

`test_seed.py` and `test_a6.py` run the bootstrap job and the A6 helper over real HTTP against fake
LiteLLM, agent-server and OpenCode servers (`tests/fakes.py`). `test_fragment.py` checks both
fragments against INTERFACES section 14, runs `docker compose config`, validates both manifests
against the schema, runs the embedded bootstrap text with `python3 -I -c`, and exercises `switch.sh`
on a copy of the app.
