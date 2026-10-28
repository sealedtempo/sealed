# llm-gateway

An OpenAI-compatible LLM gateway for the apps in your Sealed stack and for your own clients.
It is the LiteLLM proxy (MIT core only, v1.106.5) with its own Postgres for virtual keys and spend
logs, plus a local CPU model. Spec 6.2, D-024.

## Services

| service | image | role |
|---|---|---|
| `llm-gateway-litellm` (alias `llm-gateway`) | `litellm` (built from `images/litellm`) | proxy on port 4000, the entry point for other apps (virtual keys) |
| `llm-gateway-db` | `postgres` 16.15 | virtual keys and spend logs; data on the encrypted data disk; password auth |
| `llm-gateway-ollama` | `local-model` (built from `images/local-model`) | Ollama 0.40.12, CPU only, `qwen3:4b-instruct-2507-q4_K_M` baked in, behind `sealed-ollama-gate`; read-only rootfs, uid 10002 |
| `llm-gateway-keys` | `litellm` | keys job: provisions the virtual keys of other catalog apps (below); listens on nothing; uid 65534 |

The shared `apps` network has no per-app segmentation, so every app container can open a connection
to every service above. Each one therefore authenticates on its own: LiteLLM by virtual key, Postgres
by password, and Ollama through `sealed-ollama-gate` (Go standard library,
`runtime/images/local-model/gate`). The gate runs Ollama on 127.0.0.1:11435 and answers on :11434
only to the addresses of `llm-gateway-litellm` (resolved through Docker's DNS; service names and fixed
IPs come only from the composer) and to loopback (healthcheck), and only for inference and read
endpoints (`/api/chat`, `/api/generate`, `/api/embed(dings)`, `/api/show`, `/api/tags`, `/api/ps`,
`/api/version`, `/v1/...`). Pull, push, create, copy, delete and blob uploads are refused. So the coding
agent or any other app cannot run unmetered local inference or fill Ollama's queue. A bearer key on the
gate (`-key-env`) is implemented but off, because today a secret for Ollama would mount every
llm-gateway secret (the master key included) into the Ollama container.

`images/local-model` is a symlink to `runtime/images/local-model`, so `build:images/<dir>` always
resolves relative to this app directory. Built images keep the zero digest until the image workflow
pins them (D-028), so catalog lint blocks a release until then.

## Routes (model names)

| model name | goes to | data |
|---|---|---|
| `local/qwen3-4b`, `local/<ollama tag>` | Ollama in this VM | stays in your VM |
| `relay/default`, `relay/<model>` | `http://sealed-mpp-payer:8090/v1`, which pays the platform relay per token over MPP | relay runs in an attested confidential VM |
| `byok/<provider>/<model>` | the provider's API with your key | provider's confidential VM; this gateway does not verify the provider attestation itself |
| `external/<provider>/<model>` | ordinary hosted API with your key | **data leaves your cloud** |

Both `byok` and `external` routes are off by default. `byok` needs `BYOK_ROUTES_ENABLED=true` plus a
provider key, `external` needs `EXTERNAL_ROUTES_ENABLED=true` plus a provider key. Both are labeled
`sealed_data_location: data leaves your cloud` in `GET /v1/model/info`, which the console shows; the
byok label adds that the provider's TEE attestation is not verified by Sealed. They are plain
OpenAI-compatible calls over TLS: only the relay path verifies the remote attestation. Providers and
their secrets are listed in `images/litellm/providers.yaml`.

`relay/default` falls back to `local/qwen3-4b` inside the gateway (`router_settings.fallbacks`) when
the relay call fails, for example when the relay is unfunded, unattested or down, or the payer hit its
spend limit. Fallback targets must be `local/` routes (the renderer enforces it), so a fallback never
sends data out of the VM. Other `relay/<model>` names do not fall back.

Both families also need an egress addition for the provider host (for example
`"llm-gateway": ["inference.tinfoil.sh:443"]` in the deployment config), because the release allows
no egress by default.

## Keys for other apps

`images/litellm/sealed_keys.py` runs as the `llm-gateway-keys` service, so no other app ever needs
the master key. For each entry in `images/litellm/app_keys.yaml` (today: coding-agent) whose secret is
set (`APP_KEY_CODING_AGENT`, generated `sk-hex32`), it makes the key with exactly that value exist:
alias `coding-agent`, models `relay/*` and `local/*` (byok, external and `*` are refused by the
loader), `key_type: llm_api`, rpm/tpm/parallel limits. It looks keys up by sha256 hash
(`GET /key/info?key=<hash>`), creates them with `POST /key/generate {"key": <value>, ...}`, restores
drifted scope with `/key/update`, leaves keys an admin blocked alone, and deletes the alias when the
secret is unset. It repeats every 5 minutes, so a reset gateway database heals by itself, and its
status file (no secrets) is its healthcheck. The consumer app stores the same value as its own secret
(`LLM_GATEWAY_KEY` for coding-agent).

## Boot

`images/litellm/sealed_entrypoint.py` runs before LiteLLM (after `envexec` exported the secrets):
it checks `LITELLM_MASTER_KEY` (must start with `sk-`, not a known default), `LITELLM_SALT_KEY` and
`POSTGRES_PASSWORD`, builds `DATABASE_URL`, renders `/run/litellm/config.yaml` from `config.yaml`
and `providers.yaml`, removes env vars that must never reach LiteLLM (`LITELLM_LICENSE`,
`OPENAI_API_KEY`, tracing exporters, the Postgres password), and execs `litellm --config ...`.
The rendered file has no secret values, only `os.environ/<NAME>` references.

## Metering

`images/litellm/sealed_usage.py` is a LiteLLM `CustomLogger` instance registered as
`sealed_usage.usage_logger`. For each successful call it posts

```json
{"app":"llm-gateway","unit":"tokens","quantity":87,"id":"<litellm call id>","meta":{"model":"local/qwen3-4b","prompt_tokens":23,"completion_tokens":64,"key_alias":"coding-agent"}}
```

to `http://sealed-agent:7070/v1/usage-events` with `trust_env=False` (never through the egress proxy).
`id` is LiteLLM's call id; sealed-agent deduplicates on it, so retries never bill a call twice. A
failure that cannot have reached the agent (connect error, 503) is retried; an ambiguous one (read
timeout, other 5xx) is retried only because the event has an id. Events the agent does not take within
three quick attempts wait in a bounded in-memory queue (10,000 events, 24 hours) and are retried with
backoff up to a minute. They are lost if the gateway process restarts before the agent comes back;
`LiteLLM_SpendLogs` in Postgres keeps per-call token counts for a manual audit (nothing reconciles them
automatically). It never reads or sends prompts, outputs or headers, and it never raises into LiteLLM.

## Using the gateway

Inside the VM: `http://llm-gateway:4000`. Outside: the `gateway` route
(`https://gateway.<ip-with-dashes>.sslip.io`), which passes LiteLLM bearer keys through without the
password gate. Catalog apps get their keys from the keys job; for your own clients, create a key
with the master key:

```sh
curl -s https://gateway.<ip>.sslip.io/key/generate -H "Authorization: Bearer $LITELLM_MASTER_KEY" \
  -H 'content-type: application/json' \
  -d '{"key_alias":"my-app","models":["local/*","relay/*"],"key_type":"llm_api"}'
```

Health: `GET /health/liveliness` (liveness) and `GET /health/readiness` (DB connected). Never use
`GET /health` as a probe: it calls every model.

## Secrets

`LITELLM_MASTER_KEY` (sk-hex32; only `llm-gateway-litellm` and `llm-gateway-keys` list it),
`LITELLM_SALT_KEY` (sk-hex32, never change after first boot), `POSTGRES_PASSWORD` (hex32),
`APP_KEY_CODING_AGENT` (sk-hex32, optional; copy the value into coding-agent's `LLM_GATEWAY_KEY`), and
the optional provider keys with `BYOK_ROUTES_ENABLED` and `EXTERNAL_ROUTES_ENABLED`. Secret Manager
names are `sealed-llm-gateway-<NAME>`.

## Never enable (enterprise only)

`LITELLM_LICENSE`, JWT/SSO/SCIM auth, `allowed_routes`, `allowed_ips`, `enforced_params`, request and
response size limits, key/team `tags`, `guardrails`, `policies`, team-based logging, `/key/regenerate`,
the moderation and prompt-injection callbacks, `generic_api`, email and PagerDuty alerting, and
`LITELLM_ENABLE_ADMIN_MCP`. `tests/test_render_config.py` fails if the rendered config contains any of
these keys.

## Tests

```sh
python3 -m venv tmp/pyenv && tmp/pyenv/bin/pip install PyYAML==6.0.3 httpx==0.28.1 jsonschema==4.25.1
tmp/pyenv/bin/python -m unittest discover -s catalog/apps/llm-gateway/tests -t catalog/apps/llm-gateway/tests
```

`tests/test_packaging.py` checks the fragment against INTERFACES section 14, runs
`docker compose config` on it with dummy digests, validates the manifest against
`catalog/schema/manifest.schema.json`, and checks the Dockerfile pins and flattening.
`tests/test_sealed_keys.py` runs the keys job over real HTTP against `tests/fake_litellm.py` (custom
key, alias and hash semantics from the LiteLLM 1.106.5 source). The image build re-checks the callback,
the renderer and the keys config against the real LiteLLM with `--network=none`. The gate has Go tests:
`cd runtime/images/local-model/gate && go test .`.
