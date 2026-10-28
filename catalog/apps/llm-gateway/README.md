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

Every service is on the app's own network `app-llm-gateway` (D-041). Only `llm-gateway-litellm`, the
primary service, is also on the shared `apps` network, where other apps reach it as `llm-gateway`, so
other apps cannot open a connection to the database, Ollama or the keys job at all. Each service still
authenticates on its own: LiteLLM by virtual key, Postgres by password, and Ollama through
`sealed-ollama-gate` (Go standard library, `runtime/images/local-model/gate`). The gate runs Ollama on
127.0.0.1:11435 and answers on :11434 only to the addresses of `llm-gateway-litellm` (resolved through
Docker's DNS; service names and fixed IPs come only from the composer) and to loopback (healthcheck),
only with the bearer key `OLLAMA_GATE_KEY` (`-key-env`, which every `local/` route sends as
`api_key`), and only for inference and read endpoints (`/api/chat`, `/api/generate`, `/api/embed(dings)`,
`/api/show`, `/api/tags`, `/api/ps`, `/api/version`, `/v1/...`). Pull, push, create, copy, delete and blob
uploads are refused. So the coding agent or any other app cannot run unmetered local inference or fill
Ollama's queue.

Each service gets bind mounts of exactly the secret files it lists in `x-sealed-secrets` (D-042), so the
Ollama container sees `OLLAMA_GATE_KEY` and nothing else, and only `llm-gateway-litellm` and
`llm-gateway-keys` see the master key.

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
status file (no secrets) is its healthcheck. The consumer app's secret refers to this one
(`LLM_GATEWAY_KEY` of coding-agent has `same_as: llm-gateway/APP_KEY_CODING_AGENT`, D-043), so
`sealed secrets` sets the value once and the key broker returns it to both apps.

## Boot

`images/litellm/sealed_entrypoint.py` runs before LiteLLM (after `envexec` exported the secrets):
it checks `LITELLM_MASTER_KEY` (must start with `sk-`, not a known default), `LITELLM_SALT_KEY`,
`POSTGRES_PASSWORD` and `OLLAMA_GATE_KEY` (at least 16 characters, and every `local/` route must send it),
builds `DATABASE_URL`, renders `/run/litellm/config.yaml` from `config.yaml`
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
`OLLAMA_GATE_KEY` (hex32; only `llm-gateway-litellm` and `llm-gateway-ollama` list it),
`APP_KEY_CODING_AGENT` (sk-hex32, generated; coding-agent's `LLM_GATEWAY_KEY` refers to it with
`same_as`, and a required secret may only refer to a required one, so it always exists; without
coding-agent the key lives only inside llm-gateway), and the optional provider keys with
`BYOK_ROUTES_ENABLED` and `EXTERNAL_ROUTES_ENABLED`.
Secret Manager names are `sealed-llm-gateway-<NAME>`.

## Never enable (enterprise only)

`LITELLM_LICENSE`, JWT/SSO/SCIM auth, `allowed_routes`, `allowed_ips`, `enforced_params`, request and
response size limits, key/team `tags`, `guardrails`, `policies`, team-based logging, `/key/regenerate`,
the moderation and prompt-injection callbacks, `generic_api`, email and PagerDuty alerting, and
`LITELLM_ENABLE_ADMIN_MCP`. `tests/test_render_config.py` fails if the rendered config contains any of
these keys.

## Tests

```sh
python3 -m venv tmp/pyenv && tmp/pyenv/bin/pip install PyYAML==6.0.3 httpx==0.28.1
make -C catalog/apps/llm-gateway test PYTHON="$PWD/tmp/pyenv/bin/python"   # needs Go for the composer
```

The catalog rules are checked only by the real composer: `tests/sealed_compose.py` runs
`go run ./runtime/composer/cmd/sealed-compose lint` and `compose` on this app (there is no app-local
copy of the rules any more; it moves to `catalog/tools/` once that exists). `tests/test_packaging.py`
requires the lint to report nothing but the unbuilt `litellm` and `local-model` digests (and missing
SBOMs), composes the app, checks that each service exports and (with composer 1.2.0) mounts exactly the
secrets it lists, runs `docker compose config` on the composed document, and checks the Dockerfile pins
and flattening. Without Go the composer tests skip; with `CI` or `SEALED_REQUIRE_COMPOSER=1` set they
fail instead.
`tests/test_sealed_keys.py` runs the keys job over real HTTP against `tests/fake_litellm.py` (custom
key, alias and hash semantics from the LiteLLM 1.106.5 source). The image build re-checks the callback,
the renderer and the keys config against the real LiteLLM with `--network=none`. The gate has Go tests:
`cd runtime/images/local-model/gate && go test .`.
