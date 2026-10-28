# llm-gateway

An OpenAI-compatible LLM gateway for the apps in your Sealed stack and for your own clients.
It is the LiteLLM proxy (MIT core only, v1.106.5) with its own Postgres for virtual keys and spend
logs, plus a local CPU model. Spec 6.2, D-024.

## Services

| service | image | role |
|---|---|---|
| `llm-gateway-litellm` (alias `llm-gateway`) | `litellm` (built from `images/litellm`) | proxy on port 4000, the only service other apps reach |
| `llm-gateway-db` | `postgres` 16.15 | virtual keys and spend logs; data on the encrypted data disk |
| `llm-gateway-ollama` | `local-model` (built from `runtime/images/local-model`) | Ollama 0.40.12, CPU only, `qwen3:4b-instruct-2507-q4_K_M` baked in; read-only rootfs |

`build:images/<dir>` resolves to `catalog/apps/llm-gateway/images/<dir>` when that directory exists,
otherwise to `runtime/images/<dir>`. Built images keep the zero digest until the image workflow pins
them (D-028), so catalog lint blocks a release until then.

## Routes (model names)

| model name | goes to | data |
|---|---|---|
| `local/qwen3-4b`, `local/<ollama tag>` | Ollama in this VM | stays in your VM |
| `relay/default`, `relay/<model>` | `http://sealed-mpp-payer:8090/v1`, which pays the platform relay per token over MPP | relay runs in an attested confidential VM |
| `byok/<provider>/<model>` | the provider's API with your key | provider's confidential VM; this gateway does not verify the provider attestation itself |
| `external/<provider>/<model>` | ordinary hosted API with your key | **data leaves your cloud** |

`byok` routes exist only when the key secret exists. `external` routes are off by default: they need
the secret `EXTERNAL_ROUTES_ENABLED=true` and a provider key, and they are labeled
`sealed_data_location: data leaves your cloud` in `GET /v1/model/info`, which the console shows.
Providers and their secrets are listed in `images/litellm/providers.yaml`.

Both families also need an egress addition for the provider host (for example
`"llm-gateway": ["inference.tinfoil.sh:443"]` in the deployment config), because the release allows
no egress by default.

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
{"app":"llm-gateway","unit":"tokens","quantity":87,"meta":{"model":"local/qwen3-4b","prompt_tokens":23,"completion_tokens":64,"key_alias":"coding-agent"}}
```

to `http://sealed-agent:7070/v1/usage-events` with `trust_env=False` (never through the egress proxy).
It never reads or sends prompts, outputs or headers, and it never raises into LiteLLM. Callbacks are
best effort; `LiteLLM_SpendLogs` in Postgres holds the same counts for reconciliation.

## Using the gateway

Inside the VM: `http://llm-gateway:4000`. Outside: the `gateway` route
(`https://gateway.<ip-with-dashes>.sslip.io`), which passes LiteLLM bearer keys through without the
password gate. Create a key per app with the master key:

```sh
curl -s https://gateway.<ip>.sslip.io/key/generate -H "Authorization: Bearer $LITELLM_MASTER_KEY" \
  -H 'content-type: application/json' \
  -d '{"key_alias":"my-app","models":["local/*","relay/*"],"key_type":"llm_api"}'
```

Health: `GET /health/liveliness` (liveness) and `GET /health/readiness` (DB connected). Never use
`GET /health` as a probe: it calls every model.

## Secrets

`LITELLM_MASTER_KEY` (sk-hex32), `LITELLM_SALT_KEY` (sk-hex32, never change after first boot),
`POSTGRES_PASSWORD` (hex32), and the optional provider keys and `EXTERNAL_ROUTES_ENABLED`. Secret
Manager names are `sealed-llm-gateway-<NAME>`.

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
`catalog/schema/manifest.schema.json`, and checks the Dockerfile pins and flattening. The image
build itself re-checks the callback and renderer against the real LiteLLM.
