# Inference relay

Paid, attested inference for Sealed deployments, operated by the platform in its own
confidential VM. A customer's `llm-gateway` routes `relay/<model>` to `sealed-mpp-payer` in the
customer VM, which verifies this relay's live attestation and pays it per token over the
Machine Payments Protocol (MPP) in FEE_TOKEN on Tempo (USDC.e on mainnet, D-035).

The relay is deployed like any other stack: released through this catalog as appId
`inference-relay`, approved onchain by OWNER as the customer, with its own key broker in the
platform project and an onchain deployment record.

## Services

| service | job |
|---|---|
| `inference-relay-front` | mppx server (Hono, Tempo method, payee `TREASURY_ADDRESS`, currency `FEE_TOKEN_ADDRESS`). Prices, payment, provider gate, forwarding to LiteLLM, token usage to sealed-agent |
| `inference-relay-db` | Postgres 16.15: the MPP session store (vouchers survive restarts) and nothing else |
| `inference-relay-litellm` | LiteLLM 1.106.5 MIT core, no database, holds the provider keys |
| `inference-relay-tinfoil` | verifies Tinfoil with `@tinfoilsh/verifier`, forwards over TLS pinned to the attested key |
| `inference-relay-phala` | verifies Phala Confidential AI with `@phala/aci-verifier` (`connectAci`), requires a reviewed compose hash (`PHALA_ACCEPTED_COMPOSE_HASHES`), forwards over its pinned transport |
| `inference-relay-nearai` | verifies the NEAR AI Cloud gateway report (Intel DCAP quote with `@phala/dcap-qvl`, report_data binding of signer, TLS key and nonce, RTMR3 and compose), requires a reviewed compose hash and OS image (`NEARAI_ACCEPTED_COMPOSE_HASHES`, `NEARAI_ACCEPTED_OS_MEASUREMENTS`), forwards pinned |
| `inference-relay-privatemode` | Edgeless Privatemode proxy v1.60.0, which attests the Privatemode deployment against its manifest and encrypts prompts itself |

A provider is enabled only when its API key secret exists. The front polls each provider's
status and refuses a request for that provider with `503 attestation_failed` before any
payment when the latest verification failed or is older than its freshness window, and re-reads
the sidecar status once more right before a paid request settles.

Code identity:

- Tinfoil: the Sigstore-signed release of `tinfoilsh/confidential-model-router` must match the
  attested measurement.
- Phala, NEAR AI: the sidecar refuses to verify while its allowlist is empty, so `phala/*` and
  `nearai/*` stay off until the operator reviews the provider's serving stack and pins the
  hashes in the fragment. The refusal names the observed value (`GET /v1/attest-status`).
  `ALLOW_UNPINNED_PROVIDER_CODE=1` accepts empty lists for development only.
- Privatemode: the proxy verifies the deployment against the manifest it fetched; the front proves
  the proxy is serving attested traffic with an authenticated one-token completion through it
  every 120 seconds (the proxy encrypts only with a key released after attestation and answers 500
  while it holds none) and records the hash of the manifest the proxy logged.
- NEAR AI model attestations and GPU evidence (`nvidia_payload`) are not checked, and
  `/v1/attest-status` says so; the TLS channel terminates at the gateway, whose TDX quote is
  checked.

## API

- `POST /v1/chat/completions`: OpenAI-compatible. Only the standard chat parameters are
  forwarded (messages, tools, tool_choice, functions, response_format, sampling settings, stop,
  seed, logprobs, reasoning_effort); routing and credential fields such as `fallbacks`,
  `mock_response`, `api_base` or `api_key` are dropped, `n` must be 1, and content parts other
  than text are refused. Bodies are limited to 4 MiB and unpaid requests to 120 per minute per
  client. Unpaid requests get `402` with two MPP offers:
  - `session` (`unitType: usd_micro`, one FEE_TOKEN base unit): a TIP-1034 channel; the response is
    SSE and the relay charges per token, in batches of `SESSION_BATCH_TOKENS`, ahead of delivery,
    then reconciles with the provider's reported usage and credits back any overcharge.
  - `charge`: one FEE_TOKEN transfer priced from estimated prompt tokens plus `max_tokens`
    (the relay always sets `max_tokens`, bounded by the model's limit).
- `GET /v1/models`: models with relay prices (`input_per_1m`, `output_per_1m` in FEE_TOKEN base
  units per 1M tokens, list price x (1 + `relay_markup_bps`/10000)) and whether each is attested.
  `default` resolves to the first preferred model whose provider is attested.
- `GET /v1/attest-status`: per-provider status and content-free evidence (measurements,
  compose hashes, pinned TLS keys).

## Money

Charges are paid to `TREASURY_ADDRESS`, the operator treasury
`0x755a1e289503c7109d01a74ed253ba0f724ca3eb` (the one FeeSplitter was deployed with,
`contracts/deployments/tempo-mainnet.json`). The currency is `FEE_TOKEN_ADDRESS`, equal to
`chain.fee_token` in `config/defaults.yaml`: USDC.e on mainnet (D-035). Session settle and close
transactions are sent by `RELAY_SETTLER_KEY` as the channel operator (it needs FEE_TOKEN for
network fees only). A supervisor runs
mppx's `superviseCloses` every minute over the open channels listed in Postgres, so spend is
captured before a payer's close request can be withdrawn after the 900 second grace period.

A per-request charge is final: the transfer settles before the upstream call, so a provider
failure after that is not refunded. Payers use sessions first, which charge only for delivered
tokens.

Prices live in `runtime/relay/config/prices.json`, baked into the measured image, as provider
list prices in FEE_TOKEN base units per 1M tokens. Every entry names its source and the date it
was read. Tinfoil does not publish per-model prices on a fetchable page and Privatemode prices in
EUR; those entries are `"confirmed": false`.
`TREASURY_ADDRESS` in the fragment is a literal (measured, read by every payer).
`pnpm --filter @sealed/relay release-check` fails while a price is unconfirmed or unsourced, the
treasury differs from the deployed one, or the fee token differs from `config/defaults.yaml`; the
composer's catalog lint blocks the unbuilt image digests.

## Payer trust

`sealed-mpp-payer` verifies this relay's live attestation through `sealed-verifierd` and then
sends prompts and payments only over TLS connections that present the key the attestation bound
(`tlsPubKeyHash`, the key of the attest host's certificate). So the chat endpoint must be served
on the attested origin (D-045). The `relay` route therefore sets `on_attest_host: true` with the
path prefix `/v1`: Caddy serves `/v1/*` of `inference-relay-front` on the deployment's attest
host, the same origin and certificate as `/attest`. `endpoints.relay` in a customer config is that
origin with no path, and `endpoints.relayAttest` is `<origin>/attest`; the payer refuses a config
where they differ. The attested stack must be exactly this app,
owned by OWNER, and the payee is `TREASURY_ADDRESS` of `inference-relay-front` in the attested
compose.

## Limits

Confidential VMs do not stop physical attacks on the server, bugs inside apps, or a cloud
provider with physical access. The relay sees prompts in its own attested VM; provider
attestation covers the provider's serving stack, not what a provider does outside it.
