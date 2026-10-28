# Inference relay

Paid, attested inference for Sealed deployments, operated by the platform in its own
confidential VM. A customer's `llm-gateway` routes `relay/<model>` to `sealed-mpp-payer` in the
customer VM, which verifies this relay's live attestation and pays it per token over the
Machine Payments Protocol (MPP) in pathUSD on Tempo.

The relay is deployed like any other stack: released through this catalog as appId
`inference-relay`, approved onchain by OWNER as the customer, with its own key broker in the
platform project and an onchain deployment record.

## Services

| service | job |
|---|---|
| `inference-relay-front` | mppx server (Hono, Tempo method, payee `TREASURY_ADDRESS`, pathUSD). Prices, payment, provider gate, forwarding to LiteLLM, token usage to sealed-agent |
| `inference-relay-db` | Postgres 16.15: the MPP session store (vouchers survive restarts) and nothing else |
| `inference-relay-litellm` | LiteLLM 1.106.5 MIT core, no database, holds the provider keys |
| `inference-relay-tinfoil` | verifies Tinfoil with `@tinfoilsh/verifier`, forwards over TLS pinned to the attested key |
| `inference-relay-phala` | verifies Phala Confidential AI with `@phala/aci-verifier` (`connectAci`), forwards over its pinned transport |
| `inference-relay-nearai` | verifies the NEAR AI Cloud gateway report (Intel DCAP quote with `@phala/dcap-qvl`, report_data binding of signer, TLS key and nonce, RTMR3 and compose), forwards pinned |
| `inference-relay-privatemode` | Edgeless Privatemode proxy v1.60.0, which attests the Privatemode deployment and encrypts prompts itself |

A provider is enabled only when its API key secret exists. The front polls each provider's
status and refuses a request for that provider with `503 attestation_failed` before any
payment when the latest verification failed or is older than its freshness window.

## API

- `POST /v1/chat/completions`: OpenAI-compatible. Unpaid requests get `402` with two MPP offers:
  - `session` (`unitType: usd_micro`, one pathUSD base unit): a TIP-1034 channel; the response is
    SSE and the relay charges per token, in batches of `SESSION_BATCH_TOKENS`, ahead of delivery,
    then reconciles with the provider's reported usage and credits back any overcharge.
  - `charge`: one pathUSD transfer priced from estimated prompt tokens plus `max_tokens`
    (the relay always sets `max_tokens`, bounded by the model's limit).
- `GET /v1/models`: models with relay prices (`input_per_1m`, `output_per_1m` in pathUSD base
  units per 1M tokens, list price x (1 + `relay_markup_bps`/10000)) and whether each is attested.
  `default` resolves to the first preferred model whose provider is attested.
- `GET /v1/attest-status`: per-provider status and content-free evidence (measurements,
  compose hashes, pinned TLS keys).

## Money

Charges are paid to `TREASURY_ADDRESS`. Session settle and close transactions are sent by
`RELAY_SETTLER_KEY` as the channel operator (it needs pathUSD for fees only). A supervisor runs
mppx's `superviseCloses` every minute over the open channels listed in Postgres, so spend is
captured before a payer's close request can be withdrawn after the 900 second grace period.

Prices live in `runtime/relay/config/prices.json`, baked into the measured image. Tinfoil does
not publish per-model prices on a fetchable page and Privatemode prices in EUR; both are marked
in the file and must be confirmed by the operator before a release.

## Limits

Confidential VMs do not stop physical attacks on the server, bugs inside apps, or a cloud
provider with physical access. The relay sees prompts in its own attested VM; provider
attestation covers the provider's serving stack, not what a provider does outside it. NEAR AI GPU
evidence (`nvidia_payload`) is not yet checked; only the gateway's TDX evidence is.
