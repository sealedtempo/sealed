# Sealed architecture

Every app is built from public source, pinned, scanned, signed and reviewed. You can verify that exactly that build is what runs.

Your data stays in your cloud account. Apps run in confidential VMs, we have no access path, and outbound traffic only reaches destinations you approve. Your wallet approves exactly which builds can unlock your data.

Limits: confidential VMs do not stop physical attacks on the server, bugs inside apps, or a cloud provider with physical access.

This document describes the system as built on `ws/integration` after merge C and the release-candidate round (composer 1.5.0), including the hardening decisions D-058 to D-069 and D-073. Byte-level formats are in [INTERFACES.md](INTERFACES.md); the fragment and composed-stack contract is [runtime/composer/README.md](../runtime/composer/README.md), which wins where the two differ. Decisions are cited as D-0xx.

## Actors

- Operator: runs the control plane (api, oracle, indexer, console), the catalog and its release CI, and the inference relay. Owns the contracts (OWNER key, `Ownable2Step`), holds the OPS key (release registrar, record submitter) and the ORACLE key (signs deployment records; it exists only in the platform's Secret Manager).
- Customer: owns a Google Cloud project and a Tempo wallet. Runs the bootstrap with their own credentials, keeps secrets in their own Secret Manager, approves stacks onchain, authorizes a daily spend limit.
- Maintainer: owns an app's packaging in the catalog and receives a share of that app's fees in USDC.e.
- Verifier: anyone holding an evidence bundle and a Tempo RPC endpoint.

## System overview

```mermaid
flowchart LR
  subgraph GH["Public GitHub repo"]
    CAT["catalog/apps"] --> RCI["release CI: GHCR mirror, SBOM, Grype, bundle, cosign keyless, SLSA"]
    RCI --> REL[("GitHub Releases: bundle, signature, provenance, SBOMs")]
    RCI --> GHCR[("ghcr.io images, same digests")]
  end

  subgraph TEMPO["Tempo mainnet, chain 4217"]
    PR["PlatformRegistry"]
    AR["AppRegistry"]
    DR["DeploymentRegistry"]
    OSV["OracleSignatureVerifier, method 1"]
    FS["FeeSplitter"]
    DR --> OSV
  end
  RCI -->|"publishRelease, OPS key"| AR

  subgraph CUST["Customer Google Cloud project"]
    KB["key broker on Cloud Run"]
    SM[("Secret Manager sealed-*")]
    KMS[("Cloud KMS HMAC key")]
    LOG[("Cloud Logging decision log")]
    DEP["deployer service account"]
    DISK[("sealed-data disk, LUKS2")]
    subgraph CVM["Confidential VM: Intel TDX, dstack"]
      GA["dstack guest agent"]
      AG["sealed-agent"]
      EG["sealed-egress: proxy and DNS"]
      CD["Caddy: TLS and routes"]
      MP["sealed-mpp-payer"]
      VD["sealed-verifierd"]
      APPS["apps: llm-gateway, scraper, crm, coding-agent, internal-tools"]
    end
  end

  subgraph PLAT["Platform project"]
    API["api, oracle, indexer"]
    CON["console"]
    VDP["sealed-verifierd"]
    API --> VDP
    subgraph RVM["Relay confidential VM"]
      RF["inference-relay-front: mppx"] --> RL["LiteLLM"]
      RL --> RS["provider attestation sidecars"]
    end
  end
  PROV["attested inference providers"]
  RS --> PROV

  KB --> SM
  KB --> KMS
  KB --> LOG
  AG -->|"quote, event log, config"| KB
  KB -.->|"reads approvals, images, releases"| DR
  KB -.->|"bundles by hash"| REL
  AG --> GA
  AG --> DISK
  AG -->|"evidence bundle"| API
  API -->|"registerDeployment, heartbeat"| DR
  API -->|"impersonates"| DEP
  DEP -->|"creates, stops, deletes the VM"| GA
  AG -->|"approve, payFees, topUpFees"| FS
  CD -->|"forward_auth /v1/gate"| AG
  CD --> APPS
  APPS -->|"all outbound"| EG
  APPS -->|"relay/* routes"| MP
  MP -->|"verify relay /attest"| VD
  MP -->|"MPP payments, prompts over the attested TLS key"| RF
  CON -->|"approveStack, authorizeKey with the customer wallet"| DR
```

Not drawn: every outbound connection of the agent, Caddy, the payer and verifierd also goes through sealed-egress (key broker, platform api, Tempo RPC, Intel PCS, Let's Encrypt, the relay, the release asset hosts). Image pulls by dockerd are digest-pinned and do not go through it. The key broker, `sealed verify`, the oracle's verifierd and the in-VM verifierd fetch release bundles from GitHub Releases and accept them only when their sha256 equals the onchain bundleHash.

## Components

| component | runs in | language | source |
|---|---|---|---|
| contracts | Tempo mainnet | Solidity, Foundry | `contracts/` |
| catalog and release CI | public GitHub repo | YAML, GitHub Actions, Go | `catalog/`, `catalog/tools/`, `.github/workflows/` |
| composer | key broker, CLI, verifierd, release CI | Go | `runtime/composer/` |
| sealed-agent | customer VM | TypeScript | `runtime/agent/`, `packages/core/` |
| sealed-egress | customer VM | Go (stripe/smokescreen as a library) | `runtime/egress/` |
| Caddy config and gate template | customer VM | Caddyfile, Go | `runtime/caddy/` |
| envexec | every app container | Go | `runtime/envexec/` |
| sealed-mpp-payer | customer VM, only with llm-gateway | TypeScript | `runtime/mpp-payer/` |
| sealed-verifierd | customer VM (for the payer), platform VM (for the oracle) | Go | `verifier/` |
| key broker | customer project, Cloud Run | Go | `key-broker/` |
| sealed CLI | anywhere | Go | `cli/` |
| customer bootstrap | customer project | Terraform | `infra/terraform/customer-bootstrap/` |
| inference relay | platform confidential VM | TypeScript, LiteLLM | `runtime/relay/`, `catalog/apps/inference-relay/` |
| api, oracle, indexer | platform VM | TypeScript | private repository |
| console | platform VM | Next.js | private repository |

## Trust flow

1. A maintainer opens a pull request that adds or bumps `catalog/apps/<id>/`. CI validates the manifest against the schema, runs the composer lint (licenses D-021 and D-050, digests, telemetry switches, egress policy, exclusions, waivers), builds SBOMs with Syft and scans them with Grype, and composes every app with `docker compose config`.
2. On merge, the release job mirrors the images to GHCR with identical digests, builds the deterministic bundle tar, signs it with cosign keyless through GitHub OIDC (logged in Rekor), adds SLSA provenance, uploads everything to a GitHub Release under the D-046 asset rule, and calls `AppRegistry.publishRelease` with the OPS key.
3. A customer runs `sealed bootstrap` with their own credentials. The key broker is deployed from a digest-pinned public image with its own service account, and its customer address and Tempo RPC are set by the customer.
4. The customer picks apps. The composer builds `app-compose.json` deterministically from the public config and the release bundles; its sha256 is the stackHash. The customer's wallet calls `DeploymentRegistry.approveStack(stackHash, releaseIds, imageId, expiry)`. The first approval of a stackHash fixes its release list and image (contract review CR-2).
5. The platform creates the VM through the deployer account (or the customer does, with `sealed deploy`). dstack boots the measured image and measures the compose hash into RTMR3.
6. sealed-agent gets a nonce from the customer's key broker and a TDX quote whose report_data binds that nonce and an ephemeral X25519 key. dstack returns the quote zero-padded to 8000 bytes; the agent sends only the signed bytes (D-052). The key broker verifies the quote with Intel collateral and its TCB policy, refuses a chain head older than 60 seconds (D-060), checks the measurements against an approved non-debug image in PlatformRegistry, the TD attributes against the production rule and XFAM against the allowlist `tdx.allowed_xfam` (D-077), replays RTMR3, recomputes the stack byte for byte from the onchain releases and their bundles, and checks the customer's approval and its exact release set (D-014). Only then it returns the stack's secrets, the data-disk key and the signer seed, HPKE-encrypted to the ephemeral key. Every decision goes to the customer's Cloud Logging.
7. The agent unlocks the data disk, writes each declared secret to tmpfs, opens the ready gate, starts the apps, and sends an evidence bundle to the platform oracle. The oracle verifies it independently with sealed-verifierd, signs an EIP-712 record and submits `registerDeployment` with the OPS key. Re-attestation every 24 hours and after a reboot gives a `heartbeat`.
8. Apps send usage events to the agent. Every settlement interval the agent signs a usage report, stores it with the platform api and pays FeeSplitter, which splits each payment between the maintainer and the treasury.
9. Anyone with the evidence bundle runs `sealed verify` against a Tempo RPC to check the whole chain without trusting the platform ([VERIFY.md](VERIFY.md)).

The oracle is not in the secret-release path. Secrets move only on the key broker's own checks in the customer's project.

## Boot and key release

```mermaid
sequenceDiagram
  participant W as Customer wallet
  participant T as Tempo
  participant P as Platform api and oracle
  participant V as Confidential VM
  participant K as Customer key broker
  W->>T: approveStack(stackHash, releaseIds, imageId, expiry)
  P->>V: create the VM through the deployer account, no secrets
  V->>V: dstack measures app-compose.json into RTMR3
  V->>K: GET /v1/nonce
  V->>K: POST /v1/release with the signed quote, event log, config, appCompose, releaseIds, imageId
  K->>T: head block (at most 60 s old), then getImage, isApprovedImage, getRelease at that block
  K->>K: Intel collateral, TCB policy, TD attribute rule, RTMR3 replay, stack recomputation
  K->>T: a fresh head (at most 60 s old), then isStackApproved, getStackApproval at that block
  K-->>V: HPKE sealed secrets, diskKey, signerSeed
  V->>V: open LUKS2 disk, write tmpfs secrets, ready gate, apps start
  V->>P: POST /v1/evidence
  P->>P: sealed-verifierd checks the bundle
  P->>T: registerDeployment(record, method 1, oracle signature)
```

`diskKey = HMAC_KMS("sealed/disk/v2" || customer || salt)` and `signerSeed = HMAC_KMS("sealed/signer/v2" || customer || salt)` are computed by the customer's Cloud KMS HMAC key (D-058, replacing the deploymentId of D-011), and the root key never leaves KMS. A reboot or a stack upgrade (new releases, same config salt) keeps the data disk and the enclave signer, so the access-key authorization stays valid across upgrades. The broker still releases them only to an approved stack of that customer, and a customer who wants a fresh disk uses a new salt. The enclave signer is derived from the seed with HKDF inside the VM.

The measurement chain behind the image check: RTMR1 and RTMR2 are computed from the image file, and MRTD and RTMR0 come from Google's firmware and are recorded trust-on-first-use per machine type (D-052, [THREAT_MODEL.md](THREAT_MODEL.md#measurement-chain-on-google-cloud)).

## Networks inside a deployment VM (D-041)

```mermaid
flowchart LR
  NET(("Internet"))
  CDY["caddy: edge .4, apps .4"]
  EGR["sealed-egress: edge .2, apps .2, .2 on every app network"]
  AGT["sealed-agent: apps .3, .3 on every app network"]
  PAY["sealed-mpp-payer: apps .5, verifier .5"]
  VFD["sealed-verifierd: verifier .6 only"]
  subgraph APPA["app-a network 172.30.1.0/24, internal"]
    AP["app-a primary: also on apps"]
    AD["app-a database"]
  end
  subgraph APPB["app-b network 172.30.2.0/24, internal"]
    BP["app-b primary: also on apps"]
    BW["app-b worker"]
  end
  NET -->|"80, 443"| CDY
  CDY -->|"apps network"| AP
  CDY -->|"apps network"| BP
  CDY -->|"forward_auth"| AGT
  AP --- AD
  BP --- BW
  AP -->|"proxy and DNS on app-a"| EGR
  AD -->|"proxy and DNS on app-a"| EGR
  BW -->|"proxy and DNS on app-b"| EGR
  BP -->|"apps network"| PAY
  PAY -->|"verifier network"| VFD
  VFD -->|"proxy and DNS on verifier"| EGR
  EGR -->|"allowlisted host:port only"| NET
```

| network | subnet | members |
|---|---|---|
| `apps` | `172.30.0.0/24`, internal | sidecars (egress `.2`, agent `.3`, Caddy `.4`, payer `.5`) and each app's primary service (from `.16`, alias `<appId>`) |
| `edge` | `172.31.0.0/24`, inter-container traffic off | sealed-egress `.2` and Caddy `.4` (publishes 80 and 443) |
| `app-<appId>` | `172.30.<n>.0/24`, internal, n = 1..16 in sorted app order | every service of that app, sealed-egress `.2`, sealed-agent `.3` |
| `verifier` | `172.30.250.0/24`, internal, only with llm-gateway (D-061) | sealed-egress `.2`, sealed-mpp-payer `.5`, sealed-verifierd `.6`; no app service |

- A non-primary service (a database, a worker, a bootstrap job) is reachable only from its own app, sealed-egress and sealed-agent. Apps reach each other only primary to primary on `apps`, for example coding-agent to `llm-gateway`, and llm-gateway to `sealed-mpp-payer`.
- Every service's `dns` and `HTTP(S)_PROXY` point at sealed-egress on its own app network. sealed-egress identifies callers by source address (one caller per address) and enforces per-caller allowlists that are part of the measured stack: the agent may reach only the key broker, the platform api and the Tempo RPC; Caddy only Let's Encrypt ACME; the payer only the relay and the Tempo RPC; verifierd only Intel PCS, the Tempo RPC, the relay attest host and the release asset hosts (`github.com`, `objects.githubusercontent.com` and `release-assets.githubusercontent.com` on 443), which it needs to recompute the relay's stack (D-061); an app service only its manifest's `default_allow` plus the customer's `egressAdditions`.
- sealed-verifierd is on the `verifier` network only, together with sealed-egress and the payer, and accepts requests only from the payer's address there (`172.30.250.5`, D-061). It fetches no attest URL itself (the payer submits the attestation it fetched). So no app can reach it or use it as an outbound client toward the hosts on verifierd's allowlist. The agent's addresses on the app networks (`sealed-agent--app-<appId>`) and the payer's on the verifier network have empty egress allowlists: the agent's own traffic leaves from `172.30.0.3`.
- Inside each container, names resolve through Docker's embedded DNS (`127.0.0.11`), which forwards to sealed-egress on the container's own app network and never to the host resolver. On internal-only networks Docker forwards this way only from 26.1.3 on (26.0.0 to 26.1.2 forward nothing, so names would not resolve); dstack 0.6.1 ships Docker 29.3.0.
- sealed-egress resolves only allowlisted names (everything else is NXDOMAIN and counted), never dials metadata, link-local, loopback or the VM's own networks, dials a private address only when it is an IP-literal entry of that caller's own allowlist and lies inside the config's `allowedVpcRanges` (never for a hostname, so DNS rebinding reaches no VPC host), and checks every resolved address again just before the dial. The VM ranges (`172.30.0.0/16`, which holds `apps`, the app networks and `verifier`, and `172.31.0.0/24`) are counted as `ip-vm-internal`, not `ip-private` (D-064). Counts per allowlist entry, with a fixed vocabulary for everything else, are the only egress data that leaves the VM, and counts sent to the platform are rounded down to two significant figures (D-065).
- Capabilities: app services drop `NET_RAW`, `AUDIT_WRITE`, `MKNOD` and `SETFCAP`; every service has `no-new-privileges`; sealed-init, sealed-egress, the payer and verifierd drop `ALL`, Caddy keeps only `NET_BIND_SERVICE`, and sealed-agent drops `NET_RAW` and adds `SYS_ADMIN` for the data disk. The `NET_RAW` drop is load-bearing: on a real Docker engine, a container with Docker's default capabilities forged a DNS query from the agent's address on its app network and sealed-egress counted it for the agent, while without `NET_RAW` every forging path failed. Docker's internal-network rules also confine a forged source to the container's own app network. Proxy credentials (`proxyAuth`) exist in sealed-egress but stay off: identity is the source address on separate networks with `NET_RAW` dropped.
- Host rules (`pre_launch_script`, measured) drop anything forwarded from the edge subnet to outside the VM unless it comes from sealed-egress. They also drop traffic from the container ranges (`172.30.0.0/16`, `172.31.0.0/24`) and from every `sealed-+` bridge to any VM address, except replies to connections the VM opened, so no container reaches the dstack guest agent's `8090` listener or anything else on the VM itself (D-064, host rules v3). Docker's embedded DNS answers inside each container's own namespace and published ports arrive through forwarding, so the stack needs nothing on the VM's input path. They fail closed when they cannot be verified. Every container on two or more networks (sealed-egress, Caddy, the agent, the payer, every primary) runs with `net.ipv4.ip_forward=0`, so none routes packets between its networks.
- Bootstrap firewall rules: ingress TCP 80 and 443 to tagged Sealed VMs only; egress TCP 443 and 53 only, then deny all.

## Ingress and the password gate (D-044, D-045)

Caddy terminates TLS inside the VM with keys generated there. Hostnames are `<route>.<ip-with-dashes>.sslip.io` or customer domains. Routes: `gateway`, `scraper`, `crm`, `code`, `tools`, and `attest`.

- `gate` routes: Caddy runs `forward_auth sealed-agent:7070` with `uri /v1/gate?route=<route>`. The agent answers 200 for a valid `sealed_gate` cookie (HMAC-SHA256 with a per-boot key, 12 hours, `HttpOnly; Secure; SameSite=Lax`) or for Basic auth as user `sealed` whose password matches the bcrypt hash released by the key broker; a Basic success sets the cookie (a 303 for browser navigations). Otherwise 401 with a Basic challenge, 429 under brute force, and 503 `starting` until the app's bootstrap job has finished, so no app is reachable half configured.
- Caddy strips the gate's own Basic credentials and the `sealed_gate` cookie before proxying, so an app's own `Authorization` header (for example a Bearer token) passes untouched and no app can replay the gate cookie.
- `bearer-passthrough` (only llm-gateway `gateway`): Caddy asks the gate in bearer mode (`/v1/gate?route=<route>&bearer=1`, review C-6, since 1.4.0), which holds bearer requests with 503 `starting` while the keys are not released or the gateway's bootstrap runs, then passes them with their `Authorization` header unchanged, so LiteLLM checks every key itself; anything else on that route is gated.
- `public`: only `attest` and the relay's `relay` route. A manifest cannot turn the gate off for any other route; the composer rejects it.
- `attest` proxies `sealed-agent:7070/attest`, which returns a fresh quote over `sha256("sealed/attest/v1" || nonce || tlsPubKeyHash || enclaveSigner)`, so a caller learns that the TLS key it is talking to belongs to the attested VM.
- The relay route sets `on_attest_host: true`: the relay's `/v1` API is served on its attest host, the same origin and certificate as `/attest` (D-045).
- The payment-needed switch: the agent loads the measured `Caddyfile.payment-needed` through Caddy's admin socket (group 10001, mode 0660, on a tmpfs). App hosts then answer 402 with a static page; `/attest` and the data are untouched.

## Secrets inside the VM (D-042, D-043, D-059)

- The key broker returns only the secrets named in the manifests of the stack's releases, plus the gate's bcrypt hash. Secret Manager names are `sealed-<app>-<NAME>` and `sealed-gate-password`.
- `same_as: "<appId>/<NAME>"` lets one app use another app's secret (for example a gateway key), but only when the source secret's own manifest entry lists the referencing app in `share_with: [<appId>]` (D-059). llm-gateway's `APP_KEY_CODING_AGENT` declares `share_with: [coding-agent]`. The composer, the key broker and the CLI each enforce this. The referenced app must be in the stack; the broker returns the value under the referencing app's name.
- The agent writes each secret file to the host's `/run` tmpfs. Each service gets read-only bind mounts of exactly the files it lists in `x-sealed-secrets`, never a directory. The agent refuses to boot if the measured compose would let a service see another owner's secrets.
- envexec waits for `/run/sealed/ready/ok`, exports only the declared names, and execs the app. Caddy holds no secret.

## Data at rest (D-017, D-058)

- dstack's own system disk uses `key_provider: tpm`: its seed is sealed in the Google Cloud vTPM. It holds container images and container layers.
- App data lives on a separate persistent disk, `sealed-data`, which survives the VM. sealed-agent formats and opens it with LUKS2 (aes-xts-plain64, 512-bit) using keys derived from the broker's `diskKey`, and checks the header and the device-mapper table before mounting, so a header the host prepared can never be mounted. Every app volume, Caddy's certificate store and the agent's state are directories on it. Because `diskKey` depends only on the customer and the config's salt (D-058), the disk survives stack upgrades. A Google Cloud stop is not a clean shutdown, so the volume is ext4 with journaling and recovers its journal at the next boot (seen in the runtime spike, D-052).
- The system disk seed survives a stop and start of the same VM (confirmed on C3 TDX, D-052).
- The agent is the only container with the dstack socket, the data-disk device and `CAP_SYS_ADMIN`. The composer rejects privileged mode, devices, host networking, extra capabilities, bind mounts and any socket mount in app fragments.

## Payments

All amounts are FEE_TOKEN base units: USDC.e, 6 decimals (D-035). Prices come from `config/defaults.yaml`: $0.20 per 1M gateway tokens, $0.20 per 1,000 scraped pages, $0.05 per app-hour for crm, coding-agent and internal-tools, and relay inference at provider list price plus 5%.

1. Metering. llm-gateway posts token counts from a LiteLLM callback, the scraper posts successful page counts, and the agent counts app-hours of heartbeat apps from container health. Only counts and model names reach the agent; prompts and outputs never leave the gateway.
2. Usage reports. Each settlement interval (60 minutes, 5 in tests) the agent closes a period and signs an EIP-712 `UsageReport` with the enclave signer. Its digest is the `usageHash`. The report goes to the platform api, which stores it, refuses a report whose period overlaps a stored one (409), and returns a deployment's stored reports at `GET /v1/deployments/:id/usage-reports` to the enclave signer's signed read. The agent pays only reports the platform accepted. At boot and before each settlement the agent rebuilds its paid ledger from those reports, keeping only the ones that verify against its own enclave signer, and from onchain `usagePaid`. It never signs a report whose period overlaps a period it already signed, so restoring an older copy of the data disk cannot bill a period twice (D-062).
3. Spending. The customer's wallet authorizes the enclave signer as a Tempo access key on the customer account (`AccountKeychain.authorizeKey`) with a spending limit ($2 a day by default) and exactly eight allowed calls, never `allowAnyCalls` (D-026, D-054): the fee token's `approve` to FeeSplitter and `transferWithMemo` to the treasury (MPP charges), FeeSplitter's `payFees` and `topUpFees`, and the TIP-1034 escrow's `open`, `topUp`, `requestClose` and `withdraw` (MPP sessions). The keychain cannot bind a payee on the escrow calls, so the payer's firewall enforces the treasury as the channel payee. The console and the api build this authorization with one helper (`buildAccessKeyAuthorization` in `@sealed/core`). FeeSplitter sees the customer as `msg.sender`. Because the enclave signer survives stack upgrades (D-058), the authorization does too. The fallback mode pays from the enclave signer's own balance. The console warns when the selected apps' app-hour fees exceed the limit: a full stack costs 3.60 USD per day (D-067).
4. Settlement. One Tempo transaction per batch: `approve(FeeSplitter, exact total)`, one `payFees` per leg, and `topUpFees` for any leg someone paid short, ending with the allowance back at zero. A leg counts as paid only when `usagePaid(deploymentId, usageHash, appId)` reaches the report's fee (contract review V-1). FeeSplitter enforces $5 per payment and $20 per deployment per UTC day, credits 20% (`maintainerShareBps` 2000) to the app's maintainer and the rest to the treasury, and both withdraw with `withdraw(token)`.
5. Failure. Billing fails closed for failures on the customer's side (a missing, revoked or expired access key, an exhausted limit, too little balance, a reverted payment, an unreadable chain): when they last the grace period (24 hours, 5 minutes in tests), the agent switches app routes to the payment-needed page; data stays intact, and the routes come back after the next successful settlement. A platform outage never does that (D-073): while the platform api cannot be reached or has not accepted a report, settlement is deferred, the grace period does not run, and the deferred fees are paid once the platform is back.

## The inference relay (D-045, D-048, D-061, D-067)

- The relay is an ordinary Sealed stack (`inference-relay`) in a confidential VM in the platform project, with its own key broker. OWNER is the customer that approves its stack, and it has its own onchain record.
- Services: `inference-relay-front` (mppx server, Tempo payment method, payee the treasury `0x755a1e289503c7109d01a74ed253ba0f724ca3eb`, currency USDC.e), its Postgres session store, LiteLLM holding the platform's provider keys, and one verification sidecar per attested provider (Tinfoil, with Phala and NEAR AI behind their allowlists; Privatemode is dropped, D-055). A provider is used only while its own attestation verifies; otherwise the relay answers `503 attestation_failed` before any payment.
- Customer side: llm-gateway routes `relay/<model>` to sealed-mpp-payer, with `max_retries: 0` on those routes so a failed paid request is not paid again (D-067). Before first use and every 15 minutes the payer fetches the relay's `/attest` with a fresh nonce over TLS, records the certificate's key, and submits that attestation to the in-VM sealed-verifierd (which fetches nothing itself) to check: quote, image, a stack approved by OWNER, active releases (recomputed from bundles fetched from the release asset hosts, D-061), and the relay app only. Prompts and payments then go only over TLS connections that present the attested key. The payer gets a `stop_grace_period` of 60 seconds (D-067 asks for at least 45), so it can close its session cleanly. Its payment firewall accepts only the attested treasury as payee, only FEE_TOKEN and only the TIP-1034 escrow, because the access key cannot carry a payee rule on the escrow calls (D-054a).
- Payment: MPP sessions over the TIP-1034 escrow with per-token charging, falling back to per-request charges priced from prompt tokens plus `max_tokens`. A per-request charge is deferred: the relay validates the payer's signed transaction, calls the upstream, and broadcasts the charge only after the upstream's first byte, so an upstream that fails or stays silent costs nothing (`charged: false`). A request that fails after it was paid gets 424 `relay_failed_after_payment` from the payer, which LiteLLM and the OpenAI SDKs do not retry.
- Shared budget (D-048): fee settlement and the payer draw on one budget. In access-key mode it follows the key's onchain remaining limit and period (`getRemainingLimit`); in enclave-account mode it is the config's daily limit. The payer reserves through `POST /v1/spend/reserve` and releases through `/v1/spend/release`; it may use at most what remains after fees spent, payer spend, open reservations and the fees reserved for the rest of the window (unpaid legs, the open period, app-hours until the window ends and the later settlements' network fees). Fee settlement is never blocked by the payer. No reservation, no payment.

## Determinism and versions

- Canonical JSON (sorted ASCII keys, integers only, no insignificant whitespace) has one Go implementation (`runtime/composer/cjson`) and a TypeScript twin in `@sealed/core`, both tested on shared vectors.
- The composer exists once, in Go (D-006); the key broker, `sealed verify`, verifierd and release CI all use it. Any change to composed bytes needs a new composer version, because approved stacks pin the old bytes. The config names its `composerVersion`, and a composer refuses any other.
- Images are referenced only by digest from the catalog registry `ghcr.io/sealedtempo`. Release bundles are deterministic ustar archives, so `sealed release build <app>` reproduces a published bundleHash.

## Contracts

| contract | job |
|---|---|
| PlatformRegistry | measured OS images: MRTD and RTMR0 to RTMR2 hashed onchain, debug flag, Active, Deprecated or Revoked |
| AppRegistry | apps (owner) and releases (registrar role): bundleHash, egressPolicyHash, sbomHash, provenance and signature URIs |
| DeploymentRegistry | stack approvals by customers, attested deployment records, heartbeats, close; one pluggable verifier per attestation method |
| OracleSignatureVerifier | method 1: an allowed oracle signer's signature over the EIP-712 record digest |
| FeeSplitter | per-app fee payments from a deployment's customer or enclave signer, caps, maintainer and treasury credits, pull withdrawals |

All five are non-upgradeable and store only hashes and addresses for deployments (P6). Addresses are in the [README](../README.md#contracts-on-tempo-mainnet) and `contracts/deployments/tempo-mainnet.json`.

## Security properties

| id | property | enforced by |
|---|---|---|
| P1 | Only stacks the customer's wallet approved onchain, built only from active releases, on an approved non-debug image, receive the customer's secrets | key broker checks, read from a chain head at most 60 seconds old (D-060); DeploymentRegistry, PlatformRegistry, AppRegistry |
| P2 | Production VMs have no shell, no SSH daemon, no serial console login and no cloud service account; app containers cannot reach the metadata server | dstack production image; VM settings; egress deny rules |
| P3 | App containers have no direct internet route; all outbound goes through the measured allowlist, with allowed and blocked counts per destination | internal Docker networks; sealed-egress; `NET_RAW` dropped; `ip_forward=0` on multi-homed containers; host rules, including the INPUT drop toward the VM's own listeners (D-064); verifierd on its own network (D-061); firewall |
| P4 | The platform's deployer account can create, stop and delete VMs, but cannot read secrets, change the key broker or get a shell | custom IAM roles with resource-name conditions; IAM checks |
| P5 | Only content-free data leaves the VM toward the platform: health, counts, signed usage totals, attestation evidence | agent API surface; egress stats vocabulary; counts rounded down to two significant figures (D-065; the residual channel through counts is described in [THREAT_MODEL.md](THREAT_MODEL.md#residual-risks)) |
| P6 | Onchain records hold only hashes and addresses | contract storage layout |
| P7 | Anyone can re-verify a deployment without trusting the platform | `sealed verify` with an evidence bundle and a Tempo RPC |

How each property can fail, and what is not covered, is in [THREAT_MODEL.md](THREAT_MODEL.md).
