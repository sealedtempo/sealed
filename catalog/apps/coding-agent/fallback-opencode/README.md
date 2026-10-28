# coding-agent: OpenCode fallback

OpenCode 1.19.5 (MIT) in server mode, as the spec 6.5 fallback for OpenHands. It is **not** part of
the default `coding-agent` release; the release CI only reads the files at
`catalog/apps/coding-agent/`. This directory keeps a complete, tested variant ready to switch in.

## What is here

| file | purpose |
|---|---|
| `manifest.yaml` | `coding-agent` manifest for the OpenCode variant (route `code` -> port 4096) |
| `compose.fragment.in.yaml` -> `compose.fragment.yaml` | same service names as the OpenHands fragment; regenerate with `../tools/build_fragment.py` |
| `egress.yaml`, `waivers.yaml` | no egress by default; no waivers |
| `images/opencode/Dockerfile` | thin image FROM the pinned OpenCode digest adding bash, git, python3 and uid 10001 |
| `switch.sh` | copies this variant over the app's release files |

## How it is wired

- `coding-agent-bootstrap` (root, then uid 10001 via `bootstrap/dropuid.py`) runs `bootstrap/seed.py`
  in `key-file` mode: it waits for llm-gateway, creates the virtual key `coding-agent`, and writes it
  to `/workspace/.sealed/llm-gateway-key` (0600).
- `coding-agent-server` waits for the bootstrap job, exports the key as `LITELLM_API_KEY` and runs
  `opencode serve --hostname 0.0.0.0 --port 4096`. `OPENCODE_CONFIG_CONTENT` defines one provider,
  `litellm` (`@ai-sdk/openai-compatible`, `http://llm-gateway:4000/v1`, key `{env:LITELLM_API_KEY}`),
  with models `relay-default` (id `relay/default`, the default) and `local-qwen3-4b`
  (id `local/qwen3-4b`, the small model). `permission: allow` makes it headless.
- Off: autoupdate (`autoupdate:false`, `OPENCODE_DISABLE_AUTOUPDATE=1`), the models.dev fetch
  (`OPENCODE_DISABLE_MODELS_FETCH=1`), LSP downloads (`OPENCODE_DISABLE_LSP_DOWNLOAD=1`), default
  plugins (`OPENCODE_DISABLE_DEFAULT_PLUGINS=1`), `.claude` discovery (`OPENCODE_DISABLE_CLAUDE_CODE=1`),
  sharing (`share: disabled`).
- Sessions and state persist under `/workspace/.opencode` (XDG dirs on the volume).

## Auth behind the password gate

OpenCode protects every route, including `/global/health`, with HTTP basic auth
(`OPENCODE_SERVER_USERNAME=sealed`, password from the `OPENCODE_SERVER_PASSWORD` secret). Caddy's
password gate also uses basic auth, and a client can send only one `Authorization` header. Set
`OPENCODE_SERVER_PASSWORD` to the same value as the gate password, so the same header passes both.
The gate's basic_auth user must be `sealed` (to confirm with the Caddy config owner).

## Switch

```sh
catalog/apps/coding-agent/fallback-opencode/switch.sh
```

It copies `manifest.yaml`, `compose.fragment.in.yaml`, `egress.yaml` and `waivers.yaml` over the
app's files, copies `images/opencode` to `catalog/apps/coding-agent/images/opencode` (so
`build:images/opencode` resolves), and regenerates `compose.fragment.yaml`. Then build the image,
pin its digest in `manifest.yaml` (D-028), store `OPENCODE_SERVER_PASSWORD`, run the tests, and open a
PR. To return to OpenHands, revert that commit.

A6 for this variant: `scripts/a6-coding-agent.sh --target opencode --url https://code.<ip>.sslip.io --gate-password ...`.
