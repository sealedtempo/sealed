# coding-agent (OpenCode)

A headless coding agent for your stack: OpenCode 1.19.5 in server mode (MIT), the spec 6.5
fallback for the OpenHands release. The agent's shell and file edits run inside its own container
on the apps network, as uid 10001 with no_new_privs. Its LLM is `llm-gateway`, so tokens are
metered there and this app is metered per app hour.

Requires `llm-gateway` in the same stack.

This README is installed by `fallback-opencode/switch.sh`; the source is
`fallback-opencode/app-README.md`.

## Service

`coding-agent-server` (alias `coding-agent`) is the only service:

1. `bootstrap/dropuid.py` (as root) hands the workspace volume to uid 10001, sets no_new_privs and
   drops privileges.
2. `bootstrap/authproxy.py` starts `opencode serve --hostname 127.0.0.1 --port 4097` and serves
   the API on port 4096. Every request needs `X-Session-API-Key: <CODE_SESSION_API_KEY>`, except
   `GET /global/health`. The proxy adds OpenCode's own Basic auth (user `opencode`, password
   `OPENCODE_SERVER_PASSWORD`) and drops any client `Authorization` header. `/global/upgrade` and
   WebSocket upgrades are refused. Responses stream, so `GET /event` works.

Why a proxy: Caddy's password gate strips `Authorization` before proxying, so OpenCode's own Basic
auth cannot pass the gate, and the gate password must never be given to the agent (it protects
every app UI). Both scripts are embedded verbatim in `compose.fragment.yaml`.

`OPENCODE_CONFIG_CONTENT` defines one provider, `litellm` (`@ai-sdk/openai-compatible`,
`http://llm-gateway:4000/v1`, key `{env:LLM_GATEWAY_KEY}`), with models `relay-default` (id
`relay/default`, the default; the gateway answers it from the local model when the relay fails)
and `local-qwen3-4b` (the small model). `permission: allow` makes it headless. Autoupdate, the
models.dev fetch, LSP downloads, default plugins and `.claude` discovery are off. Sessions persist
under `/workspace/.opencode` on the encrypted data disk.

## Secrets

| name | generate | notes |
|---|---|---|
| `LLM_GATEWAY_KEY` | none | this app's gateway virtual key; must equal llm-gateway's `APP_KEY_CODING_AGENT`, from which the gateway's keys job provisions it (alias `coding-agent`, models `relay/*` and `local/*`, rate limited) |
| `CODE_SESSION_API_KEY` | hex32 | API key for the code route (`X-Session-API-Key`); removed from OpenCode's environment |
| `OPENCODE_SERVER_PASSWORD` | hex32 | OpenCode's own password, used only on loopback; never the gate password |

No service of this app holds the gateway master key. The composer mounts all of this app's secrets
into its container, so the agent's shell can read them; none of them grants more than the agent
already has (its own scoped gateway key and access to itself).

## API

```sh
curl -u "sealed:$GATE_PASSWORD" -H "X-Session-API-Key: $CODE_SESSION_API_KEY" \
  https://code.<ip>.sslip.io/session
```

## Acceptance test A6

```sh
catalog/apps/coding-agent/scripts/a6-coding-agent.sh --target opencode --url https://code.<ip>.sslip.io \
  --session-key "$CODE_SESSION_API_KEY" --gate-password "$GATE_PASSWORD" \
  --gateway-admin-key "$LITELLM_MASTER_KEY" --gateway-check-url https://gateway.<ip>.sslip.io
```

The reply's token counters must be non-zero; with the gateway options, llm-gateway's spend logs for
alias `coding-agent` must also show tokens since the run started (required when the reply carries no
counters).

## Egress

None by default. Add git hosts and package registries as customer egress additions for
`coding-agent`.

## Going back to OpenHands

Revert the commit that ran `switch.sh`.
