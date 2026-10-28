# coding-agent (OpenCode)

A headless coding agent for your stack: OpenCode 1.19.5 in server mode (MIT), the spec 6.5
fallback for the OpenHands release. The agent's shell and file edits run inside its own container
on its own app network, as uid 10001 with no_new_privs. Its LLM is `llm-gateway`, so tokens are
metered there and this app is metered per app hour.

Requires `llm-gateway` in the same stack.

This README is installed by `fallback-opencode/switch.sh`; the source is
`fallback-opencode/app-README.md`.

## Service

`coding-agent-server` (alias `coding-agent`) is the only service:

The service runs as uid 10001 from the start: the workspace volume declares
`x-sealed-owner: "10001:10001"`, and sealed-agent creates it with that owner before the ready gate opens.

1. `bootstrap/prepdirs.py` creates `/workspace/project` and `/workspace/.opencode`, checks
   no_new_privs and changes to `/workspace/project` (the container starts in the volume root, because
   Docker would create a missing working directory as root).
2. `bootstrap/authproxy.py` starts `opencode serve --hostname 127.0.0.1 --port 4097` and serves
   the API on port 4096. Every request needs the session key `CODE_SESSION_API_KEY`, as
   `X-Session-API-Key: <key>` or `Authorization: Bearer <key>`, except `GET /global/health`. The proxy
   adds OpenCode's own Basic auth (user `opencode`, password `OPENCODE_SERVER_PASSWORD`) and drops any
   client `Authorization` header and the gate's `sealed_gate` cookie. `/global/upgrade` and WebSocket
   upgrades are refused. Responses stream, so `GET /event` works.

Why a proxy: the gate password and the gate cookie must never reach the agent, because the gate
protects every app UI. A client logs in to the gate once (Basic auth, user `sealed`) and then sends the
`sealed_gate` cookie, so its own `Authorization: Bearer <session key>` passes the gate untouched; a
browser, however, keeps sending the gate's Basic credentials, which the proxy drops. Both scripts are
embedded verbatim in `compose.fragment.yaml`.

`OPENCODE_CONFIG_CONTENT` defines one provider, `litellm` (`@ai-sdk/openai-compatible`,
`http://llm-gateway:4000/v1`, key `{env:LLM_GATEWAY_KEY}`), with models `relay-default` (id
`relay/default`, the default; the gateway answers it from the local model when the relay fails)
and `local-qwen3-4b` (the small model). `permission: allow` makes it headless. Autoupdate, the
models.dev fetch, LSP downloads, default plugins and `.claude` discovery are off. Sessions persist
under `/workspace/.opencode` on the encrypted data disk.

## Secrets

| name | generate | notes |
|---|---|---|
| `LLM_GATEWAY_KEY` | none, `same_as: llm-gateway/APP_KEY_CODING_AGENT` | this app's gateway virtual key, llm-gateway's `APP_KEY_CODING_AGENT`, from which the gateway's keys job provisions it (alias `coding-agent`, models `relay/*` and `local/*`, rate limited) |
| `CODE_SESSION_API_KEY` | hex32 | API key for the code route (`X-Session-API-Key` or `Authorization: Bearer`); removed from OpenCode's environment |
| `OPENCODE_SERVER_PASSWORD` | hex32 | OpenCode's own password, used only on loopback; never the gate password |

No service of this app holds the gateway master key. Its only service lists all three secrets, so the
agent's shell can read them; none of them grants more than the agent already has (its own scoped
gateway key and access to itself).

## API

```sh
jar="$(mktemp)"
curl -s -o /dev/null -c "$jar" -u "sealed:$GATE_PASSWORD" https://code.<ip>.sslip.io/global/health   # gate login, once
curl -s -b "$jar" -H "Authorization: Bearer $CODE_SESSION_API_KEY" https://code.<ip>.sslip.io/session
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
