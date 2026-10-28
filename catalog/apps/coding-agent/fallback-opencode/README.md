# coding-agent: OpenCode fallback

OpenCode 1.19.5 (MIT) in server mode, as the spec 6.5 fallback for OpenHands. It is **not** part of
the default `coding-agent` release; the release CI only reads the files at
`catalog/apps/coding-agent/`. This directory keeps a complete, tested variant ready to switch in.

## What is here

| file | purpose |
|---|---|
| `manifest.yaml` | `coding-agent` manifest for the OpenCode variant (route `code` -> port 4096) |
| `compose.fragment.in.yaml` -> `compose.fragment.yaml` | one service, `coding-agent-server` (the primary service of both variants); regenerate with `../tools/build_fragment.py` |
| `egress.yaml`, `waivers.yaml` | no egress by default; no waivers |
| `images/opencode/Dockerfile` | thin image FROM the pinned OpenCode digest adding bash, git, python3 and uid 10001 |
| `app-README.md` | the app README after the switch |
| `switch.sh` | copies this variant over the app's release files and README |

## How it is wired

`coding-agent-server` runs as uid 10001 from the start (the workspace volume declares
`x-sealed-owner: "10001:10001"`, and sealed-agent creates it with that owner). It runs
`bootstrap/prepdirs.py` (workspace directories, no_new_privs, change to `/workspace/project`), then
`bootstrap/authproxy.py`, which runs OpenCode on 127.0.0.1:4097 and serves the API on :4096 to callers
with the session key `CODE_SESSION_API_KEY` (`X-Session-API-Key`, or `Authorization: Bearer`, which
passes the gate untouched once the client uses the `sealed_gate` cookie). The proxy authenticates to
OpenCode with OpenCode's own generated password (`OPENCODE_SERVER_PASSWORD`) and drops every client
`Authorization` header and the `sealed_gate` cookie. See `app-README.md` for the details.

Earlier drafts reused the password gate's password as OpenCode's password so one Basic header would
pass both. That would hand the gate password, which protects every app UI, to the agent's shell, and a
browser keeps sending the gate's Basic credentials after it logged in, so the proxy must drop them
rather than pass them on. It is gone.

The gateway key `LLM_GATEWAY_KEY` refers to llm-gateway's `APP_KEY_CODING_AGENT` (`same_as`), from which
llm-gateway provisions the key. This variant has no bootstrap job and never holds the gateway master key.

## Switch

```sh
catalog/apps/coding-agent/fallback-opencode/switch.sh
```

It copies `manifest.yaml`, `compose.fragment.in.yaml`, `egress.yaml`, `waivers.yaml` and
`app-README.md` (as `README.md`) over the app's files, copies `images/opencode` to
`catalog/apps/coding-agent/images/opencode` (so `build:images/opencode` resolves), and regenerates
`compose.fragment.yaml`. Then run the app tests: every test class checks the variant the app holds
and skips the other, and `test_switch_script` already runs the whole suite on a switched copy. Build
the image, pin its digest in `manifest.yaml` (D-028), store the secrets, and open a PR. To return to
OpenHands, revert that commit.

A6 for this variant: `scripts/a6-coding-agent.sh --target opencode --url https://code.<ip>.sslip.io
--session-key "$CODE_SESSION_API_KEY" --gate-password "$GATE_PASSWORD"` (gate login once, then the
`sealed_gate` cookie).
