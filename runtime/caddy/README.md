# runtime/caddy

`Caddyfile.tmpl` and `payment-needed.html`, embedded by the Go package in this directory and rendered by the composer (`runtime/composer`). Both Caddyfile variants and the page are passed to the stack as inline compose configs, so they are part of stackHash.

- Normal variant: one site per route hostname. `gate` routes sit behind `basic_auth` (user `sealed`, bcrypt hash from the `GATE_PASSWORD_BCRYPT` secret exported by envexec); `bearer-passthrough` routes send `Authorization: Bearer` requests straight to the app and gate everything else; `public` routes are open. The template renders any mode; the composer allows `bearer-passthrough` only for `llm-gateway` route `gateway` and `public` only for `inference-relay` route `relay`, so every other app UI is gated. The `attest` site is public and proxies `sealed-agent:7070/attest`.
- The Caddy container drops every capability except `NET_BIND_SERVICE` (the image's `caddy` binary carries it as a file capability, and exec fails without it in the bounding set) and runs with `no-new-privileges`.
- Payment-needed variant: every app host serves the static page with status 402 and bearer API calls get a plain 402; attest is unchanged. sealed-agent switches by `POST /load` (`Content-Type: text/caddyfile`) on the admin socket `/run/sealed/caddy-admin/admin.sock`, and restores by loading the normal file.

Pinned image: `caddy:2.11.7-alpine` (index `sha256:eb4d35b7...`, Apache-2.0), mirrored to the catalog registry; see `runtime/composer/runtime-images.json`. The page uses only plain product wording, no external resources and no em-dashes. Tests: `go test ./runtime/caddy`, plus the optional real-Caddy run in `runtime/composer` (`SEALED_CADDY_BIN`).
