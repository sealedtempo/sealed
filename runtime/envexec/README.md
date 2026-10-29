# envexec

Static Go entrypoint wrapper for every Sealed app container (INTERFACES section 14). The composer rewrites each service's entrypoint to:

```
/sealed/bin/envexec --app <appId> [--secret NAME]... [--optional-secret NAME]... -- <original entrypoint...>
```

envexec waits until `/run/sealed/ready` is open (a regular file, or the shared tmpfs directory containing `ok`), exports each declared secret from `/run/sealed/secrets/<appId>/<NAME>` as an environment variable with its exact bytes, and `exec`s the original command with the container's environment. The composer bind-mounts exactly the secret files a service lists in `x-sealed-secrets` (read-only, D-042), never the whole directory, so a service can neither read nor export another service's secrets. sealed-agent writes every mounted file before the gate opens, an empty one for an optional secret the customer did not set, because a missing bind source would stop the container. A missing or empty required secret is an error; a missing or empty optional one is not exported. Services without secrets still wait for the gate. It never logs secret values.

Other modes:

- `envexec install <dir>`: copies itself to `<dir>/envexec` (mode 0755, atomic rename). `sealed-init` runs `/envexec install /sealed/bin` to fill the shared `sealed-bin` volume.
- `envexec probe tcp://host:port` or `probe http://host:port/path`: image-independent healthcheck (exit 0 on connect, or on an HTTP status below 400); ignores proxy settings.
- `envexec private <dir> -- <cmd> [args...]`: makes `<dir>` private to the container's user, then `exec`s the command with the container's environment unchanged (no secrets, no ready gate). The directory is opened without following a symlink and must belong to the effective uid (otherwise exit 1 before the command runs); its mode becomes 0700, special bits included. The composer runs sealed-mpp-payer as `envexec private /var/lib/sealed-mpp-payer -- node /app/dist/main.js`: sealed-agent creates the payer's data-disk directory (mode 0755) for uid 1000, and only that owner can change its mode.

Build the `sealed-init` image with `runtime/envexec/Dockerfile` from the repo root (static, `FROM scratch`): `docker buildx build --platform linux/amd64 -f runtime/envexec/Dockerfile .`. The build stage cross-compiles for BuildKit's `TARGETOS` and `TARGETARCH`, so an image built for another platform carries a binary for that platform. Tests: `go test ./runtime/envexec` (including a check of the Dockerfile).
