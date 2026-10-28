# envexec

Static Go entrypoint wrapper for every Sealed app container (INTERFACES section 14). The composer rewrites each service's entrypoint to:

```
/sealed/bin/envexec --app <appId> [--secret NAME]... [--optional-secret NAME]... -- <original entrypoint...>
```

envexec waits until `/run/sealed/ready` is open (a regular file, or the shared tmpfs directory containing `ok`), exports each declared secret from `/run/sealed/secrets/<appId>/<NAME>` as an environment variable with its exact bytes, and `exec`s the original command with the container's environment. A missing required secret is an error; a missing optional one is skipped. The filter applies to the environment only: the app's whole secrets directory is mounted read-only into every service that declares secrets, so secrets are scoped per app, not per service. Services without secrets still wait for the gate. It never logs secret values.

Other modes:

- `envexec install <dir>`: copies itself to `<dir>/envexec` (mode 0755, atomic rename). `sealed-init` runs `/envexec install /sealed/bin` to fill the shared `sealed-bin` volume.
- `envexec probe tcp://host:port` or `probe http://host:port/path`: image-independent healthcheck (exit 0 on connect, or on an HTTP status below 400); ignores proxy settings.

Build the `sealed-init` image with `runtime/envexec/Dockerfile` (static, `FROM scratch`). Tests: `go test ./runtime/envexec`.
