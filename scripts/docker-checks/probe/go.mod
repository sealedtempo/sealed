// Network probe for scripts/docker-checks. A separate module (stdlib only,
// no go.sum) so the root module's ./... never builds this linux-only tool.
module sealed-docker-checks/probe

go 1.24
