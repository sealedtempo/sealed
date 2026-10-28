# Stand-in app image for scripts/docker-checks: busybox (shell, ip, wget)
# plus the static probe tool and a CA bundle. Build context: scripts/docker-checks/probe.
FROM --platform=$BUILDPLATFORM golang:1.27.3-trixie@sha256:7b072c590a326b9d2a43b165ae247f6e8eafff32e1ad154ab97139e89f053be9 AS build
ARG TARGETOS
ARG TARGETARCH
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly
WORKDIR /src
COPY go.mod main.go ./
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /out/probe .

FROM busybox:1.37.0@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e
COPY --from=build /out/probe /probe
# busybox has no CA bundle; the probe verifies TLS through the proxy.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
