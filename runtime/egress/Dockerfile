# sealed-egress image. Build from the repository root:
#   docker build -f runtime/egress/Dockerfile -t sealed-egress .
# Base images are pinned by index digest (docs/notes/go-tdx-egress.md section 8,
# rechecked with crane on 2026-10-28). The build is reproducible: CGO off,
# -trimpath, -buildvcs=false, empty build id, and only go.mod, go.sum and
# runtime/egress are copied in.
FROM --platform=$BUILDPLATFORM golang:1.27.3-trixie@sha256:7b072c590a326b9d2a43b165ae247f6e8eafff32e1ad154ab97139e89f053be9 AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly
WORKDIR /src
COPY go.mod go.sum ./
COPY runtime/egress/ runtime/egress/
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
      -trimpath -buildvcs=false \
      -tags smokescreen_no_prometheus \
      -ldflags="-s -w -buildid=" \
      -o /out/sealed-egress ./runtime/egress/cmd/sealed-egress

FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
COPY --from=build /out/sealed-egress /sealed-egress
USER nonroot:nonroot
# Port 53 binds as nonroot because Docker sets
# net.ipv4.ip_unprivileged_port_start=0 in container network namespaces.
EXPOSE 3128/tcp 53/udp 53/tcp 9100/tcp
HEALTHCHECK --interval=10s --timeout=3s --retries=3 CMD ["/sealed-egress", "-healthcheck"]
ENTRYPOINT ["/sealed-egress"]
