# sealed-egress image. Build from the repository root:
#   docker build -f runtime/egress/Dockerfile -t sealed-egress .
# For a reproducible image digest (not just a reproducible binary), pin the
# layer timestamps too:
#   SOURCE_DATE_EPOCH=0 docker buildx build -f runtime/egress/Dockerfile \
#     --build-arg SOURCE_DATE_EPOCH=0 \
#     --output type=image,name=sealed-egress,rewrite-timestamp=true .
# Base images are pinned by index digest (rechecked with `crane digest` on
# 2026-10-28). The binary is reproducible: CGO off, -trimpath,
# -buildvcs=false, empty build id, and only go.mod, go.sum and
# runtime/egress are copied in.
FROM --platform=$BUILDPLATFORM golang:1.27.3-trixie@sha256:7b072c590a326b9d2a43b165ae247f6e8eafff32e1ad154ab97139e89f053be9 AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG SOURCE_DATE_EPOCH
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly
WORKDIR /src
COPY go.mod go.sum ./
COPY runtime/egress/ runtime/egress/
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
      -trimpath -buildvcs=false \
      -tags smokescreen_no_prometheus \
      -ldflags="-s -w -buildid=" \
      -o /out/sealed-egress ./runtime/egress/cmd/sealed-egress
# License and notice files of every linked module and of Go itself (MIT and
# BSD need the notice in binary redistributions, Apache-2.0 the text).
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH sh runtime/egress/build/collect-licenses.sh /out/licenses
# Mount point for the proxy credential volume (see runtime/egress/README.md).
# A new named volume copies this directory's owner, so nonroot can write it.
RUN mkdir -p /out/auth

FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
ARG SOURCE_DATE_EPOCH
COPY --from=build /out/sealed-egress /sealed-egress
COPY --from=build /out/licenses/ /licenses/
COPY --from=build --chown=65532:65532 /out/auth /run/sealed-egress/auth
USER nonroot:nonroot
# Port 53 binds as nonroot because Docker sets
# net.ipv4.ip_unprivileged_port_start=0 in container network namespaces.
EXPOSE 3128/tcp 53/udp 53/tcp 9100/tcp
HEALTHCHECK --interval=10s --timeout=3s --retries=3 CMD ["/sealed-egress", "-healthcheck"]
ENTRYPOINT ["/sealed-egress"]
