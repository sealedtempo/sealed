# sealed-init image: the static envexec binary on an empty base. sealed-init
# runs "/envexec install /sealed/bin" to copy it into the shared volume.
# Build from the repository root:
#   docker buildx build --platform linux/amd64 -f runtime/envexec/Dockerfile .
# The build stage runs on the build machine and cross-compiles for the
# requested platform (TARGETOS and TARGETARCH from BuildKit, docker-checks
# bug 4); production images are linux/amd64. dockerfile_test.go checks that
# the copied sources cover every package of this module the binary imports.
FROM --platform=$BUILDPLATFORM golang:1.27.3-trixie@sha256:7b072c590a326b9d2a43b165ae247f6e8eafff32e1ad154ab97139e89f053be9 AS build
ARG TARGETOS
ARG TARGETARCH
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly
WORKDIR /src
COPY go.mod go.sum ./
COPY runtime/envexec ./runtime/envexec
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o /out/envexec ./runtime/envexec

FROM scratch
COPY --from=build /out/envexec /envexec
ENTRYPOINT ["/envexec"]
