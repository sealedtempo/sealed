# Sealed key broker for Cloud Run. Build from the repository root:
#   docker build -f key-broker/Dockerfile -t sealed-key-broker .
# Base images are pinned by index digest (docs/notes/go-tdx-egress.md section 8, the same pins as verifier/Dockerfile).
# The binary is static (CGO off) and built WITHOUT build tags: the sealeddev tag, simulated quotes and the local
# fakes can never be part of this image (key-broker/cmd/key-broker TestDockerfileIsProduction checks this file).
# /licenses holds the license and notice files of every linked Go module and of Go itself, and a README with the
# GNU LGPL notice for go-ethereum and where the corresponding source is (key-broker/third_party/README.md). Pass
# --build-arg SOURCE_REF=<commit or tag> so that the README names the exact source tree; without it, the README
# names the repository and the release that publishes the image.
ARG SOURCE_URL=https://github.com/sealedtempo/sealed
ARG SOURCE_REF=

FROM golang:1.27.3-trixie@sha256:7b072c590a326b9d2a43b165ae247f6e8eafff32e1ad154ab97139e89f053be9 AS build
# One target for the binary and the license collector, so both see the same module set.
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' \
    -o /out/key-broker ./key-broker/cmd/key-broker
# Declared after the build so that a new SOURCE_REF does not invalidate the cached binary layer.
ARG SOURCE_URL
ARG SOURCE_REF
RUN DOCKERFILE=key-broker/Dockerfile sh key-broker/third_party/collect-licenses.sh /out/licenses ./key-broker/cmd/key-broker

FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
ARG SOURCE_URL
LABEL org.opencontainers.image.source=$SOURCE_URL
COPY --from=build /out/key-broker /key-broker
COPY --from=build /out/licenses/ /licenses/
ENV PORT=8080
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/key-broker"]
