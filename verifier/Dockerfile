# sealed-verifierd. Build from the repository root:
#   docker build -f verifier/Dockerfile -t sealed-verifierd .
# Base images are pinned by digest (docs/notes/go-tdx-egress.md section 8). The binary is static (CGO off, so
# go-ethereum uses the pure-Go secp256k1) and runs as nonroot on distroless.
# /licenses holds the license and notice files of every linked Go module and of Go itself, and a README with the
# GNU LGPL notice for go-ethereum and where the corresponding source is (verifier/third_party/README.md). Pass
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
    -o /out/sealed-verifierd ./verifier/cmd/sealed-verifierd
# Declared after the build so that a new SOURCE_REF does not invalidate the cached binary layer.
ARG SOURCE_URL
ARG SOURCE_REF
RUN DOCKERFILE=verifier/Dockerfile sh verifier/third_party/collect-licenses.sh /out/licenses ./verifier/cmd/sealed-verifierd

FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
ARG SOURCE_URL
LABEL org.opencontainers.image.source=$SOURCE_URL
COPY --from=build /out/sealed-verifierd /sealed-verifierd
COPY --from=build /out/licenses/ /licenses/
COPY config/defaults.yaml /etc/sealed/defaults.yaml
ENV SEALED_DEFAULTS_FILE=/etc/sealed/defaults.yaml \
    SEALED_VERIFIERD_LISTEN=:8088
USER nonroot:nonroot
EXPOSE 8088
ENTRYPOINT ["/sealed-verifierd"]
