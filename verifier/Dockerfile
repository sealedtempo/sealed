# sealed-verifierd. Build from the repository root:
#   docker build -f verifier/Dockerfile -t sealed-verifierd .
# Base images are pinned by digest (docs/notes/go-tdx-egress.md section 8). The binary is static (CGO off, so
# go-ethereum uses the pure-Go secp256k1) and runs as nonroot on distroless.
FROM golang:1.27.3-trixie@sha256:7b072c590a326b9d2a43b165ae247f6e8eafff32e1ad154ab97139e89f053be9 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' \
    -o /out/sealed-verifierd ./verifier/cmd/sealed-verifierd

FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
COPY --from=build /out/sealed-verifierd /sealed-verifierd
COPY config/defaults.yaml /etc/sealed/defaults.yaml
ENV SEALED_DEFAULTS_FILE=/etc/sealed/defaults.yaml \
    SEALED_VERIFIERD_LISTEN=:8088
USER nonroot:nonroot
EXPOSE 8088
ENTRYPOINT ["/sealed-verifierd"]
