# Sealed key broker for Cloud Run. Build from the repository root:
#   docker build -f key-broker/Dockerfile -t sealed-key-broker .
# Base images are pinned by index digest (docs/notes/go-tdx-egress.md section 8, the same pins as verifier/Dockerfile).
# The binary is static (CGO off) and built WITHOUT build tags: the sealeddev tag, simulated quotes and the local
# fakes can never be part of this image (key-broker/cmd/key-broker TestDockerfileIsProduction checks this file).
FROM golang:1.27.3-trixie@sha256:7b072c590a326b9d2a43b165ae247f6e8eafff32e1ad154ab97139e89f053be9 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' \
    -o /out/key-broker ./key-broker/cmd/key-broker

FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
COPY --from=build /out/key-broker /key-broker
ENV PORT=8080
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/key-broker"]
