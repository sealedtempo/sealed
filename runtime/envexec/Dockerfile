# sealed-init image: the static envexec binary on an empty base. sealed-init
# runs "/envexec install /sealed/bin" to copy it into the shared volume.
FROM golang:1.27.3-trixie@sha256:7b072c590a326b9d2a43b165ae247f6e8eafff32e1ad154ab97139e89f053be9 AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY runtime/envexec ./runtime/envexec
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o /out/envexec ./runtime/envexec

FROM scratch
COPY --from=build /out/envexec /envexec
ENTRYPOINT ["/envexec"]
