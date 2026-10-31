# Third-party licenses in the sealed-verifierd image

`verifier/Dockerfile` runs `collect-licenses.sh` in its build stage, after `go build`, and copies the result to
`/licenses/` in the runtime image. This follows `runtime/egress/Dockerfile` (license audit finding F3). The same
script and test live in `key-broker/third_party/`; keep the two copies identical.

## What `/licenses` holds

| Path | Content |
|---|---|
| `README` | Program, source repository, target, the list of linked modules, the GNU LGPL notice and where the corresponding source is |
| `<module path>/` | The `LICENSE*`, `LICENCE*`, `COPYING*`, `COPYRIGHT*`, `NOTICE*`, `PATENTS*` and `AUTHORS*` files at the root of every linked module, byte for byte from the module cache |
| `<module path>/<dir>/` | The same kinds of file found in a linked package's own directory or a parent below the module root. Today: `go-ethereum/metrics/LICENSE` (BSD-2-Clause-Views, from rcrowley/go-metrics, audit F4) and `go-ethereum/crypto/keccak/LICENSE` (BSD-3-Clause, The Go Authors) |
| `go/` | The Go distribution's `LICENSE` and `PATENTS` (the standard library is linked) |
| `github.com/sealedtempo/sealed/` | This repository's `LICENSE` (Apache-2.0) |

The module set is `go list -deps` of `./verifier/cmd/sealed-verifierd` for the target the build stage sets once
with `ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64`, so it is exactly what the binary links (29 modules on 2026-10-28, with
go-ethereum v1.17.10; 86 on 2026-10-29, with sigstore-go v1.3.0).

## sigstore-go (release signatures, supply-2)

`verifier/releasesig` links github.com/sigstore/sigstore-go v1.3.0 (Apache-2.0), pinned in `go.mod`, into
sealed-verifierd and the `sealed` CLI (not the key broker). With it come 56 modules, none copyleft, checked on
2026-10-29 from each module's root license text:

- Apache-2.0 (43): sigstore-go, sigstore/sigstore, sigstore/rekor, sigstore/rekor-tiles/v2,
  sigstore/timestamp-authority/v2, sigstore/protobuf-specs, theupdateframework/go-tuf/v2, in-toto/attestation,
  in-toto/in-toto-golang, google/certificate-transparency-go, google/go-containerregistry, transparency-dev/formats,
  transparency-dev/merkle, cyberphone/json-canonicalization, opencontainers/go-digest, oklog/ulid/v2, shibumi/go-pathspec,
  go-openapi (analysis, errors, jsonpointer, jsonreference, loads, runtime, runtime/server-middleware, spec, strfmt,
  validate, swag and its 11 submodules), google.golang.org/grpc, genproto googleapis/api and googleapis/rpc,
  k8s.io/klog/v2. go-openapi/runtime ships a NOTICE, which the collector copies.
- MIT (7): asaskevich/govalidator, blang/semver, cenkalti/backoff/v5, digitorus/pkcs7, go-viper/mapstructure/v2,
  secure-systems-lab/go-securesystemslib, youmark/pkcs8.
- BSD-3-Clause (4): google/uuid, grpc-ecosystem/grpc-gateway/v2, golang.org/x/mod, golang.org/x/term.
- BSD-2-Clause (2): digitorus/timestamp, pkg/errors.

The new requirements also raise github.com/gorilla/websocket (BSD-2-Clause, linked through go-ethereum's rpc package)
from v1.4.2 to v1.5.1 in every binary that links it. The tests below run the collector over this set, so a later
version that drops a license text fails them.

## go-ethereum and the LGPL

go-ethereum's library packages are LGPL-3.0-or-later and are linked statically. No `cmd/` package (GPL-3.0) is
linked. What LGPL-3.0 section 4 asks of a Combined Work we convey, and where the image meets it:

- 4(a) prominent notice that the Library is used and is under the LGPL: the notice section of `/licenses/README`.
- 4(b) copies of the GPL-3.0 and LGPL-3.0 texts: `github.com/ethereum/go-ethereum/COPYING` and `COPYING.LESSER`.
- 4(c) does not apply: sealed-verifierd shows no copyright notices while it runs.
- 4(d)(0) the Minimal Corresponding Source and the Corresponding Application Code, conveyed as GPL-3.0 section 6
  allows. Our source is public, so the image uses 6(d), directions next to the object code: the README names the
  application code (`SOURCE_URL`, at `SOURCE_REF` when the build passes it), whose `go.mod` and `go.sum` pin the
  exact library version and hash; the library archive on the Go module proxy; and the commands to relink against a
  modified library (`go mod edit -replace`, then the same build). The `org.opencontainers.image.source` label puts
  the repository link on the registry page too. 6(d) also requires the source to stay available as long as the
  image is offered, so tags and commits that published images were built from must not be deleted.
- 4(e) installation information applies only to User Products, which a container image is not.

No written offer is needed, because the source is published at a network location next to the image.

## What fails the image build

`collect-licenses.sh` exits non-zero, and so does `docker build`, when:

- a linked module has no license text at its root (a module that only has a `NOTICE` or a `README` fails too);
- a linked module is under the GPL or AGPL without the LGPL, or a linked package directory of a non-LGPL module
  carries a GNU license text (both need a recorded decision first);
- an LGPL-3.0 module does not ship the GPL-3.0 text that section 4(b) also requires;
- a module is missing from the module cache, or `go list` fails.

## Checks

```sh
go test ./verifier/third_party/
```

No Docker daemon is needed. The tests run the collector the way the Dockerfile does and compare its output with an
independent `go list -deps` walk: every linked module has a license text, every file is copied unchanged, the README
lists exactly the linked modules, and go-ethereum gets the LGPL notice with its source location. Fixture modules
check each failure above. A Dockerfile check pins the shared `ENV` target, the collector run for the package that
is built (with the same build tags), the `COPY` into `/licenses/`, the source label, and that `ARG SOURCE_URL`
names the public repository that `config/defaults.yaml` uses.

By hand, from the repository root:

```sh
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 SOURCE_URL=https://github.com/sealedtempo/sealed \
  sh verifier/third_party/collect-licenses.sh /tmp/licenses ./verifier/cmd/sealed-verifierd
```
