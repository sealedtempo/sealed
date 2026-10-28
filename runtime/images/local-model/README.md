# local-model image

Ollama 0.40.12, CPU only, with `qwen3:4b-instruct-2507-q4_K_M` baked in (D-024), behind
`sealed-ollama-gate`. Used by the `llm-gateway` app as `{{image:local-model}}` (service
`llm-gateway-ollama`, route `local/qwen3-4b`; `catalog/apps/llm-gateway/images/local-model` is a
symlink to this directory).

| item | value |
|---|---|
| base | `ollama/ollama:0.40.12@sha256:20d1bbfbabe1c97ba4b16301f08a20d8484bcf77047742a3cb71c613d8e12d0b` (MIT) |
| model | Qwen3-4B-Instruct-2507, 4.0B params, Q4_K_M, Apache-2.0 |
| Ollama ID | `0edcdef34593` |
| model blob | `sha256:85e4a5b7b8ef0e48af0e8658f5aaab9c2324c76c1641493f4d1e25fce54b18b9` (2,497,280,480 bytes) |
| size | about 0.5 GB runtime plus 2.5 GB model |
| gate builder | `golang:1.27.3-trixie@sha256:7b072c590a326b9d2a43b165ae247f6e8eafff32e1ad154ab97139e89f053be9` (build stage only) |
| user | 10002:10002, `HOME=/tmp/ollama` (tmpfs) |

## sealed-ollama-gate

`gate/` (Go standard library only) is the image entrypoint. It starts Ollama with
`OLLAMA_HOST=127.0.0.1:11435`, forwards SIGTERM/SIGINT to it, exits with its exit code, and serves
the Ollama API on :11434:

- only to loopback and to the current addresses of the `-allow-peer` names (`llm-gateway-litellm`),
  resolved through Docker's embedded DNS, re-resolved on a miss at most once a second;
- only for `GET /`, `/api/tags`, `/api/ps`, `/api/version`, `/v1/models[/<name>]` and
  `POST /api/chat`, `/api/generate`, `/api/embed`, `/api/embeddings`, `/api/show`,
  `/v1/chat/completions`, `/v1/completions`, `/v1/embeddings`, with canonical paths only;
- with streaming (`FlushInterval: -1`), a 64 MiB request limit, and `Authorization` removed;
- with a bearer key (`-key-env NAME`): the llm-gateway fragment runs it with
  `-key-env OLLAMA_GATE_KEY`, a secret only `llm-gateway-litellm` and `llm-gateway-ollama` list. Per-service
  secret mounts (integration brief item 5, D-042) mean this container sees that one file and nothing
  else of llm-gateway's secrets. The gate removes the variable from Ollama's environment and checks
  `Authorization: Bearer <key>` on every route except `/healthz`.

Subcommands: `probe <url>` (healthcheck without proxies) and `verify-manifest` (build time, below).

What the build does:

0. Builds the gate offline with Go 1.27.3 and fails if it imports anything outside the Go standard
   library (`go list -deps`). Go's `LICENSE` (BSD-3-Clause) and `PATENTS`, checked by sha256, go to
   `/licenses/sealed-ollama-gate/` with a README, because a binary built from the standard library
   carries them (license audit F3). `catalog/apps/llm-gateway/LICENSES/` has the same two texts.
1. Deletes the GPU runtimes (`/usr/lib/ollama/{cuda_v12,cuda_v13,mlx_cuda_v13,vulkan}` and the NVIDIA
   license files) and fails if any CUDA, Vulkan or ROCm library is left. CPU backends
   (`libggml-cpu-*.so`, including the Sapphire Rapids build for C3) stay.
2. Starts `ollama serve` inside the build step, pulls the model, and checks the `ollama list` ID and
   the sha256 of every blob in the registry manifest (model, template, license, params, config).
   Any extra blob or manifest fails the build. `sealed-ollama-gate verify-manifest` then checks the
   manifest role by role: exactly one model, template, license and params layer, each with its pinned
   digest, and the pinned config, so pinned blobs cannot swap roles. It prints the manifest's full
   sha256; set `MODEL_MANIFEST_SHA256` to it after the first CI build to pin the file itself. Ollama
   cannot pull by digest, so these checks are the guarantee.
3. Copies the model's Apache-2.0 license to `/models/licenses/`.
4. Flattens with `FROM scratch`, so no layer carries the removed files, and sets
   `OLLAMA_NO_CLOUD=1` (no model-recommendation polling, no cloud model proxy), a read-only model
   store, fixed context (8192) and two parallel slots.

Build (CI only; needs egress to `registry.ollama.ai` and its blob CDN, never inside the TEE):

```sh
docker buildx build --platform linux/amd64 -t sealed-local-model runtime/images/local-model
```

The fallback model `qwen3:1.7b` (ID `8f68893c685c`, Apache-2.0) can be built by overriding the
`MODEL*` and `*_BLOB` build args with its registry manifest values; then also change
`local/qwen3-4b` in `catalog/apps/llm-gateway/images/litellm/config.yaml`.

Tests: `make -C runtime/images/local-model test` (static Dockerfile checks, no daemon, plus
`go vet` and `go test` of the gate, which also runs the built gate binary as a supervising process).
After a build, CI must run one generation on the stripped image (VERIFY-AT-BUILD in
`docs/notes/litellm.md` section 10). The default command runs the gate with
`-key-env OLLAMA_GATE_KEY`, so such a run needs `-e OLLAMA_GATE_KEY=<16 or more characters>` and
`Authorization: Bearer <that key>` on the request; without the variable the gate exits with code 2.
