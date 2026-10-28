# local-model image

Ollama 0.40.12, CPU only, with `qwen3:4b-instruct-2507-q4_K_M` baked in (D-024). Used by the
`llm-gateway` app as `{{image:local-model}}` (service `llm-gateway-ollama`, route `local/qwen3-4b`).

| item | value |
|---|---|
| base | `ollama/ollama:0.40.12@sha256:20d1bbfbabe1c97ba4b16301f08a20d8484bcf77047742a3cb71c613d8e12d0b` (MIT) |
| model | Qwen3-4B-Instruct-2507, 4.0B params, Q4_K_M, Apache-2.0 |
| Ollama ID | `0edcdef34593` |
| model blob | `sha256:85e4a5b7b8ef0e48af0e8658f5aaab9c2324c76c1641493f4d1e25fce54b18b9` (2,497,280,480 bytes) |
| size | about 0.5 GB runtime plus 2.5 GB model |

What the build does:

1. Deletes the GPU runtimes (`/usr/lib/ollama/{cuda_v12,cuda_v13,mlx_cuda_v13,vulkan}` and the NVIDIA
   license files) and fails if any CUDA, Vulkan or ROCm library is left. CPU backends
   (`libggml-cpu-*.so`, including the Sapphire Rapids build for C3) stay.
2. Starts `ollama serve` inside the build step, pulls the model, and checks the `ollama list` ID and
   the sha256 of every blob in the registry manifest (model, template, license, params, config).
   Any extra blob fails the build. Ollama cannot pull by digest, so these checks are the guarantee.
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

Tests (static, no daemon): `python -m unittest discover -s runtime/images/local-model/tests`.
After a build, CI must run one generation on the stripped image (VERIFY-AT-BUILD in
`docs/notes/litellm.md` section 10).
