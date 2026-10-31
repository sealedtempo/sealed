# syntax=docker/dockerfile:1.7
# Sealed local model: Ollama 0.40.12, CPU only, with qwen3:4b-instruct-2507-q4_K_M
# (Qwen3-4B-Instruct-2507, Apache-2.0) baked in. Flattened with FROM scratch so no
# layer carries the NVIDIA CUDA/cuDNN, MLX-CUDA or Vulkan runtimes.
# Ollama listens on loopback only; sealed-ollama-gate (gate/, Go stdlib) serves the API on
# :11434 to the llm-gateway-litellm service only, for inference and read endpoints only.
# Build context: this directory. Needs egress to registry.ollama.ai at build time only.
# Never build inside the TEE.

ARG OLLAMA_BASE=ollama/ollama:0.40.12@sha256:20d1bbfbabe1c97ba4b16301f08a20d8484bcf77047742a3cb71c613d8e12d0b
ARG GO_BASE=golang:1.27.3-trixie@sha256:7b072c590a326b9d2a43b165ae247f6e8eafff32e1ad154ab97139e89f053be9

# The gate stage runs on the build machine and cross-compiles for linux/amd64, the platform of the
# rest of the image. Under amd64 emulation on an arm64 machine the Go 1.27.3 toolchain crashes
# ("fatal error: found pointer to free object", images-preflight), so it must not run emulated.
FROM --platform=$BUILDPLATFORM ${GO_BASE} AS gate
# Go 1.27.3's LICENSE (BSD-3-Clause) and PATENTS, which a binary built with the standard library
# carries (license audit F3). The same texts are in catalog/apps/llm-gateway/LICENSES/.
ARG GO_LICENSE_SHA256=911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad
ARG GO_PATENTS_SHA256=96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc
WORKDIR /src
COPY gate/*.go ./
# Standard library only, so the build needs no network and no go.sum. The build fails if the
# gate imports any package outside the standard library, so the two Go texts are all it needs.
RUN --network=none set -eux; \
    rm -f ./*_test.go; \
    go mod init sealed.local/ollama-gate; \
    test "$(go env GOVERSION)" = "go1.27.3"; \
    nonstd="$(GOTOOLCHAIN=local GOPROXY=off go list -deps -f '{{if not .Standard}}{{.ImportPath}}{{end}}' . | grep .)"; \
    test "$nonstd" = "sealed.local/ollama-gate"; \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-trimpath \
      go build -ldflags='-s -w -buildid=' -o /out/sealed-ollama-gate .; \
    /out/sealed-ollama-gate -listen 127.0.0.1:0 2>&1 | grep -q 'missing Ollama command'; \
    goroot="$(go env GOROOT)"; mkdir -p /out/licenses; \
    echo "$GO_LICENSE_SHA256  $goroot/LICENSE" | sha256sum -c -; \
    echo "$GO_PATENTS_SHA256  $goroot/PATENTS" | sha256sum -c -; \
    cp "$goroot/LICENSE" /out/licenses/go-1.27.3-LICENSE; \
    cp "$goroot/PATENTS" /out/licenses/go-1.27.3-PATENTS; \
    printf '%s\n' \
      'sealed-ollama-gate is Sealed code under the Apache License 2.0' \
      '(source: runtime/images/local-model/gate in the Sealed repository).' \
      'It is built with Go 1.27.3 and links only the Go standard library, whose license and' \
      'patent grant are the two files next to this one.' > /out/licenses/README; \
    chmod 0644 /out/licenses/*

FROM --platform=linux/amd64 ${OLLAMA_BASE} AS cpu
# The TDX VM has no GPU: drop every GPU runtime directory and its license files.
RUN --network=none set -eux; \
    rm -rf /usr/lib/ollama/cuda_v12 /usr/lib/ollama/cuda_v13 /usr/lib/ollama/mlx_cuda_v13 /usr/lib/ollama/vulkan \
           /usr/lib/ollama/CUDNN_LICENSE.txt /usr/lib/ollama/CUTLASS_LICENSE.txt /usr/lib/ollama/NVTX3_LICENSE.txt \
           /usr/local/nvidia; \
    find /usr/lib/ollama -mindepth 1 -maxdepth 1 -type d -print; \
    test -z "$(find /usr/lib/ollama \( -iname '*cuda*' -o -iname '*vulkan*' -o -iname '*hip*' -o -iname '*rocm*' \) -print -quit)"; \
    test -z "$(find / -xdev \( -name 'libcudart*' -o -name 'libcublas*' -o -name 'libcudnn*' -o -name 'libnvidia*' -o -name 'libcuda.so*' \) -print -quit)"; \
    ls /usr/lib/ollama/libggml-cpu-*.so >/dev/null

FROM cpu AS models
ARG MODEL=qwen3:4b-instruct-2507-q4_K_M
ARG MODEL_ID=0edcdef34593
ARG MODEL_MANIFEST=/models/manifests/registry.ollama.ai/library/qwen3/4b-instruct-2507-q4_K_M
# Every blob of the registry manifest, checked after the pull (Ollama cannot pull by digest).
ARG MODEL_BLOB=85e4a5b7b8ef0e48af0e8658f5aaab9c2324c76c1641493f4d1e25fce54b18b9
ARG TEMPLATE_BLOB=eade0a07cac7712787bbce23d12f9306adb4781d873d1df6e16f7840fa37afec
ARG LICENSE_BLOB=d18a5cc71b84bc4af394a31116bd3932b42241de70c77d2b76d69a314ec8aa12
ARG PARAMS_BLOB=0914c7781e001948488d937994217538375b4fd8c1466c5e7a625221abd3ea7a
ARG CONFIG_BLOB=b72accf9724e93698c57cbd3b1af2d3341b3d05ec2089d86d273d97964853cd2
# Full sha256 of the manifest file. Empty until the first CI build prints it ("manifest
# sha256:..."); the role-by-role layer check below applies either way.
ARG MODEL_MANIFEST_SHA256=
COPY --from=gate /out/sealed-ollama-gate /usr/local/bin/sealed-ollama-gate
ENV OLLAMA_MODELS=/models OLLAMA_HOST=127.0.0.1:11434 OLLAMA_NO_CLOUD=1
RUN set -eu; \
    ollama serve >/tmp/serve.log 2>&1 & pid=$!; \
    i=0; until ollama list >/dev/null 2>&1; do \
      i=$((i+1)); if [ "$i" -ge 60 ]; then cat /tmp/serve.log; exit 1; fi; sleep 1; \
    done; \
    ollama pull "$MODEL"; \
    id="$(ollama list | awk -v m="$MODEL" '$1==m {print $2}')"; \
    kill "$pid"; wait "$pid" || true; \
    [ "$id" = "$MODEL_ID" ] || { echo "model id '$id' != '$MODEL_ID'"; exit 1; }; \
    for b in "$MODEL_BLOB" "$TEMPLATE_BLOB" "$LICENSE_BLOB" "$PARAMS_BLOB" "$CONFIG_BLOB"; do \
      echo "$b  /models/blobs/sha256-$b" | sha256sum -c -; \
    done; \
    extra="$(find /models/blobs -type f ! -name "sha256-$MODEL_BLOB" ! -name "sha256-$TEMPLATE_BLOB" \
             ! -name "sha256-$LICENSE_BLOB" ! -name "sha256-$PARAMS_BLOB" ! -name "sha256-$CONFIG_BLOB" -print)"; \
    [ -z "$extra" ] || { echo "unexpected blobs: $extra"; exit 1; }; \
    [ "$(find /models/manifests -type f | wc -l)" -eq 1 ] || { echo "unexpected manifests"; exit 1; }; \
    sealed-ollama-gate verify-manifest -manifest "$MODEL_MANIFEST" -config "$CONFIG_BLOB" -model "$MODEL_BLOB" \
      -template "$TEMPLATE_BLOB" -license "$LICENSE_BLOB" -params "$PARAMS_BLOB" -sha256 "$MODEL_MANIFEST_SHA256"; \
    mkdir -p /models/licenses; \
    cp "/models/blobs/sha256-$LICENSE_BLOB" /models/licenses/qwen3-4b-instruct-2507.Apache-2.0.txt; \
    grep -q "Apache License" /models/licenses/qwen3-4b-instruct-2507.Apache-2.0.txt; \
    chmod -R a+rX,go-w /models; \
    rm -rf /root/.ollama /tmp/serve.log

FROM scratch
COPY --from=cpu / /
COPY --from=models /models /models
COPY --from=gate /out/sealed-ollama-gate /usr/local/bin/sealed-ollama-gate
COPY --from=gate /out/licenses /licenses/sealed-ollama-gate
# Runs as uid 10002 (no capabilities). HOME is on the /tmp tmpfs: Ollama writes a fresh
# keypair there at every start. OLLAMA_HOST is the loopback address the gate proxies to.
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    HOME=/tmp/ollama \
    OLLAMA_HOST=127.0.0.1:11435 \
    OLLAMA_MODELS=/models \
    OLLAMA_NO_CLOUD=1 \
    OLLAMA_NOPRUNE=1 \
    OLLAMA_KEEP_ALIVE=-1 \
    OLLAMA_CONTEXT_LENGTH=8192 \
    OLLAMA_NUM_PARALLEL=2 \
    OLLAMA_MAX_LOADED_MODELS=1 \
    OLLAMA_VULKAN=0
LABEL org.opencontainers.image.source="https://github.com/ollama/ollama" \
      org.opencontainers.image.version="0.40.12" \
      org.opencontainers.image.revision="f067033f9126993b6172bdfffa71a74ad693fda4" \
      org.opencontainers.image.licenses="MIT AND Apache-2.0 AND BSD-3-Clause" \
      org.opencontainers.image.description="Ollama CPU-only with qwen3:4b-instruct-2507-q4_K_M behind the Sealed peer gate" \
      sealed.base.digest="ollama/ollama@sha256:20d1bbfbabe1c97ba4b16301f08a20d8484bcf77047742a3cb71c613d8e12d0b" \
      sealed.gate.builder="golang@sha256:7b072c590a326b9d2a43b165ae247f6e8eafff32e1ad154ab97139e89f053be9" \
      sealed.model="qwen3:4b-instruct-2507-q4_K_M@0edcdef34593" \
      sealed.model.blob="sha256:85e4a5b7b8ef0e48af0e8658f5aaab9c2324c76c1641493f4d1e25fce54b18b9"
USER 10002:10002
EXPOSE 11434
ENTRYPOINT ["/usr/local/bin/sealed-ollama-gate"]
# The gate requires the bearer key in OLLAMA_GATE_KEY (the llm-gateway secret of the same name) and
# refuses to start without it.
CMD ["-listen", "0.0.0.0:11434", "-upstream", "127.0.0.1:11435", "-allow-peer", "llm-gateway-litellm", "-key-env", "OLLAMA_GATE_KEY", "--", "/bin/ollama", "serve"]
