# syntax=docker/dockerfile:1.7
# Sealed local model: Ollama 0.40.12, CPU only, with qwen3:4b-instruct-2507-q4_K_M
# (Qwen3-4B-Instruct-2507, Apache-2.0) baked in. Flattened with FROM scratch so no
# layer carries the NVIDIA CUDA/cuDNN, MLX-CUDA or Vulkan runtimes.
# Build context: this directory. Needs egress to registry.ollama.ai at build time only.
# Never build inside the TEE.

ARG OLLAMA_BASE=ollama/ollama:0.40.12@sha256:20d1bbfbabe1c97ba4b16301f08a20d8484bcf77047742a3cb71c613d8e12d0b

FROM --platform=linux/amd64 ${OLLAMA_BASE} AS cpu
# The TDX VM has no GPU: drop every GPU runtime directory and its license files.
RUN set -eux; \
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
# Every blob of the registry manifest, checked after the pull (Ollama cannot pull by digest).
ARG MODEL_BLOB=85e4a5b7b8ef0e48af0e8658f5aaab9c2324c76c1641493f4d1e25fce54b18b9
ARG TEMPLATE_BLOB=eade0a07cac7712787bbce23d12f9306adb4781d873d1df6e16f7840fa37afec
ARG LICENSE_BLOB=d18a5cc71b84bc4af394a31116bd3932b42241de70c77d2b76d69a314ec8aa12
ARG PARAMS_BLOB=0914c7781e001948488d937994217538375b4fd8c1466c5e7a625221abd3ea7a
ARG CONFIG_BLOB=b72accf9724e93698c57cbd3b1af2d3341b3d05ec2089d86d273d97964853cd2
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
    mkdir -p /models/licenses; \
    cp "/models/blobs/sha256-$LICENSE_BLOB" /models/licenses/qwen3-4b-instruct-2507.Apache-2.0.txt; \
    grep -q "Apache License" /models/licenses/qwen3-4b-instruct-2507.Apache-2.0.txt; \
    rm -rf /root/.ollama /tmp/serve.log

FROM scratch
COPY --from=cpu / /
COPY --from=models /models /models
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    OLLAMA_HOST=0.0.0.0:11434 \
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
      org.opencontainers.image.licenses="MIT AND Apache-2.0" \
      org.opencontainers.image.description="Ollama CPU-only with qwen3:4b-instruct-2507-q4_K_M for Sealed" \
      sealed.base.digest="ollama/ollama@sha256:20d1bbfbabe1c97ba4b16301f08a20d8484bcf77047742a3cb71c613d8e12d0b" \
      sealed.model="qwen3:4b-instruct-2507-q4_K_M@0edcdef34593" \
      sealed.model.blob="sha256:85e4a5b7b8ef0e48af0e8658f5aaab9c2324c76c1641493f4d1e25fce54b18b9"
EXPOSE 11434
ENTRYPOINT ["/bin/ollama"]
CMD ["serve"]
