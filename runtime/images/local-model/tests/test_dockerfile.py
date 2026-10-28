"""Static checks for runtime/images/local-model/Dockerfile (no docker daemon needed)."""
from __future__ import annotations

import hashlib
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
IMAGE_DIR = os.path.normpath(os.path.join(HERE, ".."))
REPO = os.path.normpath(os.path.join(IMAGE_DIR, "..", "..", ".."))
sys.path.insert(0, os.path.join(REPO, "catalog", "apps", "llm-gateway", "tests"))

import dockerfile_lint  # noqa: E402

OLLAMA_BASE = "ollama/ollama:0.40.12@sha256:20d1bbfbabe1c97ba4b16301f08a20d8484bcf77047742a3cb71c613d8e12d0b"
GO_BASE = "golang:1.27.3-trixie@sha256:7b072c590a326b9d2a43b165ae247f6e8eafff32e1ad154ab97139e89f053be9"
MODEL_PINS = {
    "MODEL": "qwen3:4b-instruct-2507-q4_K_M",
    "MODEL_ID": "0edcdef34593",
    "MODEL_MANIFEST": "/models/manifests/registry.ollama.ai/library/qwen3/4b-instruct-2507-q4_K_M",
    "MODEL_BLOB": "85e4a5b7b8ef0e48af0e8658f5aaab9c2324c76c1641493f4d1e25fce54b18b9",
    "TEMPLATE_BLOB": "eade0a07cac7712787bbce23d12f9306adb4781d873d1df6e16f7840fa37afec",
    "LICENSE_BLOB": "d18a5cc71b84bc4af394a31116bd3932b42241de70c77d2b76d69a314ec8aa12",
    "PARAMS_BLOB": "0914c7781e001948488d937994217538375b4fd8c1466c5e7a625221abd3ea7a",
    "CONFIG_BLOB": "b72accf9724e93698c57cbd3b1af2d3341b3d05ec2089d86d273d97964853cd2",
    "MODEL_MANIFEST_SHA256": "",
}
GPU_DIRS = ("cuda_v12", "cuda_v13", "mlx_cuda_v13", "vulkan")


class LocalModelDockerfileTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(IMAGE_DIR, "Dockerfile"), encoding="utf-8") as handle:
            cls.text = handle.read()
        cls.args, cls.stages = dockerfile_lint.stages(cls.text)
        cls.by_name = {s.name: s for s in cls.stages}
        cls.final = cls.stages[-1]

    def test_bases_pinned_by_digest(self):
        self.assertEqual(self.args["OLLAMA_BASE"], OLLAMA_BASE)
        self.assertEqual(self.args["GO_BASE"], GO_BASE)
        self.assertEqual(self.by_name["gate"].base, GO_BASE)
        self.assertEqual(self.by_name["cpu"].base, OLLAMA_BASE)
        names = {s.name for s in self.stages}
        for stage in self.stages:
            if stage.base != "scratch" and stage.base not in names:
                self.assertTrue(dockerfile_lint.is_digest_pinned(stage.base), stage.base)

    def test_gate_built_offline_from_stdlib(self):
        stage = self.by_name["gate"]
        self.assertEqual(stage.all("COPY"), ["gate/*.go ./"])
        run = " ".join(stage.all("RUN"))
        self.assertTrue(run.startswith("--network=none "))
        for needle in ("CGO_ENABLED=0", "GOPROXY=off", "GOTOOLCHAIN=local", "-trimpath", "rm -f ./*_test.go"):
            self.assertIn(needle, run)
        gate_dir = os.path.join(IMAGE_DIR, "gate")
        for name in os.listdir(gate_dir):
            if name.endswith(".go") and not name.endswith("_test.go"):
                with open(os.path.join(gate_dir, name), encoding="utf-8") as handle:
                    imports = handle.read().split("import (", 1)[-1].split(")", 1)[0]
                for line in imports.split():
                    self.assertNotIn(".", line.strip('"').split("/")[0], f"{name}: non-stdlib import {line}")

    def test_gate_ships_the_go_license_texts(self):
        """License audit F3: a binary built with the Go standard library carries Go's LICENSE and PATENTS."""
        stage = self.by_name["gate"]
        declared = dict(arg.split("=", 1) for arg in stage.all("ARG"))
        texts = os.path.join(REPO, "catalog", "apps", "llm-gateway", "LICENSES")
        for arg, name in (("GO_LICENSE_SHA256", "go-1.27.3-LICENSE"), ("GO_PATENTS_SHA256", "go-1.27.3-PATENTS")):
            with open(os.path.join(texts, name), "rb") as handle:
                self.assertEqual(declared[arg], hashlib.sha256(handle.read()).hexdigest(), name)
        run = " ".join(" ".join(stage.all("RUN")).split())
        self.assertIn('echo "$GO_LICENSE_SHA256 $goroot/LICENSE" | sha256sum -c -', run)
        self.assertIn('echo "$GO_PATENTS_SHA256 $goroot/PATENTS" | sha256sum -c -', run)
        self.assertIn('cp "$goroot/LICENSE" /out/licenses/go-1.27.3-LICENSE', run)
        self.assertIn('cp "$goroot/PATENTS" /out/licenses/go-1.27.3-PATENTS', run)
        self.assertIn("> /out/licenses/README", run)
        # The texts match the toolchain: the builder is Go 1.27.3, checked in the build.
        self.assertTrue(GO_BASE.startswith("golang:1.27.3-"))
        self.assertIn('test "$(go version)" = "go version go1.27.3 linux/amd64"', run)

    def test_gate_build_fails_on_non_stdlib_imports(self):
        run = " ".join(" ".join(self.by_name["gate"].all("RUN")).split())
        self.assertIn("go list -deps -f '{{if not .Standard}}{{.ImportPath}}{{end}}' . | grep .)", run)
        self.assertIn('test "$nonstd" = "sealed.local/ollama-gate"', run)
        # The check runs before the build and after the test files are gone.
        self.assertLess(run.index("rm -f ./*_test.go"), run.index("go list -deps"))
        self.assertLess(run.index("go list -deps"), run.index("go build"))

    def test_gpu_runtimes_removed(self):
        run = " ".join(self.by_name["cpu"].all("RUN"))
        for name in GPU_DIRS:
            self.assertIn(f"/usr/lib/ollama/{name}", run)
        self.assertIn("libggml-cpu-*.so", run)

    def test_model_pins_and_integrity_checks(self):
        stage = self.by_name["models"]
        declared = dict(arg.split("=", 1) for arg in stage.all("ARG"))
        self.assertEqual(declared, MODEL_PINS)
        run = " ".join(stage.all("RUN"))
        self.assertIn('[ "$id" = "$MODEL_ID" ]', run)
        self.assertIn("sha256sum -c", run)
        for key in ("MODEL_BLOB", "TEMPLATE_BLOB", "LICENSE_BLOB", "PARAMS_BLOB", "CONFIG_BLOB"):
            self.assertIn(f'"${key}"', run)
        self.assertIn("unexpected blobs", run)
        self.assertIn("rm -rf /root/.ollama", run)
        self.assertIn('sealed-ollama-gate verify-manifest -manifest "$MODEL_MANIFEST" -config "$CONFIG_BLOB" '
                      '-model "$MODEL_BLOB" -template "$TEMPLATE_BLOB" -license "$LICENSE_BLOB" '
                      '-params "$PARAMS_BLOB" -sha256 "$MODEL_MANIFEST_SHA256"', " ".join(run.split()))
        self.assertIn("chmod -R a+rX,go-w /models", run)
        self.assertTrue(MODEL_PINS["MODEL_MANIFEST"].endswith(MODEL_PINS["MODEL"].replace(":", "/")))
        self.assertEqual(stage.env().get("OLLAMA_NO_CLOUD"), "1")

    def test_flattened_final_stage(self):
        self.assertEqual(self.final.base, "scratch")
        self.assertEqual(self.final.all("COPY"), [
            "--from=cpu / /", "--from=models /models /models",
            "--from=gate /out/sealed-ollama-gate /usr/local/bin/sealed-ollama-gate",
            "--from=gate /out/licenses /licenses/sealed-ollama-gate",
        ])
        self.assertEqual(self.final.all("RUN"), [])
        self.assertEqual(self.final.all("USER"), ["10002:10002"])

    def test_final_runtime_env(self):
        env = self.final.env()
        self.assertEqual(env["OLLAMA_NO_CLOUD"], "1")
        self.assertEqual(env["OLLAMA_MODELS"], "/models")
        self.assertEqual(env["OLLAMA_NOPRUNE"], "1")
        self.assertEqual(env["OLLAMA_VULKAN"], "0")
        self.assertEqual(env["OLLAMA_CONTEXT_LENGTH"], "8192")
        self.assertEqual(env["OLLAMA_HOST"], "127.0.0.1:11435")  # loopback only; the gate serves :11434
        self.assertEqual(env["HOME"], "/tmp/ollama")
        self.assertNotIn("OLLAMA_DEBUG_LOG_REQUESTS", env)
        self.assertNotIn("LD_LIBRARY_PATH", env)
        self.assertNotIn("NVIDIA_VISIBLE_DEVICES", env)

    def test_entrypoint_matches_gateway_fragment(self):
        import yaml
        path = os.path.join(REPO, "catalog", "apps", "llm-gateway", "compose.fragment.yaml")
        with open(path, encoding="utf-8") as handle:
            svc = yaml.safe_load(handle)["services"]["llm-gateway-ollama"]
        self.assertEqual(self.final.exec_form("ENTRYPOINT"), svc["entrypoint"])
        self.assertEqual(self.final.exec_form("CMD"), svc["command"])
        self.assertEqual(self.final.all("USER"), [svc["user"]])
        upstream = svc["command"][svc["command"].index("-upstream") + 1]
        self.assertEqual(upstream, self.final.env()["OLLAMA_HOST"])
        # The bearer key is on (per-service secret mounts, integration brief item 5).
        self.assertEqual(svc["command"][svc["command"].index("-key-env") + 1], "OLLAMA_GATE_KEY")
        self.assertEqual(svc["x-sealed-secrets"], ["OLLAMA_GATE_KEY"])

    def test_context_length_matches_gateway_config(self):
        import yaml
        path = os.path.join(REPO, "catalog", "apps", "llm-gateway", "images", "litellm", "config.yaml")
        with open(path, encoding="utf-8") as handle:
            local = yaml.safe_load(handle)["model_list"][0]
        self.assertEqual(local["model_info"]["max_input_tokens"], int(self.final.env()["OLLAMA_CONTEXT_LENGTH"]))
        self.assertEqual(local["litellm_params"]["model"], "ollama_chat/" + MODEL_PINS["MODEL"])


if __name__ == "__main__":
    unittest.main()
