"""Static checks for runtime/images/local-model/Dockerfile (no docker daemon needed)."""
from __future__ import annotations

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
IMAGE_DIR = os.path.normpath(os.path.join(HERE, ".."))
REPO = os.path.normpath(os.path.join(IMAGE_DIR, "..", "..", ".."))
sys.path.insert(0, os.path.join(REPO, "catalog", "apps", "llm-gateway", "tests"))

import dockerfile_lint  # noqa: E402

OLLAMA_BASE = "ollama/ollama:0.40.12@sha256:20d1bbfbabe1c97ba4b16301f08a20d8484bcf77047742a3cb71c613d8e12d0b"
MODEL_PINS = {
    "MODEL": "qwen3:4b-instruct-2507-q4_K_M",
    "MODEL_ID": "0edcdef34593",
    "MODEL_BLOB": "85e4a5b7b8ef0e48af0e8658f5aaab9c2324c76c1641493f4d1e25fce54b18b9",
    "TEMPLATE_BLOB": "eade0a07cac7712787bbce23d12f9306adb4781d873d1df6e16f7840fa37afec",
    "LICENSE_BLOB": "d18a5cc71b84bc4af394a31116bd3932b42241de70c77d2b76d69a314ec8aa12",
    "PARAMS_BLOB": "0914c7781e001948488d937994217538375b4fd8c1466c5e7a625221abd3ea7a",
    "CONFIG_BLOB": "b72accf9724e93698c57cbd3b1af2d3341b3d05ec2089d86d273d97964853cd2",
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

    def test_base_pinned_by_digest(self):
        self.assertEqual(self.args["OLLAMA_BASE"], OLLAMA_BASE)
        self.assertEqual(self.stages[0].base, OLLAMA_BASE)
        self.assertTrue(dockerfile_lint.is_digest_pinned(self.stages[0].base))

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
        self.assertEqual(stage.env().get("OLLAMA_NO_CLOUD"), "1")

    def test_flattened_final_stage(self):
        self.assertEqual(self.final.base, "scratch")
        self.assertEqual(self.final.all("COPY"), ["--from=cpu / /", "--from=models /models /models"])
        self.assertEqual(self.final.all("RUN"), [])

    def test_final_runtime_env(self):
        env = self.final.env()
        self.assertEqual(env["OLLAMA_NO_CLOUD"], "1")
        self.assertEqual(env["OLLAMA_MODELS"], "/models")
        self.assertEqual(env["OLLAMA_NOPRUNE"], "1")
        self.assertEqual(env["OLLAMA_VULKAN"], "0")
        self.assertEqual(env["OLLAMA_CONTEXT_LENGTH"], "8192")
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

    def test_context_length_matches_gateway_config(self):
        import yaml
        path = os.path.join(REPO, "catalog", "apps", "llm-gateway", "images", "litellm", "config.yaml")
        with open(path, encoding="utf-8") as handle:
            local = yaml.safe_load(handle)["model_list"][0]
        self.assertEqual(local["model_info"]["max_input_tokens"], int(self.final.env()["OLLAMA_CONTEXT_LENGTH"]))
        self.assertEqual(local["litellm_params"]["model"], "ollama_chat/" + MODEL_PINS["MODEL"])


if __name__ == "__main__":
    unittest.main()
