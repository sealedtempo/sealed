"""Tests for scripts/a6_coding_agent.py against fake OpenHands and OpenCode servers."""
from __future__ import annotations

import base64
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from fakes import FakeOpenCode, FakeOpenHands, write_broken_files  # noqa: E402

SCRIPTS = os.path.normpath(os.path.join(HERE, "..", "scripts"))
spec = importlib.util.spec_from_file_location("a6", os.path.join(SCRIPTS, "a6_coding_agent.py"))
a6 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a6)

SESSION = "session-key-0123456789"
VKEY = "sk-virtual-0001"


def seeded(oh):
    oh.settings["agent_settings"]["llm"] = {
        "model": "litellm_proxy/relay/default", "base_url": "http://llm-gateway:4000",
        "api_key": VKEY, "usage_id": "coding-agent", "litellm_extra_body": {"fallbacks": ["local/qwen3-4b"]},
    }
    return oh


class A6Test(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def run_a6(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = a6.main(argv)
        return code, out.getvalue(), err.getvalue()

    def base_args(self, oh, *extra):
        return ["--url", oh.url, "--session-key", SESSION, "--poll", "0.01", "--timeout", "10", *extra]

    def test_openhands_success(self):
        with seeded(FakeOpenHands(SESSION, self.tmp.name)) as oh:
            code, out, err = self.run_a6(self.base_args(oh, "--gate-password", "gatepw"))
            self.assertEqual(code, 0, err)
            summary = json.loads(out)
            self.assertTrue(summary["ok"])
            self.assertEqual(summary["model"], "litellm_proxy/relay/default")
            self.assertEqual(summary["prompt_tokens"], 321)
            start = [c for c in oh.calls if c[0] == "POST" and c[1] == "/api/conversations"][0]
            body = start[2]
            self.assertEqual(body["agent"]["llm"]["api_key"], VKEY)
            self.assertEqual(body["agent"]["llm"]["base_url"], "http://llm-gateway:4000")
            self.assertEqual([t["name"] for t in body["agent"]["tools"]], ["terminal", "file_editor"])
            self.assertFalse(body["autotitle"])
            self.assertTrue(body["workspace"]["working_dir"].startswith("/workspace/project/a6-"))
            gate = "Basic " + base64.b64encode(b"sealed:gatepw").decode()
            self.assertTrue(all(c[3].get("authorization") == gate for c in oh.calls))
            settings_call = [c for c in oh.calls if c[1] == "/api/settings"][0]
            self.assertEqual(settings_call[3]["x-expose-secrets"], "plaintext")
            self.assertIn("DELETE", [c[0] for c in oh.calls])
            self.assertNotIn(VKEY, err)

    def test_model_override_drops_fallback(self):
        with seeded(FakeOpenHands(SESSION, self.tmp.name)) as oh:
            code, out, err = self.run_a6(self.base_args(oh, "--model", "litellm_proxy/local/qwen3-4b", "--keep"))
            self.assertEqual(code, 0, err)
            body = [c for c in oh.calls if c[1] == "/api/conversations"][0][2]
            self.assertEqual(body["agent"]["llm"]["model"], "litellm_proxy/local/qwen3-4b")
            self.assertNotIn("litellm_extra_body", body["agent"]["llm"])
            self.assertNotIn("DELETE", [c[0] for c in oh.calls])

    def test_explicit_llm_key_skips_settings(self):
        with FakeOpenHands(SESSION, self.tmp.name) as oh:
            code, out, err = self.run_a6(self.base_args(oh, "--llm-key", "sk-explicit"))
            self.assertEqual(code, 0, err)
            self.assertNotIn("/api/settings", oh.paths())

    def test_unseeded_settings_fail(self):
        with FakeOpenHands(SESSION, self.tmp.name) as oh:
            code, _, err = self.run_a6(self.base_args(oh))
            self.assertEqual(code, 1)
            self.assertIn("did the bootstrap job run", err)

    def test_agent_error_fails(self):
        with seeded(FakeOpenHands(SESSION, self.tmp.name, final_status="error")) as oh:
            code, _, err = self.run_a6(self.base_args(oh))
            self.assertEqual(code, 1)
            self.assertIn("last status 'error'", err)

    def test_timeout_fails(self):
        with seeded(FakeOpenHands(SESSION, self.tmp.name, running_polls=10_000)) as oh:
            code, _, err = self.run_a6(self.base_args(oh, "--timeout", "0.2"))
            self.assertEqual(code, 1)
            self.assertIn("last status 'running'", err)

    def test_independent_test_run_catches_wrong_code(self):
        with seeded(FakeOpenHands(SESSION, self.tmp.name, agent_writes=write_broken_files)) as oh:
            code, _, err = self.run_a6(self.base_args(oh))
            self.assertEqual(code, 1)
            self.assertIn("independent test run failed", err)

    def test_no_usage_fails(self):
        with seeded(FakeOpenHands(SESSION, self.tmp.name, record_tokens=False)) as oh:
            code, _, err = self.run_a6(self.base_args(oh))
            self.assertEqual(code, 1)
            self.assertIn("no LLM usage", err)

    def test_wrong_session_key(self):
        with seeded(FakeOpenHands("other-key", self.tmp.name)) as oh:
            code, _, err = self.run_a6(self.base_args(oh))
            self.assertEqual(code, 1)
            self.assertIn("HTTP 401", err)

    def test_opencode_success(self):
        with FakeOpenCode("sealed", "gatepw", self.tmp.name) as oc:
            code, out, err = self.run_a6(["--target", "opencode", "--url", oc.url, "--gate-password", "gatepw",
                                          "--timeout", "10"])
            self.assertEqual(code, 0, err)
            summary = json.loads(out)
            self.assertEqual(summary["target"], "opencode")
            message = [c for c in oc.calls if c[1].endswith("/message")][0][2]
            self.assertEqual(message["model"], {"providerID": "litellm", "modelID": "relay-default"})

    def test_opencode_failing_test(self):
        with FakeOpenCode("sealed", "gatepw", self.tmp.name, exit_override=1) as oc:
            code, _, err = self.run_a6(["--target", "opencode", "--url", oc.url, "--gate-password", "gatepw"])
            self.assertEqual(code, 1)
            self.assertIn("exit 1", err)

    def test_required_args(self):
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                a6.parse_args(["--url", "http://x"])
            with self.assertRaises(SystemExit):
                a6.parse_args(["--target", "opencode", "--url", "http://x"])

    def test_token_counting_shapes(self):
        self.assertEqual(a6.total_prompt_tokens({"stats": {"usage_to_metrics": {}}}), None)
        self.assertEqual(a6.total_prompt_tokens({"stats": {"usage_to_metrics": {"a": {"x": 1}}}}), -1)
        self.assertEqual(a6.total_prompt_tokens({"stats": {"usage_to_metrics": [
            {"accumulated_token_usage": {"prompt_tokens": 2}}, {"accumulated_token_usage": {"prompt_tokens": 3}}]}}), 5)

    def test_shell_wrapper(self):
        with seeded(FakeOpenHands(SESSION, self.tmp.name)) as oh:
            env = dict(os.environ, A6_URL=oh.url, CODING_AGENT_API_KEY=SESSION, A6_POLL_S="0.01", A6_TIMEOUT_S="10",
                       PATH=os.path.dirname(sys.executable) + os.pathsep + os.environ.get("PATH", ""))
            proc = subprocess.run(["bash", os.path.join(SCRIPTS, "a6-coding-agent.sh")], env=env,
                                  capture_output=True, text=True, timeout=60)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(json.loads(proc.stdout)["ok"])


if __name__ == "__main__":
    unittest.main()
