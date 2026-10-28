"""Tests for scripts/a6_coding_agent.py against fake OpenHands and OpenCode servers."""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from fake_gate import FakeGate  # noqa: E402
from fakes import FakeLiteLLM, FakeOpenCode, FakeOpenHands, write_broken_files, write_good_files  # noqa: E402

SCRIPTS = os.path.normpath(os.path.join(HERE, "..", "scripts"))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


a6 = load("a6", os.path.join(SCRIPTS, "a6_coding_agent.py"))
authproxy = load("authproxy_for_a6", os.path.join(HERE, "..", "bootstrap", "authproxy.py"))

SESSION = "session-key-0123456789"
VKEY = "sk-" + "f6" * 32
MASTER = "sk-" + "a1" * 32
OC_PASSWORD = "opencode-password-fedcba9876543210"


class OpenCodeBehindProxy:
    """FakeOpenCode on loopback behind the real authproxy, as in the OpenCode fragment."""

    def __init__(self, root, **kwargs):
        self.oc = FakeOpenCode("opencode", OC_PASSWORD, root, **kwargs)

    def __enter__(self):
        self.oc.__enter__()
        settings = authproxy.Settings(("127.0.0.1", self.oc.httpd.server_port), SESSION, "opencode", OC_PASSWORD)
        self.server = authproxy.make_server(("127.0.0.1", 0), settings)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = "http://127.0.0.1:%d" % self.server.server_address[1]
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        self.oc.__exit__(*exc)


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
            # No gate in front of this URL: the gate password is never sent to it.
            self.assertFalse([c for c in oh.calls if "authorization" in c[3]])
            self.assertIn("did not ask for the gate password", err)
            settings_call = [c for c in oh.calls if c[1] == "/api/settings"][0]
            self.assertEqual(settings_call[3]["x-expose-secrets"], "plaintext")
            self.assertIn("DELETE", [c[0] for c in oh.calls])
            self.assertNotIn(VKEY, err)

    def gated_openhands_run(self, mode, *extra, gate_kwargs=None, oh=None):
        oh = oh or seeded(FakeOpenHands(SESSION, self.tmp.name))
        with oh, FakeGate(oh.url, "gatepw", mode=mode, **(gate_kwargs or {})) as gate:
            args = ["--url", gate.url, "--session-key", SESSION, "--poll", "0.01", "--timeout", "10",
                    "--gate-password", "gatepw", *extra]
            code, out, err = self.run_a6(args)
        return code, out, err, gate, oh

    def assert_cookie_flow(self, gate, oh):
        self.assertEqual(gate.basic_checks, 1)  # Basic auth went over the wire once
        self.assertGreater(gate.cookie_passes, 5)
        for _, path, _, headers in oh.calls:
            self.assertNotIn("sealed:gatepw", base64.b64decode(
                (headers.get("authorization") or "Basic ").split(" ", 1)[1] or b"").decode("utf-8", "replace"), path)
            if path.startswith("/api/"):
                self.assertEqual(headers["x-session-api-key"], SESSION, path)

    def test_openhands_through_the_gate_with_the_cookie(self):
        code, out, err, gate, oh = self.gated_openhands_run("proxy")
        self.assertEqual(code, 0, err)
        self.assertTrue(json.loads(out)["ok"])
        self.assert_cookie_flow(gate, oh)
        self.assertIn("using the sealed_gate cookie", err)
        self.assertNotIn("gatepw", err)

    def test_openhands_through_a_gate_that_sets_the_cookie_on_a_redirect(self):
        code, out, err, gate, oh = self.gated_openhands_run("redirect")
        self.assertEqual(code, 0, err)
        self.assert_cookie_flow(gate, oh)

    def test_older_basic_auth_gate_gets_basic_on_every_call(self):
        code, out, err, gate, oh = self.gated_openhands_run("basic")
        self.assertEqual(code, 0, err)
        self.assertIn("no sealed_gate cookie was set", err)
        self.assertEqual(gate.basic_checks, len(oh.calls))  # every call reached the app with Basic auth
        self.assertFalse([c for c in oh.calls if "authorization" in c[3]])

    def test_waits_while_the_gate_answers_starting(self):
        code, out, err, gate, oh = self.gated_openhands_run("proxy", gate_kwargs={"starting": 3})
        self.assertEqual(code, 0, err)
        self.assertIn("waiting for the app to start", err)
        self.assertEqual(gate.starting, 0)

    def test_gives_up_when_the_app_never_starts(self):
        code, _, err, _, _ = self.gated_openhands_run("proxy", "--gate-wait", "0.05",
                                                      gate_kwargs={"starting": 10_000})
        self.assertEqual(code, 1)
        self.assertIn("did not start", err)

    def test_wrong_gate_password(self):
        with seeded(FakeOpenHands(SESSION, self.tmp.name)) as oh, FakeGate(oh.url, "other") as gate:
            code, _, err = self.run_a6(["--url", gate.url, "--session-key", SESSION, "--gate-password", "gatepw"])
        self.assertEqual(code, 1)
        self.assertIn("refused the gate password", err)
        self.assertEqual(oh.calls, [])

    def test_gated_route_without_the_gate_password(self):
        with seeded(FakeOpenHands(SESSION, self.tmp.name)) as oh, FakeGate(oh.url, "gatepw") as gate:
            code, _, err = self.run_a6(["--url", gate.url, "--session-key", SESSION, "--poll", "0.01"])
        self.assertEqual(code, 1)
        self.assertIn("pass --gate-password", err)

    def test_logs_in_again_when_the_cookie_stops_working(self):
        box = {}

        def writes(directory):
            write_good_files(directory)
            box["gate"].rotate()  # sealed-agent restarted: the per-boot cookie key changed

        oh = seeded(FakeOpenHands(SESSION, self.tmp.name, agent_writes=writes))
        with oh, FakeGate(oh.url, "gatepw") as gate:
            box["gate"] = gate
            code, out, err = self.run_a6(["--url", gate.url, "--session-key", SESSION, "--poll", "0.01",
                                          "--timeout", "10", "--gate-password", "gatepw"])
        self.assertEqual(code, 0, err)
        self.assertIn("logging in again", err)
        self.assertEqual(gate.basic_checks, 2)

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

    def opencode_args(self, proxy, *extra):
        return ["--target", "opencode", "--url", proxy.url, "--session-key", SESSION, "--timeout", "10", *extra]

    def test_opencode_success_through_the_session_key_proxy(self):
        with OpenCodeBehindProxy(self.tmp.name) as proxy:
            code, out, err = self.run_a6(self.opencode_args(proxy, "--gate-password", "gatepw"))
            self.assertEqual(code, 0, err)
            summary = json.loads(out)
            self.assertEqual((summary["target"], summary["tokens"]), ("opencode", 1280))
            message = [c for c in proxy.oc.calls if c[1].endswith("/message")][0]
            self.assertEqual(message[2]["model"], {"providerID": "litellm", "modelID": "relay-default"})
            # OpenCode saw only its own password, never the gate password or the session key.
            self.assertEqual(message[3]["authorization"],
                             "Basic " + base64.b64encode(f"opencode:{OC_PASSWORD}".encode()).decode())
            self.assertNotIn("x-session-api-key", message[3])

    def test_opencode_through_the_gate_never_sees_the_gate_cookie(self):
        with OpenCodeBehindProxy(self.tmp.name) as proxy, FakeGate(proxy.url, "gatepw") as gate:
            args = ["--target", "opencode", "--url", gate.url, "--session-key", SESSION, "--timeout", "10",
                    "--gate-password", "gatepw"]
            code, out, err = self.run_a6(args)
            self.assertEqual(code, 0, err)
            self.assertEqual(gate.basic_checks, 1)
            opencode_basic = "Basic " + base64.b64encode(f"opencode:{OC_PASSWORD}".encode()).decode()
            for _, path, _, headers in proxy.oc.calls:
                self.assertNotIn("sealed_gate", headers.get("cookie", ""), path)
                self.assertEqual(headers["authorization"], opencode_basic, path)

    def test_opencode_wrong_session_key(self):
        with OpenCodeBehindProxy(self.tmp.name) as proxy:
            args = self.opencode_args(proxy)
            args[args.index(SESSION)] = "wrong-key"
            code, _, err = self.run_a6(args)
            self.assertEqual(code, 1)
            self.assertIn("HTTP 401", err)
            self.assertEqual([c[1] for c in proxy.oc.calls], ["/global/health"])

    def test_opencode_failing_test(self):
        with OpenCodeBehindProxy(self.tmp.name, exit_override=1) as proxy:
            code, _, err = self.run_a6(self.opencode_args(proxy))
            self.assertEqual(code, 1)
            self.assertIn("exit 1", err)

    def test_opencode_without_token_counters_needs_the_gateway(self):
        with OpenCodeBehindProxy(self.tmp.name, record_tokens=False) as proxy:
            code, _, err = self.run_a6(self.opencode_args(proxy))
            self.assertEqual(code, 1)
            self.assertIn("recorded no LLM usage", err)
        with FakeLiteLLM(MASTER) as gw:
            gw.add_key(VKEY, key_alias="coding-agent")
            with OpenCodeBehindProxy(self.tmp.name, record_tokens=False,
                                     on_message=lambda: gw.record_usage(VKEY, 900, 50)) as proxy:
                code, out, err = self.run_a6(self.opencode_args(
                    proxy, "--gateway-admin-key", MASTER, "--gateway-check-url", gw.url))
                self.assertEqual(code, 0, err)
                self.assertEqual(json.loads(out)["gateway_tokens"], 950)
                self.assertNotIn(MASTER, err)

    def test_required_args(self):
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                a6.parse_args(["--url", "http://x"])
            with self.assertRaises(SystemExit):
                a6.parse_args(["--target", "opencode", "--url", "http://x"])

    def gateway_args(self, oh, gw, *extra):
        return self.base_args(oh, "--gateway-admin-key", MASTER, "--gateway-check-url", gw.url, *extra)

    def test_unknown_usage_shape_fails_without_gateway_evidence(self):
        with seeded(FakeOpenHands(SESSION, self.tmp.name, record_tokens="unknown-shape")) as oh:
            code, _, err = self.run_a6(self.base_args(oh))
            self.assertEqual(code, 1)
            self.assertIn("unknown shape", err)

    def test_gateway_corroborates_unknown_usage_shape(self):
        with FakeLiteLLM(MASTER) as gw, seeded(FakeOpenHands(SESSION, self.tmp.name, record_tokens="unknown-shape")) as oh:
            gw.add_key(VKEY, key_alias="coding-agent")
            gw.add_key("sk-" + "99" * 32, key_alias="other-app")
            gw.record_usage(VKEY, 400, 20, at=time.time() + 1)
            gw.record_usage("sk-" + "99" * 32, 7000, 7000, at=time.time() + 1)
            code, out, err = self.run_a6(self.gateway_args(oh, gw))
            self.assertEqual(code, 0, err)
            summary = json.loads(out)
            self.assertEqual((summary["prompt_tokens"], summary["gateway_tokens"]), (None, 420))
            logs = [c for c in gw.calls if c[1].startswith("/spend/logs")]
            self.assertIn("api_key=" + hashlib.sha256(VKEY.encode()).hexdigest(), logs[0][1])
            self.assertNotIn(VKEY, logs[0][1])

    def test_gateway_without_tokens_for_this_run_fails(self):
        with FakeLiteLLM(MASTER) as gw, seeded(FakeOpenHands(SESSION, self.tmp.name)) as oh:
            gw.add_key(VKEY, key_alias="coding-agent")
            gw.record_usage(VKEY, 400, 20, at=time.time() - 3600)  # an earlier run
            code, _, err = self.run_a6(self.gateway_args(oh, gw))
            self.assertEqual(code, 1)
            self.assertIn("llm-gateway logged no tokens", err)

    def test_gateway_rejecting_the_admin_key_fails(self):
        with FakeLiteLLM("sk-" + "00" * 32) as gw, seeded(FakeOpenHands(SESSION, self.tmp.name)) as oh:
            code, _, err = self.run_a6(self.gateway_args(oh, gw))
            self.assertEqual(code, 1)
            self.assertIn("/spend/logs: HTTP 401", err)

    def test_time_parsing(self):
        self.assertEqual(a6.parse_time("1970-01-01T00:00:10Z"), 10.0)
        self.assertEqual(a6.parse_time("1970-01-01T00:00:10.500000+00:00"), 10.5)
        self.assertEqual(a6.parse_time("1970-01-01T00:00:10"), 10.0)
        self.assertIsNone(a6.parse_time("yesterday"))
        self.assertIsNone(a6.parse_time(None))
        self.assertEqual(a6.row_tokens({"total_tokens": 0, "prompt_tokens": 3, "completion_tokens": 4}), 7)

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
