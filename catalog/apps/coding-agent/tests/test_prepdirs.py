"""Tests for bootstrap/prepdirs.py, the non-root directory preparation before the agent starts."""
from __future__ import annotations

import importlib.util
import io
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
PATH = os.path.join(HERE, "..", "bootstrap", "prepdirs.py")
spec = importlib.util.spec_from_file_location("prepdirs", PATH)
prepdirs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepdirs)


class PrepDirsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = os.path.join(self.tmp.name, "workspace")
        os.mkdir(self.root)
        self.me = (os.getuid(), os.getgid())

    def tearDown(self):
        self.tmp.cleanup()

    def env(self, **extra):
        env = {"SEALED_RUN_AS": "%d:%d" % self.me,
               "SEALED_OWNED_DIRS": ",".join([self.root, os.path.join(self.root, "project")])}
        env.update(extra)
        return env

    def run_main(self, argv, env, ids=None, no_new_privs=None):
        calls = []
        err = io.StringIO()
        uid, gid = ids or self.me

        def nnp():
            calls.append("no_new_privs")
            if no_new_privs is not None:
                no_new_privs()

        with redirect_stderr(err):
            code = prepdirs.main(argv, env=env, execvp=lambda f, a: calls.append((f, a)), getuid=lambda: uid,
                                 getgid=lambda: gid, no_new_privs=nnp, chdir=lambda p: calls.append(("chdir", p)))
        return code, calls, err.getvalue()

    def test_parse_ids(self):
        self.assertEqual(prepdirs.parse_ids("10001:10001"), (10001, 10001))
        for bad in ("0:0", "10001", "a:b", "10001:0", "-1:5"):
            with self.assertRaises(prepdirs.PrepError, msg=bad):
                prepdirs.parse_ids(bad)

    def test_owned_dirs(self):
        self.assertEqual(prepdirs.owned_dirs(" /workspace, /workspace/project ,"), ["/workspace", "/workspace/project"])
        for bad in ("workspace", "/workspace/../etc"):
            with self.assertRaises(prepdirs.PrepError):
                prepdirs.owned_dirs(bad)

    def test_prepare_creates_missing_directories_as_the_current_user(self):
        dirs = [self.root, os.path.join(self.root, "project"), os.path.join(self.root, ".openhands")]
        prepdirs.prepare(dirs, os.getuid())
        for d in dirs:
            st = os.lstat(d)
            self.assertTrue(stat.S_ISDIR(st.st_mode))
            self.assertEqual(st.st_uid, os.getuid())
        prepdirs.prepare(dirs, os.getuid())  # idempotent

    def test_prepare_replaces_a_planted_symlink_without_following_it(self):
        target = os.path.join(self.tmp.name, "etc")
        os.mkdir(target)
        link = os.path.join(self.root, ".openhands")
        os.symlink(target, link)
        prepdirs.prepare([link], os.getuid())
        self.assertFalse(os.path.islink(link))
        self.assertTrue(os.path.isdir(link))
        self.assertEqual(os.listdir(target), [])

    def test_prepare_rejects_files_and_foreign_owners(self):
        path = os.path.join(self.root, "project")
        with open(path, "w") as handle:
            handle.write("x")
        with self.assertRaises(prepdirs.PrepError):
            prepdirs.prepare([path], os.getuid())
        with self.assertRaises(prepdirs.PrepError) as ctx:
            prepdirs.prepare([self.root], os.getuid() + 1)
        self.assertIn("x-sealed-owner", str(ctx.exception))

    def test_main_prepares_and_execs_as_the_runtime_user(self):
        env = self.env()
        code, calls, err = self.run_main(["-c", "tini", "--", "server", "--port", "8000"], env)
        self.assertEqual(code, 0, err)
        self.assertTrue(os.path.isdir(os.path.join(self.root, "project")))
        self.assertEqual(calls, ["no_new_privs", ("tini", ["tini", "--", "server", "--port", "8000"])])
        self.assertIn("HOME", env)

    def test_main_changes_to_the_workdir(self):
        project = os.path.join(self.root, "project")
        code, calls, err = self.run_main(["-c", "opencode", "serve"], self.env(SEALED_WORKDIR=project))
        self.assertEqual(code, 0, err)
        self.assertEqual(calls, ["no_new_privs", ("chdir", project), ("opencode", ["opencode", "serve"])])
        code, calls, err = self.run_main(["-c", "x"], self.env(SEALED_WORKDIR="/etc"))
        self.assertEqual((code, calls), (1, []))
        self.assertIn("SEALED_WORKDIR", err)

    def test_main_refuses_root_and_other_users(self):
        code, calls, err = self.run_main(["-c", "tini"], self.env(), ids=(0, 0))
        self.assertEqual((code, calls), (1, []))
        self.assertIn("runs as root", err)
        code, calls, err = self.run_main(["-c", "tini"], self.env(), ids=(self.me[0] + 1, self.me[1]))
        self.assertEqual((code, calls), (1, []))
        self.assertIn("expected", err)
        self.assertEqual(self.run_main(["-c"], {})[0], 2)

    def test_no_new_privs_failure_aborts_before_exec(self):
        def fail():
            raise prepdirs.PrepError("prctl(PR_SET_NO_NEW_PRIVS) failed: errno 22")

        code, calls, err = self.run_main(["-c", "tini"], self.env(), no_new_privs=fail)
        self.assertEqual((code, calls), (1, ["no_new_privs"]))
        self.assertIn("PR_SET_NO_NEW_PRIVS", err)

    def test_set_no_new_privs_uses_prctl(self):
        libc = mock.Mock()
        libc.prctl.side_effect = [0, 1]
        with mock.patch.object(prepdirs.sys, "platform", "linux"), \
                mock.patch.object(prepdirs.ctypes, "CDLL", return_value=libc):
            prepdirs.set_no_new_privs()
        self.assertEqual([c.args for c in libc.prctl.call_args_list], [(38, 1, 0, 0, 0), (39, 0, 0, 0, 0)])
        for effects in ([0, 0], [-1]):
            libc.prctl.side_effect = effects
            with mock.patch.object(prepdirs.sys, "platform", "linux"), \
                    mock.patch.object(prepdirs.ctypes, "CDLL", return_value=libc):
                with self.assertRaises(prepdirs.PrepError):
                    prepdirs.set_no_new_privs()
        with mock.patch.object(prepdirs.sys, "platform", "darwin"):
            with self.assertRaises(prepdirs.PrepError):
                prepdirs.set_no_new_privs()

    def test_source_is_embeddable_and_never_changes_owners(self):
        with open(PATH) as handle:
            text = handle.read()
        self.assertNotIn("$", text)
        self.assertNotIn("\t", text)
        for call in ("chown", "setuid", "setgid", "setgroups"):
            self.assertNotIn("os." + call, text)


if __name__ == "__main__":
    unittest.main()
