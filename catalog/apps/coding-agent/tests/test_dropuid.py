"""Tests for bootstrap/dropuid.py. Root-only steps (setuid) are covered with injected getuid."""
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
PATH = os.path.join(HERE, "..", "bootstrap", "dropuid.py")
spec = importlib.util.spec_from_file_location("dropuid", PATH)
dropuid = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dropuid)


class DropUidTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = os.path.join(self.tmp.name, "workspace")
        os.mkdir(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_parse_ids(self):
        self.assertEqual(dropuid.parse_ids("10001:10001"), (10001, 10001))
        for bad in ("0:0", "10001", "a:b", "10001:0", "-1:5"):
            with self.assertRaises(dropuid.DropError, msg=bad):
                dropuid.parse_ids(bad)

    def test_owned_dirs(self):
        self.assertEqual(dropuid.owned_dirs(" /workspace, /workspace/project ,"), ["/workspace", "/workspace/project"])
        for bad in ("workspace", "/workspace/../etc"):
            with self.assertRaises(dropuid.DropError):
                dropuid.owned_dirs(bad)

    def test_prepare_creates_and_chowns(self):
        dirs = [self.root, os.path.join(self.root, "project"), os.path.join(self.root, ".openhands")]
        uid, gid = os.getuid(), os.getgid()
        dropuid.prepare(dirs, uid, gid)
        for d in dirs:
            st = os.lstat(d)
            self.assertTrue(stat.S_ISDIR(st.st_mode))
            self.assertEqual((st.st_uid, st.st_gid), (uid, gid))

    def test_prepare_replaces_planted_symlink(self):
        target = os.path.join(self.tmp.name, "etc")
        os.mkdir(target)
        link = os.path.join(self.root, ".sealed")
        os.symlink(target, link)
        calls = []
        real_chown = os.chown

        def spy(path, uid, gid, follow_symlinks=True):
            calls.append((path, follow_symlinks))
            real_chown(path, uid, gid, follow_symlinks=follow_symlinks)

        with mock.patch.object(dropuid.os, "chown", spy):
            dropuid.prepare([link], os.getuid(), os.getgid())
        self.assertFalse(os.path.islink(link))
        self.assertTrue(os.path.isdir(link))
        self.assertEqual(calls, [(link, False)])
        self.assertTrue(os.path.isdir(target))

    def test_prepare_rejects_files(self):
        path = os.path.join(self.root, "project")
        with open(path, "w") as handle:
            handle.write("x")
        with self.assertRaises(dropuid.DropError):
            dropuid.prepare([path], os.getuid(), os.getgid())

    def run_main(self, argv, env, uid, no_new_privs=None):
        calls = []
        err = io.StringIO()

        def nnp():
            calls.append("no_new_privs")
            if no_new_privs is not None:
                no_new_privs()

        with redirect_stderr(err):
            code = dropuid.main(argv, env=env, execvp=lambda f, a: calls.append((f, a)), getuid=lambda: uid,
                                no_new_privs=nnp)
        return code, calls, err.getvalue()

    def test_main_as_root_prepares_drops_and_execs(self):
        env = {"SEALED_RUN_AS": "10001:10001", "SEALED_OWNED_DIRS": self.root}
        with mock.patch.object(dropuid, "prepare") as prep, mock.patch.object(dropuid, "drop") as drop:
            code, calls, _ = self.run_main(["-c", "tini", "--", "server", "--port", "8000"], env, 0)
        self.assertEqual(code, 0)
        prep.assert_called_once_with([self.root], 10001, 10001)
        drop.assert_called_once_with(10001, 10001)
        self.assertEqual(calls, ["no_new_privs", ("tini", ["tini", "--", "server", "--port", "8000"])])
        self.assertIn("HOME", env)

    def test_main_already_target_user_skips_drop(self):
        env = {"SEALED_RUN_AS": "10001:10001", "SEALED_OWNED_DIRS": self.root}
        with mock.patch.object(dropuid, "prepare") as prep, mock.patch.object(dropuid, "drop") as drop:
            code, calls, _ = self.run_main(["-c", "opencode", "serve"], env, 10001)
        self.assertEqual(code, 0)
        prep.assert_not_called()
        drop.assert_not_called()
        self.assertEqual(calls, ["no_new_privs", ("opencode", ["opencode", "serve"])])

    def test_no_new_privs_failure_aborts_before_exec(self):
        def fail():
            raise dropuid.DropError("prctl(PR_SET_NO_NEW_PRIVS) failed: errno 22")

        env = {"SEALED_RUN_AS": "10001:10001", "SEALED_OWNED_DIRS": self.root}
        with mock.patch.object(dropuid, "prepare"), mock.patch.object(dropuid, "drop"):
            code, calls, err = self.run_main(["-c", "tini"], env, 0, no_new_privs=fail)
        self.assertEqual((code, calls), (1, ["no_new_privs"]))
        self.assertIn("PR_SET_NO_NEW_PRIVS", err)

    def test_set_no_new_privs_uses_prctl(self):
        libc = mock.Mock()
        libc.prctl.side_effect = [0, 1]
        with mock.patch.object(dropuid.sys, "platform", "linux"), \
                mock.patch.object(dropuid.ctypes, "CDLL", return_value=libc):
            dropuid.set_no_new_privs()
        self.assertEqual([c.args for c in libc.prctl.call_args_list], [(38, 1, 0, 0, 0), (39, 0, 0, 0, 0)])
        libc.prctl.side_effect = [0, 0]
        with mock.patch.object(dropuid.sys, "platform", "linux"), \
                mock.patch.object(dropuid.ctypes, "CDLL", return_value=libc):
            with self.assertRaises(dropuid.DropError):
                dropuid.set_no_new_privs()
        libc.prctl.side_effect = [-1]
        with mock.patch.object(dropuid.sys, "platform", "linux"), \
                mock.patch.object(dropuid.ctypes, "CDLL", return_value=libc):
            with self.assertRaises(dropuid.DropError):
                dropuid.set_no_new_privs()
        with mock.patch.object(dropuid.sys, "platform", "darwin"):
            with self.assertRaises(dropuid.DropError):
                dropuid.set_no_new_privs()

    def test_main_wrong_user_and_usage(self):
        code, calls, err = self.run_main(["-c", "x"], {"SEALED_RUN_AS": "10001:10001"}, 501)
        self.assertEqual((code, calls), (1, []))
        self.assertIn("expected root or 10001", err)
        self.assertEqual(self.run_main(["-c"], {}, 0)[0], 2)

    def test_drop_refuses_when_root_can_be_regained(self):
        with mock.patch.multiple(dropuid.os, setgroups=mock.DEFAULT, setgid=mock.DEFAULT, setuid=mock.DEFAULT,
                                 getuid=mock.DEFAULT, geteuid=mock.DEFAULT, getgid=mock.DEFAULT) as m:
            m["getuid"].return_value = 10001
            m["geteuid"].return_value = 10001
            m["getgid"].return_value = 10001
            with self.assertRaises(dropuid.DropError):
                dropuid.drop(10001, 10001)
            m["setgroups"].assert_called_once_with([])

    def test_drop_succeeds_when_root_is_gone(self):
        with mock.patch.multiple(dropuid.os, setgroups=mock.DEFAULT, setgid=mock.DEFAULT, setuid=mock.DEFAULT,
                                 getuid=mock.DEFAULT, geteuid=mock.DEFAULT, getgid=mock.DEFAULT) as m:
            m["getuid"].return_value = 10001
            m["geteuid"].return_value = 10001
            m["getgid"].return_value = 10001
            m["setuid"].side_effect = [None, PermissionError()]
            dropuid.drop(10001, 10001)
            self.assertEqual([c.args for c in m["setuid"].call_args_list], [(10001,), (0,)])

    def test_source_is_embeddable(self):
        with open(PATH) as handle:
            text = handle.read()
        self.assertNotIn("$", text)
        self.assertNotIn("\t", text)


if __name__ == "__main__":
    unittest.main()
