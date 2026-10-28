"""Tests for dockerfile_lint.py, the Dockerfile reader the packaging tests use."""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import dockerfile_lint  # noqa: E402


class DockerfileReaderTest(unittest.TestCase):
    def test_stages_and_env(self):
        text = (
            "# syntax=docker/dockerfile:1.7\nARG BASE=img:1@sha256:" + "a" * 64 + "\n"
            "FROM --platform=linux/amd64 ${BASE} AS one\nRUN echo a \\\n    && echo b\nENV A=1 \\\n    B=two\n"
            "FROM scratch\nCOPY --from=one / /\nENTRYPOINT [\"/bin/x\", \"-y\"]\n"
        )
        args, stages = dockerfile_lint.stages(text)
        self.assertEqual(stages[0].base, "img:1@sha256:" + "a" * 64)
        self.assertEqual(stages[0].name, "one")
        self.assertEqual(stages[0].all("RUN"), ["echo a      && echo b"])
        self.assertEqual(stages[0].env(), {"A": "1", "B": "two"})
        self.assertEqual(stages[1].exec_form("ENTRYPOINT"), ["/bin/x", "-y"])
        self.assertTrue(dockerfile_lint.is_digest_pinned(stages[0].base))
        self.assertFalse(dockerfile_lint.is_digest_pinned("img:latest"))


if __name__ == "__main__":
    unittest.main()
