#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""sealed-logship ships the Go LICENSE and PATENTS (review policy-5).

sealed-logship, in the debug variant, is a Go binary, so it links the Go
standard library (BSD-3-Clause), whose notice and patent grant a binary
redistribution must carry. Its component build script must check that
GOROOT's LICENSE and PATENTS are Go's texts byte for byte and install them
where check_image.py requires them on the published debug disk.
Run: python3 -I -m unittest discover -s runtime/images/dstack-os -p 'test_*.py'
"""

import hashlib
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import check_image  # noqa: E402

BUILD = os.path.join(HERE, "overlay", "os", "mkosi", "components", "sealed-logship", "sealed-logship-build.sh")
# Go's texts as golang/go has them at go1.26.2 (the toolchain upstream's versions.env pins) and
# go1.27.3: git blobs 2a7cf70d (LICENSE) and 73309904 (PATENTS); llm-gateway's tests check the copies.
TEXTS = os.path.join(HERE, "..", "..", "..", "catalog", "apps", "llm-gateway", "LICENSES")


def git_blob(data):
    return hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()


class LogshipLicensesTest(unittest.TestCase):
    def test_build_checks_and_installs_the_go_texts(self):
        with open(BUILD, encoding="utf-8") as f:
            script = f.read()
        lines = [line.strip() for line in script.splitlines()]
        self.assertIn("goroot=$(go env GOROOT)", lines)
        touch = next(i for i, line in enumerate(lines) if line.startswith('find "$STAGE"') and "touch" in line)
        for name, blob in (("LICENSE", "2a7cf70da6e498df9c11ab6a5eaa2ddd7af34da4"),
                           ("PATENTS", "733099041f84fa1e58611ab2e11af51c1f26d1d2")):
            with open(os.path.join(TEXTS, "go-1.27.3-" + name), "rb") as f:
                data = f.read()
            self.assertEqual(git_blob(data), blob, name)
            check = f'echo "{hashlib.sha256(data).hexdigest()}  $goroot/{name}" | sha256sum -c -'
            self.assertIn(check, lines, f"the build does not check the sha256 of GOROOT's {name}")
            path = f"usr/share/licenses/sealed-logship/go/{name}"
            self.assertIn(path, check_image.DEBUG_ONLY, f"check_image.py does not require {path} in the debug image")
            install = f'install -Dm0644 "$goroot/{name}" "$STAGE/{path}"'
            self.assertIn(install, lines, f"the build does not install {name} at /{path}")
            self.assertLess(lines.index(check), lines.index(install))
            # Before the timestamps of the staging tree are pinned.
            self.assertLess(lines.index(install), touch)

    def test_every_debug_only_license_is_installed(self):
        with open(BUILD, encoding="utf-8") as f:
            script = f.read()
        installed = set(re.findall(r'"\$STAGE/(usr/share/licenses/[^"]+)"', script))
        required = {p for p in check_image.DEBUG_ONLY if p.startswith("usr/share/licenses/")}
        self.assertEqual(installed, required)


if __name__ == "__main__":
    unittest.main()
