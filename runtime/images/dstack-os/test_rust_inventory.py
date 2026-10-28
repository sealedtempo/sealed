#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Tests for rust_inventory.py on a synthetic cargo metadata document."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rust_inventory  # noqa: E402


def pkg(name, lic, license_file=None):
    return {"id": f"{name} 1.0.0", "name": name, "version": "1.0.0", "license": lic, "license_file": license_file}


def dep(name, kind=None):
    return {"pkg": f"{name} 1.0.0", "dep_kinds": [{"kind": kind}]}


def metadata(extra_pkgs, edges):
    shipped = [pkg(n, "Apache-2.0") for n in rust_inventory.SHIPPED]
    pkgs = shipped + [pkg("dstack-kms", "Apache-2.0")] + extra_pkgs
    nodes = [{"id": p["id"], "deps": edges.get(p["name"], [])} for p in pkgs]
    return {"packages": pkgs, "resolve": {"nodes": nodes}, "workspace_members": [p["id"] for p in shipped] + ["dstack-kms 1.0.0"]}


class RustInventoryTest(unittest.TestCase):
    def test_closure_and_findings(self):
        meta = metadata(
            [pkg("serde", "MIT OR Apache-2.0"), pkg("unicode-ident", "(MIT OR Apache-2.0) AND Unicode-3.0"),
             pkg("evil", "BUSL-1.1"), pkg("devonly", "SSPL-1.0"), pkg("buildonly", "Proprietary"),
             pkg("kmsonly", "SSPL-1.0"), pkg("nolicense", None), pkg("filelicense", None, "LICENSE")],
            {"dstack-util": [dep("serde"), dep("devonly", "dev"), dep("buildonly", "build")],
             "serde": [dep("unicode-ident"), dep("evil"), dep("nolicense"), dep("filelicense")],
             "dstack-kms": [dep("kmsonly")]},
        )
        report = rust_inventory.inventory(meta)
        names = {c["name"] for c in report["crates"]}
        self.assertNotIn("devonly", names)
        self.assertNotIn("buildonly", names)
        self.assertNotIn("kmsonly", names)  # dstack-kms is not shipped in the guest
        self.assertIn("unicode-ident", names)
        self.assertEqual(report["violations"], ["evil 1.0.0: banned license BUSL-1.1", "nolicense 1.0.0: no SPDX license expression"])
        self.assertEqual(report["review"], ["filelicense 1.0.0: no SPDX license expression",
                                            "unicode-ident 1.0.0: (MIT OR Apache-2.0) AND Unicode-3.0"])

    def test_license_expressions(self):
        for expr, ok in [("MIT OR Apache-2.0", True), ("MIT/Apache-2.0", True), ("Apache-2.0 WITH LLVM-exception", True),
                         ("ISC AND OpenSSL", False), ("(MIT", False), ("GPL-3.0+", True), ("MPL-2.0 AND BSD-3-Clause", True)]:
            self.assertEqual(rust_inventory.license_ok(expr), ok, expr)


if __name__ == "__main__":
    unittest.main()
