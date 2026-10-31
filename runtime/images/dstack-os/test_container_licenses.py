#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""sysbox and the container stack ship the Go and project license texts (review policy-5).

sysbox-runc, sysbox-fs, sysbox-mgr, nerdctl, the CNI plugins and
stargz-snapshotter are Go binaries staged into the rootfs by hand, not Debian
packages, so mkosi.postinst never records their copyright and the prod profile
deletes /usr/share/doc. Patch 0008 makes the two upstream component builds
sha256 check and install Go's LICENSE and PATENTS and each project's own
LICENSE under /usr/share/licenses, where check_image.py requires them on both
disks. The container-stack texts are pinned in the overlay (the release
tarballs carry none); the sysbox texts come from the pinned source checkouts.
Run: python3 -I -m unittest discover -s runtime/images/dstack-os -p 'test_*.py'
"""

import glob
import hashlib
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import check_image  # noqa: E402

PATCH = glob.glob(os.path.join(HERE, "patches", "0008-*.patch"))
OVERLAY = os.path.join(HERE, "overlay", "os", "mkosi", "components", "container-stack", "licenses")
# Go's texts as golang/go has them at go1.26.2 (the toolchain the OS image pins) and go1.27.3:
# git blobs 2a7cf70d (LICENSE) and 73309904 (PATENTS); llm-gateway keeps the checked copies.
GO_TEXTS = os.path.join(HERE, "..", "..", "..", "catalog", "apps", "llm-gateway", "LICENSES")

GO_LICENSE_SHA = "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad"
GO_PATENTS_SHA = "96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc"

# Each hand-staged binary's license text: installed path -> (sha256 the build checks,
# git blob at the pinned upstream). The container-stack project texts are committed in
# the overlay and recomputed below; the Go and sysbox shas are what the build checks.
EXPECTED = {
    "usr/share/licenses/sysbox/go/LICENSE": (GO_LICENSE_SHA, "2a7cf70da6e498df9c11ab6a5eaa2ddd7af34da4"),
    "usr/share/licenses/sysbox/go/PATENTS": (GO_PATENTS_SHA, "733099041f84fa1e58611ab2e11af51c1f26d1d2"),
    "usr/share/licenses/sysbox/sysbox-runc-LICENSE":
        ("b6ebde6849218d10473832460729fc47104a5ef1d77c194974983c131aa8a777", "385b1fd2b63ca6a979e349d576bff90d06b308dd"),
    "usr/share/licenses/sysbox/sysbox-fs-LICENSE":
        ("d654e7d0229420c56e7cc790b251d0bb90248f509113aca960c182b70311d9ac", "c6087d5be51bdee7e9b24341e2882ec260b4f2a5"),
    "usr/share/licenses/sysbox/sysbox-mgr-LICENSE":
        ("d654e7d0229420c56e7cc790b251d0bb90248f509113aca960c182b70311d9ac", "c6087d5be51bdee7e9b24341e2882ec260b4f2a5"),
    "usr/share/licenses/container-stack/go/LICENSE": (GO_LICENSE_SHA, "2a7cf70da6e498df9c11ab6a5eaa2ddd7af34da4"),
    "usr/share/licenses/container-stack/go/PATENTS": (GO_PATENTS_SHA, "733099041f84fa1e58611ab2e11af51c1f26d1d2"),
    "usr/share/licenses/container-stack/nerdctl-LICENSE":
        ("cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30", "d645695673349e3947e8e5ae42332d0ac3164cd7"),
    "usr/share/licenses/container-stack/cni-plugins-LICENSE":
        ("b40930bbcf80744c86c46a12bc9da056641d722716c378f5659b9e555ef833e1", "8dada3edaf50dbc082c9a125058f25def75e625a"),
    "usr/share/licenses/container-stack/stargz-snapshotter-LICENSE":
        ("cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30", "d645695673349e3947e8e5ae42332d0ac3164cd7"),
}

# The committed overlay file for each container-stack project text.
OVERLAY_TEXTS = {
    "usr/share/licenses/container-stack/nerdctl-LICENSE": "nerdctl-LICENSE",
    "usr/share/licenses/container-stack/cni-plugins-LICENSE": "cni-plugins-LICENSE",
    "usr/share/licenses/container-stack/stargz-snapshotter-LICENSE": "stargz-snapshotter-LICENSE",
}


def git_blob(data):
    return hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()


def patch_files(text):
    """{path: [new-side lines]} for each file in a unified-diff patch (context + added)."""
    files, path, lines = {}, None, None
    for line in text.splitlines():
        if line.startswith("+++ b/"):
            path = line[len("+++ b/"):]
            lines = files.setdefault(path, [])
        elif path is not None and line[:1] in (" ", "+") and not line.startswith("+++"):
            lines.append(line[1:])
    return files


class ContainerLicensesTest(unittest.TestCase):
    def test_check_image_requires_every_path(self):
        self.assertEqual(check_image.REQUIRED_LICENSES, list(EXPECTED))
        # The required list is enforced in both variants, not only in one.
        for path in check_image.REQUIRED_LICENSES:
            self.assertFalse(path in check_image.DEBUG_ONLY, f"{path} must not be debug-only")

    def test_go_shas_match_the_checked_copies(self):
        for name, sha, blob in (("LICENSE", GO_LICENSE_SHA, "2a7cf70da6e498df9c11ab6a5eaa2ddd7af34da4"),
                                 ("PATENTS", GO_PATENTS_SHA, "733099041f84fa1e58611ab2e11af51c1f26d1d2")):
            with open(os.path.join(GO_TEXTS, "go-1.27.3-" + name), "rb") as f:
                data = f.read()
            self.assertEqual(git_blob(data), blob, name)
            self.assertEqual(hashlib.sha256(data).hexdigest(), sha, name)

    def test_overlay_texts_are_the_pinned_upstream(self):
        for path, fname in OVERLAY_TEXTS.items():
            with open(os.path.join(OVERLAY, fname), "rb") as f:
                data = f.read()
            sha, blob = EXPECTED[path]
            self.assertEqual(git_blob(data), blob, fname)
            self.assertEqual(hashlib.sha256(data).hexdigest(), sha, fname)

    def test_patch_checks_and_installs_every_text_before_the_timestamp_pin(self):
        self.assertEqual(len(PATCH), 1, "exactly one patches/0008-*.patch")
        with open(PATCH[0], encoding="utf-8") as f:
            files = patch_files(f.read())
        self.assertIn("os/mkosi/components/sysbox/sysbox-build.sh", files)
        self.assertIn("os/mkosi/components/container-stack/container-stack-build.sh", files)

        for script, new_lines in files.items():
            stripped = [ln.strip() for ln in new_lines]
            touch = next(i for i, ln in enumerate(stripped) if ln.startswith('find "$STAGE"') and "touch" in ln)

            def before(needle, label):
                idx = next((i for i, ln in enumerate(stripped) if needle in ln), None)
                self.assertIsNotNone(idx, f"{script}: missing {label}")
                self.assertLess(idx, touch, f"{script}: {label} must run before the timestamp pin")
                return idx

            # Go's LICENSE and PATENTS: sha256 checked against GOROOT, then installed.
            self.assertIn("goroot=$(go env GOROOT)", stripped, script)
            for sha in (GO_LICENSE_SHA, GO_PATENTS_SHA):
                before(f'echo "{sha}  $goroot/', f"GOROOT sha256 check {sha[:12]}")

        # sysbox: Go texts under sysbox/go, each module's LICENSE from its checkout.
        sysbox = [ln.strip() for ln in files["os/mkosi/components/sysbox/sysbox-build.sh"]]
        self.assertIn('install -Dm0644 "$goroot/LICENSE" "$STAGE/usr/share/licenses/sysbox/go/LICENSE"', sysbox)
        self.assertIn('install -Dm0644 "$goroot/PATENTS" "$STAGE/usr/share/licenses/sysbox/go/PATENTS"', sysbox)
        self.assertIn("for mod in sysbox-runc sysbox-fs sysbox-mgr; do", sysbox)
        self.assertIn('echo "$sha  $B/$mod/LICENSE" | sha256sum -c -', sysbox)
        self.assertIn('install -Dm0644 "$B/$mod/LICENSE" "$STAGE/usr/share/licenses/sysbox/$mod-LICENSE"', sysbox)
        for mod, sha in (("sysbox-runc", EXPECTED["usr/share/licenses/sysbox/sysbox-runc-LICENSE"][0]),
                         ("sysbox-fs", EXPECTED["usr/share/licenses/sysbox/sysbox-fs-LICENSE"][0])):
            self.assertIn(sha, "\n".join(sysbox), f"{mod} sha256 not checked")

        # container-stack: Go texts under container-stack/go, each project's pinned LICENSE.
        cstack = [ln.strip() for ln in files["os/mkosi/components/container-stack/container-stack-build.sh"]]
        self.assertIn('install -Dm0644 "$goroot/LICENSE" "$STAGE/usr/share/licenses/container-stack/go/LICENSE"', cstack)
        self.assertIn('install -Dm0644 "$goroot/PATENTS" "$STAGE/usr/share/licenses/container-stack/go/PATENTS"', cstack)
        self.assertIn('LICENSES="$SELF/components/container-stack/licenses"', cstack)
        self.assertIn("for proj in nerdctl cni-plugins stargz-snapshotter; do", cstack)
        self.assertIn('echo "$sha  $LICENSES/$proj-LICENSE" | sha256sum -c -', cstack)
        self.assertIn('install -Dm0644 "$LICENSES/$proj-LICENSE" "$STAGE/usr/share/licenses/container-stack/$proj-LICENSE"', cstack)
        for path in OVERLAY_TEXTS:
            self.assertIn(EXPECTED[path][0], "\n".join(cstack), f"{path} sha256 not checked")


if __name__ == "__main__":
    unittest.main()
