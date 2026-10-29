#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Tests for import-and-measure.sh's release checks (supply-7), in --dry-run.

The script must verify the Sigstore bundles of the identity and the disk
tarball (cosign keyless, os-image.yml at the os-image-v<version> tag) and the
tarball sha256 before it imports or boots anything. gcloud, cosign, the mtools
and sgdisk are fakes that log their arguments, and the osimage helper is a stub,
so this runs anywhere with bash and Python.
Run: python3 -I -m unittest discover -s runtime/images/dstack-os -p 'test_*.py'
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "import-and-measure.sh")
VERSION = "0.6.1-s2"
SIGNER = "https://github.com/sealedtempo/sealed/.github/workflows/os-image.yml@refs/tags/os-image-v"
ISSUER = "https://token.actions.githubusercontent.com"

FAKE_LOGGING_TOOL = """#!/bin/sh
echo "$(basename "$0") $*" >>"$FAKE_LOG"
"""

# Accepts a bundle unless its blob's path contains $FAKE_COSIGN_REJECT, like a
# signature from another identity or over other bytes.
FAKE_COSIGN = """#!/bin/sh
echo "cosign $*" >>"$FAKE_LOG"
for last in "$@"; do :; done
case "$last" in
  *"${FAKE_COSIGN_REJECT:-/nothing/}"*) echo "none of the expected identities matched" >&2; exit 1 ;;
esac
"""

FAKE_OSIMAGE = """#!/bin/sh
case "$1" in
  nonce) echo 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff ;;
  *) echo '{}' ;;
esac
"""


class ImportAndMeasureTest(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="import-measure-test-")
        self.bin = os.path.join(self.work, "bin")
        os.makedirs(self.bin)
        for name, body in (("gcloud", FAKE_LOGGING_TOOL), ("mformat", FAKE_LOGGING_TOOL), ("mcopy", FAKE_LOGGING_TOOL),
                           ("sgdisk", FAKE_LOGGING_TOOL), ("cosign", FAKE_COSIGN), ("osimage", FAKE_OSIMAGE)):
            path = os.path.join(self.bin, name)
            with open(path, "w") as f:
                f.write(body)
            os.chmod(path, 0o755)
        self.log = os.path.join(self.work, "calls.log")
        self.assets = os.path.join(self.work, "assets")
        os.makedirs(self.assets)
        base = os.path.join(self.assets, f"sealed-dstack-os-{VERSION}")
        self.tarball = base + "-gce.tar.gz"
        with open(self.tarball, "wb") as f:
            f.write(b"not really a disk")
        with open(self.tarball, "rb") as f:
            sha = hashlib.sha256(f.read()).hexdigest()
        doc = {"name": "sealed-dstack-os", "variant": "prod", "sealedOsVersion": VERSION, "osImageHash": "ab" * 32,
               "gceTarball": {"sha256": sha}}
        self.identity_json = base + "-identity.json"
        with open(self.identity_json, "w") as f:
            json.dump(doc, f)
        self.identity_tgz = base + "-identity.tar.gz"
        with tarfile.open(self.identity_tgz, "w:gz") as t:
            t.add(self.identity_json, arcname="image-identity.json")
        for f in (self.tarball, self.identity_json, self.identity_tgz):
            with open(f + ".sigstore.json", "w") as b:
                b.write("{}")

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def run_script(self, *extra, identity=None, release_base="https://github.com/sealedtempo/sealed/releases/download", env=None):
        open(self.log, "w").close()
        args = ["bash", SCRIPT, "--project", "p", "--zone", "us-central1-a", "--bucket", "gs://b",
                "--tarball", self.tarball, "--identity", identity or self.identity_json,
                "--osimage", os.path.join(self.bin, "osimage"), "--work", os.path.join(self.work, "measure"), "--dry-run"]
        if release_base:
            args += ["--release-base", release_base]
        args += list(extra)
        e = {"PATH": f"{self.bin}:{os.path.dirname(sys.executable)}:/usr/bin:/bin", "FAKE_LOG": self.log,
             "HOME": self.work, "TMPDIR": self.work}
        e.update(env or {})
        res = subprocess.run(args, capture_output=True, text=True, env=e, check=False)
        with open(self.log) as f:
            calls = f.read().splitlines()
        return res, [c for c in calls if c.startswith("cosign ")], res.stdout.count("DRY-RUN gcloud compute images create")

    def test_signed_release_is_verified_before_import(self):
        for identity in (self.identity_json, self.identity_tgz):
            res, cosign, creates = self.run_script(identity=identity)
            self.assertEqual(res.returncode, 0, res.stderr)
            regexp = "^" + SIGNER.replace(".", "\\.") + "[0-9A-Za-z.+_-]+$"
            self.assertEqual(cosign, [
                f"cosign verify-blob --bundle {identity}.sigstore.json --certificate-identity-regexp {regexp} "
                f"--certificate-oidc-issuer {ISSUER} {identity}",
                f"cosign verify-blob --bundle {identity}.sigstore.json --certificate-identity {SIGNER}{VERSION} "
                f"--certificate-oidc-issuer {ISSUER} {identity}",
                f"cosign verify-blob --bundle {self.tarball}.sigstore.json --certificate-identity {SIGNER}{VERSION} "
                f"--certificate-oidc-issuer {ISSUER} {self.tarball}",
            ])
            self.assertEqual(creates, 3)  # the boot image and the two auxiliary disks
            self.assertIn(f"signed by os-image.yml of sealedtempo/sealed at os-image-v{VERSION}", res.stderr)

    def test_missing_signature_stops_before_import(self):
        for f in (self.tarball, self.identity_json):
            os.rename(f + ".sigstore.json", f + ".moved")
            res, _, creates = self.run_script()
            os.rename(f + ".moved", f + ".sigstore.json")
            self.assertNotEqual(res.returncode, 0)
            self.assertIn(f"no signature {f}.sigstore.json", res.stderr)
            self.assertEqual(creates, 0)

    def test_bad_signature_stops_before_import(self):
        for f in (self.tarball, self.identity_json):
            res, _, creates = self.run_script(env={"FAKE_COSIGN_REJECT": os.path.basename(f)})
            self.assertNotEqual(res.returncode, 0)
            self.assertIn(f"{f} is not signed by os-image.yml of sealedtempo/sealed", res.stderr)
            self.assertEqual(creates, 0)

    def test_sha256_mismatch_stops_before_import(self):
        with open(self.tarball, "ab") as f:
            f.write(b"x")
        res, cosign, creates = self.run_script()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("does not match the identity", res.stderr)
        self.assertEqual(len(cosign), 3)
        self.assertEqual(creates, 0)

    def test_signer_repository(self):
        res, cosign, _ = self.run_script(release_base="https://github.com/acme/os-fork/releases/download")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("--certificate-identity https://github.com/acme/os-fork/.github/workflows/os-image.yml"
                      f"@refs/tags/os-image-v{VERSION} ", cosign[2])
        res, cosign, _ = self.run_script("--repo", "acme/other", "--source-uri", "https://example.com/os.tar.gz", release_base=None)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("https://github.com/acme/other/.github/workflows/os-image.yml", cosign[2])
        res, _, _ = self.run_script("--repo", "not a repo")
        self.assertNotEqual(res.returncode, 0)

    def test_allow_unsigned_skips_cosign_and_says_so(self):
        for f in (self.tarball, self.identity_json):
            os.remove(f + ".sigstore.json")
        res, cosign, creates = self.run_script("--allow-unsigned")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(cosign, [])
        self.assertIn("WARNING: --allow-unsigned", res.stderr)
        self.assertEqual(creates, 3)


if __name__ == "__main__":
    unittest.main()
