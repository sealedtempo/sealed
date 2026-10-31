#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Tests for check_image.py on synthetic disk images.

Builds a GPT disk shaped like dstack's UKI disk (ESP with the UKI, squashfs
rootfs), once clean and once with NVIDIA, ZFS and CDDL content, and checks the
findings. Needs mksquashfs/unsquashfs, sgdisk and mtools; skipped without them.
Run: python3 -I -m unittest discover -s runtime/images/dstack-os -p 'test_*.py'
"""

import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check_image  # noqa: E402

TOOLS = ("mksquashfs", "unsquashfs", "sgdisk", "mformat", "mcopy", "mmd", "mdir")


def elf(sections):
    """A minimal ELF64 LSB relocatable file with the given (name, type, data, link_name) sections."""
    names = b"\0" + b"".join(n.encode() + b"\0" for n, _, _, _ in sections) + b".shstrtab\0"
    blobs, offset = [], 64
    layout = []
    for name, typ, data, link in sections:
        layout.append((name, typ, offset, len(data), link))
        blobs.append(data)
        offset += len(data)
    shstr_off = offset
    offset += len(names)
    shoff = (offset + 7) // 8 * 8
    index = {n: i + 1 for i, (n, _, _, _) in enumerate(sections)}
    headers = [b"\0" * 64]
    for name, typ, off, size, link in layout:
        name_off = names.index(name.encode() + b"\0")
        headers.append(struct.pack("<IIQQQQIIQQ", name_off, typ, 0, 0, off, size, index.get(link, 0), 0, 1, 0))
    headers.append(struct.pack("<IIQQQQIIQQ", names.index(b".shstrtab\0"), 3, 0, 0, shstr_off, len(names), 0, 0, 1, 0))
    shnum = len(headers)
    ehdr = b"\x7fELF" + bytes([2, 1, 1]) + b"\0" * 9
    ehdr += struct.pack("<HHIQQQIHHHHHH", 1, 62, 1, 0, 0, shoff, 0, 64, 0, 0, 64, shnum, shnum - 1)
    body = ehdr + b"".join(blobs) + names
    body += b"\0" * (shoff - len(body))
    return body + b"".join(headers)


def kernel_module(license_, intree=True):
    info = b"license=" + license_.encode() + b"\0" + (b"intree=Y\0" if intree else b"") + b"vermagic=6.18.40-dstack\0"
    return elf([(".modinfo", 1, info, "")])


def linked_binary(*needed):
    dynstr = b"\0"
    dyn = b""
    for lib in needed:
        dyn += struct.pack("<qQ", 1, len(dynstr))
        dynstr += lib.encode() + b"\0"
    dyn += struct.pack("<qQ", 0, 0)
    return elf([(".dynstr", 3, dynstr, ""), (".dynamic", 6, dyn, ".dynstr")])


def write(root, rel, data, mode=0o644):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    os.chmod(path, mode)


def make_disk(work, populate):
    root = os.path.join(work, "root")
    populate(root)
    sq = os.path.join(work, "rootfs.squashfs")
    subprocess.run(["mksquashfs", root, sq, "-noappend", "-all-root", "-no-xattrs", "-no-progress", "-quiet"], check=True,
                   stdout=subprocess.DEVNULL)
    sq_mib = (os.path.getsize(sq) + (1 << 20) - 1) >> 20
    disk = os.path.join(work, "disk.raw")
    total_mib = 1 + 64 + sq_mib + 1
    with open(disk, "wb") as f:
        f.truncate(total_mib << 20)
    esp_start = 2048
    esp_end = esp_start + 64 * 2048 - 1
    root_start = esp_end + 1
    root_end = root_start + sq_mib * 2048 - 1
    subprocess.run(["sgdisk", "--zap-all", disk], check=True, capture_output=True)
    subprocess.run(["sgdisk", f"--new=1:{esp_start}:{esp_end}", "--typecode=1:ef00", "--change-name=1:EFI System Partition",
                    f"--new=2:{root_start}:{root_end}", "--typecode=2:8300", "--change-name=2:dstack-rootfs", disk],
                   check=True, capture_output=True)
    esp = os.path.join(work, "esp.img")
    with open(esp, "wb") as f:
        f.truncate(64 << 20)
    subprocess.run(["mformat", "-i", esp, "-F", "-v", "DSTACKEFI", "-T", str(64 * 2048), "-h", "64", "-s", "32", "::"], check=True)
    subprocess.run(["mmd", "-i", esp, "::/EFI", "::/EFI/BOOT"], check=True)
    uki = os.path.join(work, "BOOTX64.EFI")
    with open(uki, "wb") as f:
        f.write(b"MZ uki")
    subprocess.run(["mcopy", "-i", esp, uki, "::/EFI/BOOT/BOOTX64.EFI"], check=True)
    with open(disk, "r+b") as d:
        for img, start in ((esp, esp_start), (sq, root_start)):
            d.seek(start * 512)
            with open(img, "rb") as f:
                d.write(f.read())
    return disk


def make_inventory(work, packages):
    inv = os.path.join(work, "dstack-sealed-inventory")
    os.makedirs(os.path.join(inv, "copyright"))
    with open(os.path.join(inv, "packages.tsv"), "w") as f:
        for name, section, copyright_text in packages:
            f.write(f"{name}\t1.0\t{name.split(':')[0]}\t1.0\t{section}\tamd64\n")
            if copyright_text is not None:
                with open(os.path.join(inv, "copyright", name.split(":")[0]), "w") as c:
                    c.write(copyright_text)
    return inv


DEP5 = "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n\nFiles: *\nLicense: {}\n"


@unittest.skipUnless(all(shutil.which(t) for t in TOOLS), "needs squashfs-tools, gdisk and mtools")
class CheckImageTest(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="check-image-test-")

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def scan(self, populate, packages, exceptions=(), variant=None):
        disk = make_disk(self.work, populate)
        inv = make_inventory(self.work, packages)
        out = os.path.join(self.work, "inventory.json")
        violations = check_image.scan(disk, inv, out, list(exceptions), variant)
        with open(out) as f:
            report = json.load(f)
        return violations, report

    def test_clean_image_passes(self):
        def populate(root):
            write(root, "usr/bin/dstack-util", linked_binary("libc.so.6", "libssl.so.3"), 0o755)
            write(root, "usr/lib/modules/6.18.40-dstack/kernel/drivers/net/virtio_net.ko", kernel_module("GPL"))
            write(root, "usr/lib/modules/6.18.40-dstack/kernel/drivers/i2c/busses/i2c-nvidia-gpu.ko", kernel_module("GPL v2"))
            write(root, "etc/docker/daemon.json", b'{"runtimes": {}}')
            # Compressed data may hold the bytes "CDDL" by chance; only text files are searched for the word.
            write(root, "usr/share/data.bin", b"\x00\x01CDDL\x02")

        violations, report = self.scan(populate, [("libc6:amd64", "libs", DEP5.format("LGPL-2.1+")),
                                                  ("bash", "shells", "Copyright: GNU\nSee /usr/share/common-licenses/GPL-3\n")])
        self.assertEqual(violations, [])
        self.assertEqual(report["esp_files"], ["::/EFI/BOOT/BOOTX64.EFI"])
        self.assertEqual(report["rootfs"]["kernel_module_licenses"], {"GPL": 1, "GPL v2": 1})
        self.assertEqual(report["packages"][0]["package"], "libc6")
        self.assertEqual(report["packages"][0]["licenses"], ["LGPL-2.1+"])

    def test_nvidia_zfs_cddl_fail(self):
        def populate(root):
            write(root, "usr/bin/nvidia-smi", linked_binary("libc.so.6"), 0o755)
            write(root, "usr/bin/app", linked_binary("libnvidia-ml.so.1"), 0o755)
            write(root, "usr/sbin/zpool", b"#!/bin/sh\n", 0o755)
            write(root, "usr/lib/modules/6.18.40-dstack/extra/zfs.ko", kernel_module("CDDL", intree=False))
            write(root, "usr/lib/modules/6.18.40-dstack/kernel/drivers/video/nvidia.ko", kernel_module("Dual MIT/GPL", intree=False))
            write(root, "usr/share/doc/thing/NOTICE", b"Licensed under the CDDL\n")
            write(root, "usr/sbin/sshd", b"\x7fELF", 0o755)

        violations, _ = self.scan(populate, [("libzfs", "contrib/libs", DEP5.format("CDDL-1.0")),
                                             ("nocopyright", "admin", None)])
        found = {(v["kind"], v["subject"]) for v in violations}
        for want in [
            ("path", "usr/bin/nvidia-smi"),
            ("path", "usr/sbin/zpool"),
            ("path", "usr/lib/modules/6.18.40-dstack/extra/zfs.ko"),
            ("path", "usr/lib/modules/6.18.40-dstack/kernel/drivers/video/nvidia.ko"),
            ("kernel-module", "usr/lib/modules/6.18.40-dstack/extra/zfs.ko"),
            ("kernel-module", "usr/lib/modules/6.18.40-dstack/kernel/drivers/video/nvidia.ko"),
            ("elf-needed", "usr/bin/app"),
            ("cddl-text", "usr/share/doc/thing/NOTICE"),
            ("surface", "usr/sbin/sshd"),
            ("package-section", "libzfs"),
            ("package-license", "libzfs"),
            ("package-copyright", "nocopyright"),
        ]:
            self.assertIn(want, found)

    def test_exception_waives_a_finding(self):
        import re

        def populate(root):
            write(root, "usr/share/doc/thing/NOTICE", b"CDDL\n")

        violations, report = self.scan(populate, [], [(re.compile(r"^cddl-text:usr/share/doc/thing/NOTICE$"), "D-999")])
        self.assertEqual(violations, [])
        self.assertEqual(report["waived"][0]["decision"], "D-999")


    def test_variant_contents(self):
        def debug_tree(root):
            for path in check_image.DEBUG_ONLY + check_image.REQUIRED_LICENSES:
                write(root, path, b"x")

        violations, _ = self.scan(debug_tree, [], variant="prod")
        self.assertEqual({v["kind"] for v in violations}, {"variant"})
        self.assertEqual(len(violations), len(check_image.DEBUG_ONLY))
        shutil.rmtree(self.work)
        os.makedirs(self.work)
        violations, _ = self.scan(lambda root: write(root, "etc/hostname", b"dstack"), [], variant="debug")
        self.assertEqual(len(violations), len(check_image.DEBUG_ONLY) + len(check_image.REQUIRED_LICENSES))

    def test_required_licenses(self):
        # Both variants must carry every hand-staged binary's license text. A
        # tree without them fails in each variant; a tree with them does not.
        # No variant means no license check, as for the old callers.
        def full(root):
            for path in check_image.DEBUG_ONLY + check_image.REQUIRED_LICENSES:
                write(root, path, b"x")

        for variant in ("prod", "debug"):
            violations, _ = self.scan(lambda root: write(root, "etc/hostname", b"x"), [], variant=variant)
            missing = {v["subject"] for v in violations if v["kind"] == "license"}
            self.assertEqual(missing, set(check_image.REQUIRED_LICENSES))
            shutil.rmtree(self.work)
            os.makedirs(self.work)

        violations, _ = self.scan(full, [], variant="debug")
        self.assertEqual([v for v in violations if v["kind"] == "license"], [])
        shutil.rmtree(self.work)
        os.makedirs(self.work)
        violations, _ = self.scan(lambda root: write(root, "etc/hostname", b"x"), [])
        self.assertEqual([v for v in violations if v["kind"] == "license"], [])


class ParserTest(unittest.TestCase):
    def test_elf_parsers(self):
        self.assertEqual(check_image.elf_needed(linked_binary("libc.so.6", "libzfs.so.6")), ["libc.so.6", "libzfs.so.6"])
        self.assertEqual(check_image.elf_needed(b"not an elf"), [])
        mod = os.path.join(tempfile.mkdtemp(), "m.ko")
        with open(mod, "wb") as f:
            f.write(kernel_module("Dual BSD/GPL"))
        self.assertEqual(check_image.module_info(mod), ("Dual BSD/GPL", True))

    def test_dep5(self):
        self.assertEqual(check_image.dep5_licenses(DEP5.format("MIT") + "\nFiles: x\nLicense: GPL-2+\n License text\n"),
                         ["MIT", "GPL-2+"])
        self.assertIsNone(check_image.dep5_licenses("This package is GPL.\n"))

    def test_exceptions_need_a_decision(self):
        path = os.path.join(tempfile.mkdtemp(), "e.json")
        with open(path, "w") as f:
            json.dump({"exceptions": [{"match": "x", "reason": "r"}]}, f)
        with self.assertRaises(SystemExit):
            check_image.load_exceptions(path)
        here = os.path.dirname(os.path.abspath(__file__))
        self.assertEqual(check_image.load_exceptions(os.path.join(here, "license-exceptions.json")), [])


if __name__ == "__main__":
    unittest.main()
