#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""License and attack-surface check of a built Sealed dstack OS disk image.

Usage: check_image.py DISK_RAW INVENTORY_DIR OUT_JSON [--variant prod|debug] [--exceptions FILE]

DISK_RAW is the GCE boot disk (GPT: EFI System Partition with the UKI, then the
squashfs+dm-verity rootfs). INVENTORY_DIR is the dstack-sealed-inventory
directory written by the patched mkosi.postinst (packages.tsv and copyright/).

It fails (exit 1) when anything NVIDIA, ZFS or CDDL-licensed is in the image,
when a kernel module has a license the kernel does not treat as GPL-compatible,
when an ELF file links against an NVIDIA or ZFS library, when a Debian package
comes from outside main or declares a banned license, when a login, shell or
SSH surface is present, or when the magic SysRq key can be on at runtime
(kernel.sysrq must end up 0 after systemd-sysctl, and the UKI's measured
command line must not override it). The inventory it writes is published with
the release.
Needs unsquashfs (squashfs-tools) and, for the ESP listing, mdir (mtools).
Run as root so unsquashfs can extract every file. Standard library only.
"""

import argparse
import fnmatch
import gzip
import json
import lzma
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib

SECTOR = 512

# Licenses the kernel accepts as GPL-compatible (include/linux/license.h).
GPL_COMPATIBLE_MODULE_LICENSES = {
    "GPL",
    "GPL v2",
    "GPL and additional rights",
    "Dual BSD/GPL",
    "Dual MIT/GPL",
    "Dual MPL/GPL",
}

# Path patterns that must not occur anywhere in the rootfs. In-tree kernel
# modules whose names contain "nvidia" (for example i2c-nvidia-gpu) are GPL
# kernel code; everything under usr/lib/modules/<kver>/kernel/ is instead
# checked by module metadata: in-tree only and a GPL-compatible license.
FORBIDDEN_PATH = re.compile(
    r"nvidia|libcuda|nvcuvid|nvattest|libnvat\.|fabricmanager|nvswitch|nscq"
    r"|zfs|zpool|(^|/)zdb$|(^|/)zed(\.d)?(/|$)|libnvpair|libuutil|(^|/)spl\.ko",
    re.IGNORECASE,
)
KERNEL_MODULE_DIR = re.compile(r"^usr/lib/modules/[^/]+/kernel(/|$)")
# The out-of-tree NVIDIA driver modules, wherever they are installed.
NVIDIA_DRIVER_MODULE = re.compile(r"^nvidia(-uvm|-modeset|-drm|-peermem)?\.ko")
MODULE_SUFFIXES = (".ko", ".ko.xz", ".ko.gz", ".ko.zst")

FORBIDDEN_SONAME = re.compile(
    r"^lib(nvidia|cuda|nvcuvid|nvat|zfs|zpool|nvpair|uutil|zfs_core|nvoptix)", re.IGNORECASE
)

# Content markers of CDDL-licensed files (license headers and notices). The
# full name is searched in every non-ELF file; the short "CDDL" only as a word
# in text files, because four bytes would match compressed data by chance.
CDDL_NAME = b"Common Development and Distribution License"
CDDL_WORD = re.compile(rb"\bCDDL\b")
CDDL_MARKERS = (b"CDDL", CDDL_NAME)

# Login, shell and remote access surface that neither variant may contain.
FORBIDDEN_SURFACE = [
    "usr/sbin/sshd",
    "usr/bin/sshd",
    "usr/lib/openssh/sshd-session",
    "usr/sbin/dropbear",
    "usr/bin/login",
    "usr/bin/loginctl",
    "usr/sbin/agetty",
    "usr/sbin/getty",
    "usr/lib/systemd/system-generators/systemd-getty-generator",
    "usr/lib/systemd/system/getty@.service",
    "usr/lib/systemd/system/serial-getty@.service",
    "usr/lib/systemd/system/console-getty.service",
    "usr/lib/systemd/system/debug-shell.service",
    "usr/lib/systemd/systemd-logind",
    "usr/lib/systemd/system/systemd-logind.service",
    "usr/bin/dstack-tee-simulator",
    "usr/bin/swtpm",
    "usr/bin/gdb",
    "usr/bin/gdbserver",
    "usr/bin/strace",
    "usr/bin/tcpdump",
]

# The Cloud Logging exporter: required in the debug variant, forbidden in production.
# It is a Go binary, so the Go LICENSE and PATENTS ship with it (review policy-5).
DEBUG_ONLY = [
    "usr/bin/sealed-logship",
    "usr/lib/systemd/system/sealed-logship.service",
    "usr/lib/systemd/system-preset/82-dstack-sealed-debug.preset",
    "usr/share/licenses/sealed-logship/go/LICENSE",
    "usr/share/licenses/sealed-logship/go/PATENTS",
]

# License texts for the binaries that are staged into the rootfs by hand
# (sysbox and the container stack), not installed as Debian packages, so the
# copyright capture in mkosi.postinst does not reach them and the prod
# profile's RemoveFiles deletes /usr/share/doc. Each is a Go binary, so Go's
# standard library notice (LICENSE and PATENTS) ships with it; each project
# also ships its own LICENSE. Both the prod and the debug disk carry them
# (review policy-5).
REQUIRED_LICENSES = [
    "usr/share/licenses/sysbox/go/LICENSE",
    "usr/share/licenses/sysbox/go/PATENTS",
    "usr/share/licenses/sysbox/sysbox-runc-LICENSE",
    "usr/share/licenses/sysbox/sysbox-fs-LICENSE",
    "usr/share/licenses/sysbox/sysbox-mgr-LICENSE",
    "usr/share/licenses/container-stack/go/LICENSE",
    "usr/share/licenses/container-stack/go/PATENTS",
    "usr/share/licenses/container-stack/nerdctl-LICENSE",
    "usr/share/licenses/container-stack/cni-plugins-LICENSE",
    "usr/share/licenses/container-stack/stargz-snapshotter-LICENSE",
]

# Magic SysRq (kb-4). The host owns the serial port, and with SysRq on, a serial
# BREAK plus one key can reboot, crash or dump the guest. Upstream's kernel is
# built without it (CONFIG_MAGIC_SYSRQ=n); the overlay also sets kernel.sysrq = 0
# (usr/lib/sysctl.d/90-sealed-sysrq.conf) in case a later kernel config turns
# SysRq on. The check computes what systemd-sysctl leaves on kernel.sysrq
# (sysctl.d(5): every *.conf in these directories sorted by file name, a name in
# an earlier directory hides the same name in a later one, the last assignment
# wins), refuses command-line overrides, and refuses a kernel with SysRq that
# starts with it on (CONFIG_MAGIC_SYSRQ_DEFAULT_ENABLE other than 0).
SYSCTL_DIRS = ("etc/sysctl.d", "run/sysctl.d", "usr/local/lib/sysctl.d", "usr/lib/sysctl.d")
SYSRQ_KEY = "kernel.sysrq"
SYSRQ_CMDLINE = re.compile(r"^(sysrq_always_enabled(=.*)?|sysctl\.kernel[./]sysrq=(.*))$")
UKI_PATH = "::/EFI/BOOT/BOOTX64.EFI"

# DEP-5 License: values that are banned (rule 9, D-021) or are not free.
BANNED_LICENSE = re.compile(
    r"CDDL|SSPL|BUSL|Business[ -]Source|Elastic|Commons[ -]Clause|proprietary|NVIDIA|non-free",
    re.IGNORECASE,
)


def gpt_partitions(disk):
    """Return [(name, first_byte, size_bytes)] from the primary GPT of a raw disk."""
    with open(disk, "rb") as f:
        f.seek(SECTOR)
        hdr = f.read(92)
        if hdr[:8] != b"EFI PART":
            raise SystemExit(f"{disk}: no GPT header")
        entries_lba, count, entry_size = struct.unpack_from("<QII", hdr, 72)
        f.seek(entries_lba * SECTOR)
        table = f.read(count * entry_size)
    if zlib.crc32(table) != struct.unpack_from("<I", hdr, 88)[0]:
        raise SystemExit(f"{disk}: GPT partition array CRC mismatch")
    parts = []
    for i in range(count):
        e = table[i * entry_size : (i + 1) * entry_size]
        if e[:16] == b"\0" * 16:
            continue
        first, last = struct.unpack_from("<QQ", e, 32)
        name = e[56:128].decode("utf-16-le").rstrip("\0")
        parts.append((name, first * SECTOR, (last - first + 1) * SECTOR))
    return parts


def elf_needed(data):
    """DT_NEEDED entries of a 64-bit little-endian ELF file, from its section headers."""
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return []
    shoff = struct.unpack_from("<Q", data, 0x28)[0]
    shentsize, shnum = struct.unpack_from("<HH", data, 0x3A)
    if shoff == 0 or shentsize < 64 or shoff + shnum * shentsize > len(data):
        return []
    sections = []
    for i in range(shnum):
        sh = struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize)
        sections.append(sh)
    needed = []
    for sh in sections:
        if sh[1] != 6:  # SHT_DYNAMIC
            continue
        off, size, link = sh[4], sh[5], sh[6]
        if link >= len(sections):
            continue
        stroff = sections[link][4]
        for j in range(0, size - 15, 16):
            tag, val = struct.unpack_from("<qQ", data, off + j)
            if tag == 0:
                break
            if tag == 1:  # DT_NEEDED
                end = data.find(b"\0", stroff + val)
                needed.append(data[stroff + val : end].decode("utf-8", "replace"))
    return needed


def elf_section(data, wanted):
    """Contents of the named section of a 64-bit little-endian ELF file, or None."""
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2:
        return None
    shoff = struct.unpack_from("<Q", data, 0x28)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    if shoff == 0 or shoff + shnum * shentsize > len(data) or shstrndx >= shnum:
        return None
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize) for i in range(shnum)]
    names_off = sections[shstrndx][4]
    for sh in sections:
        end = data.find(b"\0", names_off + sh[0])
        if data[names_off + sh[0] : end].decode("ascii", "replace") == wanted:
            return data[sh[4] : sh[4] + sh[5]]
    return None


def module_info(path):
    """(license, intree) from a kernel module's .modinfo section."""
    if path.endswith(".ko.zst"):
        fields = {}
        for key in ("license", "intree"):
            out = subprocess.run(["modinfo", "-F", key, path], capture_output=True, text=True, check=False)
            fields[key] = out.stdout.strip() or None
        return fields["license"], fields["intree"] == "Y"
    with open(path, "rb") as f:
        data = f.read()
    if path.endswith(".xz"):
        data = lzma.decompress(data)
    elif path.endswith(".gz"):
        data = gzip.decompress(data)
    modinfo = elf_section(data, ".modinfo")
    if modinfo is None:
        return None, False
    lic, intree = None, False
    for field in modinfo.split(b"\0"):
        if field.startswith(b"license="):
            lic = field[len(b"license=") :].decode("utf-8", "replace")
        elif field == b"intree=Y":
            intree = True
    return lic, intree


def pe_section(data, wanted):
    """Contents of the named section of a PE image (the UKI), or None."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if pe + 24 > len(data) or data[pe : pe + 4] != b"PE\0\0":
        return None
    count = struct.unpack_from("<H", data, pe + 6)[0]
    table = pe + 24 + struct.unpack_from("<H", data, pe + 20)[0]
    for i in range(count):
        off = table + 40 * i
        if off + 40 > len(data):
            return None
        if data[off : off + 8].rstrip(b"\0").decode("ascii", "replace") != wanted:
            continue
        vsize, _, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off + 8)
        size = min(vsize, raw_size) if vsize else raw_size
        return data[raw_ptr : raw_ptr + size]
    return None


def uki_cmdline(disk, esp_offset):
    """The kernel command line measured into the UKI on the ESP, or (None, why)."""
    if not shutil.which("mcopy"):
        return None, "mcopy (mtools) is needed to read the UKI"
    tmp = tempfile.mkdtemp(prefix="sealed-uki-")
    try:
        uki = os.path.join(tmp, "BOOTX64.EFI")
        res = subprocess.run(["mcopy", "-n", "-i", f"{disk}@@{esp_offset}", UKI_PATH, uki], capture_output=True, text=True, check=False)
        if res.returncode != 0:
            return None, f"cannot copy the UKI: {res.stderr.strip()}"
        with open(uki, "rb") as f:
            section = pe_section(f.read(), ".cmdline")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if section is None:
        return None, "the UKI has no .cmdline section"
    return section.rstrip(b"\0").decode("utf-8", "replace").strip(), None


def in_root(root, rel):
    """Host path of a file inside the extracted rootfs, following its symlinks inside the rootfs.
    None for a masked (/dev/null), dangling or escaping link."""
    for _ in range(40):
        full = os.path.join(root, rel)
        if not os.path.islink(full):
            return full if os.path.isfile(full) else None
        target = os.readlink(full)
        if target == "/dev/null":
            return None
        rel = os.path.normpath(target.lstrip("/") if target.startswith("/") else os.path.join(os.path.dirname(rel), target))
        if rel == ".." or rel.startswith("../"):
            return None
    return None


def sysctl_value(root, key):
    """(value, file) that systemd-sysctl leaves on key in this rootfs; (None, None) when nothing sets it."""
    files = {}
    for d in SYSCTL_DIRS:
        full = os.path.join(root, d)
        if os.path.islink(full):
            raise ValueError(f"{d} is a symlink; the sysctl.d directories must be real directories")
        if not os.path.isdir(full):
            continue
        for name in os.listdir(full):
            if name.endswith(".conf") and name not in files:
                files[name] = f"{d}/{name}"
    value, source = None, None
    for name in sorted(files):
        path = in_root(root, files[name])
        if path is None:
            continue
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line[0] in "#;":
                    continue
                k, sep, v = line.partition("=")
                if not sep:
                    continue
                # "-key = value" only means a failed write is ignored; "/" and "." separate the same way.
                pattern = k.strip().lstrip("-").strip().replace("/", ".")
                if fnmatch.fnmatchcase(key, pattern):
                    value, source = v.strip(), files[name]
    return value, source


def kernel_sysrq_config(root):
    """{kernel release: (CONFIG_MAGIC_SYSRQ, CONFIG_MAGIC_SYSRQ_DEFAULT_ENABLE)} from usr/lib/modules/*/config."""
    out = {}
    base = os.path.join(root, "usr/lib/modules")
    for kver in sorted(os.listdir(base)) if os.path.isdir(base) else []:
        path = os.path.join(base, kver, "config")
        if not os.path.isfile(path) or os.path.islink(path):
            continue
        conf = {}
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                k, sep, v = line.strip().partition("=")
                if sep and k.startswith("CONFIG_"):
                    conf[k] = v
        out[kver] = (conf.get("CONFIG_MAGIC_SYSRQ", "n"), conf.get("CONFIG_MAGIC_SYSRQ_DEFAULT_ENABLE"))
    return out


def check_sysrq(root, cmdline, violate):
    """kb-4: SysRq stays off. Returns the report entry."""
    try:
        value, source = sysctl_value(root, SYSRQ_KEY)
    except ValueError as e:
        value, source = None, None
        violate("sysrq", SYSRQ_KEY, str(e))
    else:
        try:
            off = value is not None and int(value, 0) == 0
        except ValueError:
            off = False
        if not off:
            where = f" (last set in {source})" if source else ""
            violate("sysrq", SYSRQ_KEY, f"systemd-sysctl leaves {SYSRQ_KEY} = {value}{where}; it must be 0")
    for token in (cmdline or "").split():
        m = SYSRQ_CMDLINE.match(token)
        if m and m.group(3) != "0":
            violate("sysrq", f"cmdline:{token}", "the measured kernel command line turns SysRq on")
    kernels = kernel_sysrq_config(root)
    for kver, (magic, default) in kernels.items():
        try:
            starts_off = default is not None and int(default, 0) == 0
        except ValueError:
            starts_off = False
        if magic == "y" and not starts_off:
            violate("sysrq", f"usr/lib/modules/{kver}/config",
                    f"CONFIG_MAGIC_SYSRQ=y with CONFIG_MAGIC_SYSRQ_DEFAULT_ENABLE={default}: SysRq is on until systemd-sysctl runs")
    return {"sysctl": value, "sysctl_file": source, "kernel_config": {k: v[0] for k, v in kernels.items()}}


def dep5_licenses(text):
    """License short names from a machine-readable (DEP-5) copyright file, or None if it is not one."""
    if not text.lstrip().lower().startswith("format:"):
        return None
    names = []
    for m in re.finditer(r"^License:[ \t]*(\S[^\n]*)$", text, re.MULTILINE):
        v = m.group(1).strip()
        if v and v not in names:
            names.append(v)
    return names


def load_exceptions(path):
    if not path:
        return []
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    out = []
    for e in doc.get("exceptions", []):
        if not re.fullmatch(r"D-\d{3}[a-z]?", e.get("decision", "")) or not e.get("reason"):
            raise SystemExit(f"exception without a decision id and reason: {e}")
        out.append((re.compile(e["match"]), e["decision"]))
    return out


def scan(disk, inventory, out_json, exceptions, variant=None):
    violations = []

    def violate(kind, subject, detail):
        for rx, decision in exceptions:
            if rx.search(f"{kind}:{subject}"):
                report["waived"].append({"kind": kind, "subject": subject, "detail": detail, "decision": decision})
                return
        violations.append({"kind": kind, "subject": subject, "detail": detail})

    report = {"waived": []}
    parts = {name: (off, size) for name, off, size in gpt_partitions(disk)}
    if set(parts) != {"EFI System Partition", "dstack-rootfs"}:
        violate("disk", "partitions", f"unexpected GPT partitions {sorted(parts)}")
    report["partitions"] = {k: {"offset": v[0], "size": v[1]} for k, v in parts.items()}

    if "EFI System Partition" in parts and shutil.which("mdir"):
        off = parts["EFI System Partition"][0]
        res = subprocess.run(["mdir", "-/", "-b", "-i", f"{disk}@@{off}", "::"], capture_output=True, text=True, check=False)
        files = sorted(p for p in res.stdout.split() if not p.endswith("/"))
        report["esp_files"] = files
        if res.returncode != 0 or files != ["::/EFI/BOOT/BOOTX64.EFI"]:
            violate("esp", "contents", f"ESP must hold only the UKI, found {files or res.stderr.strip()}")
    cmdline = None
    if "EFI System Partition" in parts:
        cmdline, why = uki_cmdline(disk, parts["EFI System Partition"][0])
        if cmdline is None:
            violate("uki", "cmdline", why)
    report["uki_cmdline"] = cmdline

    work = tempfile.mkdtemp(prefix="sealed-check-")
    root = os.path.join(work, "root")
    try:
        off = parts["dstack-rootfs"][0]
        subprocess.run(
            ["unsquashfs", "-no-progress", "-no-xattrs", "-o", str(off), "-d", root, disk],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        modules = {}
        elf_files = 0
        files = 0
        for dirpath, dirnames, filenames in os.walk(root):
            for name in sorted(dirnames + filenames):
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, root)
                if NVIDIA_DRIVER_MODULE.match(name):
                    violate("path", rel, "NVIDIA driver module")
                elif FORBIDDEN_PATH.search(rel) and not KERNEL_MODULE_DIR.match(rel):
                    violate("path", rel, "NVIDIA or ZFS path")
            for name in filenames:
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, root)
                if os.path.islink(full) or not os.path.isfile(full):
                    continue
                files += 1
                if name.endswith(MODULE_SUFFIXES):
                    lic, intree = module_info(full)
                    modules[lic or "(none)"] = modules.get(lic or "(none)", 0) + 1
                    if lic not in GPL_COMPATIBLE_MODULE_LICENSES:
                        violate("kernel-module", rel, f"license {lic!r} is not GPL-compatible")
                    if not intree:
                        violate("kernel-module", rel, "out-of-tree module (the image ships only in-tree modules)")
                    continue
                size = os.path.getsize(full)
                with open(full, "rb") as f:
                    head = f.read(4)
                if head == b"\x7fELF":
                    elf_files += 1
                    with open(full, "rb") as f:
                        data = f.read()
                    for lib in elf_needed(data):
                        if FORBIDDEN_SONAME.match(lib):
                            violate("elf-needed", rel, f"links against {lib}")
                elif size <= 8 << 20:
                    with open(full, "rb") as f:
                        data = f.read()
                    if CDDL_NAME in data:
                        violate("cddl-text", rel, f"contains {CDDL_NAME.decode()!r}")
                    elif b"\0" not in data[:8192] and CDDL_WORD.search(data):
                        violate("cddl-text", rel, "contains 'CDDL'")
        for path in FORBIDDEN_SURFACE:
            if os.path.lexists(os.path.join(root, path)):
                violate("surface", path, "login, shell, debugger or SSH component present")
        report["sysrq"] = check_sysrq(root, cmdline, violate)
        for path in DEBUG_ONLY if variant else []:
            present = os.path.lexists(os.path.join(root, path))
            if variant == "debug" and not present:
                violate("variant", path, "missing from the debug variant (was the sealed-debug profile applied?)")
            elif variant == "prod" and present:
                violate("variant", path, "debug-only component in the production variant")
        for path in REQUIRED_LICENSES if variant else []:
            if not os.path.lexists(os.path.join(root, path)):
                violate("license", path, "license text for a hand-staged binary missing from the image")
        report["rootfs"] = {"files": files, "elf_files": elf_files, "kernel_module_licenses": modules}
    finally:
        shutil.rmtree(work, ignore_errors=True)

    packages = []
    with open(os.path.join(inventory, "packages.tsv"), encoding="utf-8") as f:
        for line in f:
            fields = line.rstrip("\n").split("\t")
            if len(fields) != 6:
                continue
            name, version, source, source_version, section, arch = fields
            plain = name.split(":", 1)[0]
            entry = {
                "package": plain,
                "version": version,
                "source": source,
                "sourceVersion": source_version,
                "section": section,
                "architecture": arch,
            }
            if section.startswith(("contrib", "non-free")):
                violate("package-section", plain, f"section {section} is outside Debian main")
            cpath = os.path.join(inventory, "copyright", plain)
            if not os.path.isfile(cpath):
                entry["licenses"] = None
                entry["copyright"] = "missing"
                violate("package-copyright", plain, "no copyright file recorded")
            else:
                with open(cpath, encoding="utf-8", errors="replace") as cf:
                    text = cf.read()
                lic = dep5_licenses(text)
                entry["copyright"] = "dep5" if lic is not None else "free-text"
                entry["licenses"] = lic
                for value in lic or []:
                    if BANNED_LICENSE.search(value):
                        violate("package-license", plain, f"License: {value}")
                for marker in CDDL_MARKERS:
                    if marker.decode() in text:
                        violate("package-license", plain, f"copyright file mentions {marker.decode()!r}")
                        break
            packages.append(entry)
    report["packages"] = packages
    report["violations"] = violations
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True)
        f.write("\n")
    return violations


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("disk")
    ap.add_argument("inventory")
    ap.add_argument("out_json")
    ap.add_argument("--exceptions")
    ap.add_argument("--variant", choices=("prod", "debug"))
    a = ap.parse_args()
    violations = scan(a.disk, a.inventory, a.out_json, load_exceptions(a.exceptions), a.variant)
    for v in violations:
        print(f"VIOLATION {v['kind']}: {v['subject']}: {v['detail']}", file=sys.stderr)
    if violations:
        print(f"{len(violations)} violation(s); see {a.out_json}", file=sys.stderr)
        return 1
    print(f"image check passed: no NVIDIA, ZFS or CDDL content, SysRq off; inventory in {a.out_json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
