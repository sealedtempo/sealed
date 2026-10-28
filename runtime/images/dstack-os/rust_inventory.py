#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""License inventory of the Rust crates compiled into the guest image.

Usage: cargo metadata --format-version 1 --locked --filter-platform x86_64-unknown-linux-gnu \\
         --manifest-path <src>/dstack/Cargo.toml | rust_inventory.py OUT_JSON

dstack-rust-build.sh ships three workspace binaries: dstack-guest-agent,
dstack-util and dstack-volume. This walks their normal (non-dev, non-build)
dependency closure in the resolved graph and records each crate's license
expression. It fails on a banned license (rule 9, D-021) or a crate with no
license information. Licenses outside the allowlist that are not banned are
listed under "review" for a decision, without failing. Standard library only.
"""

import json
import re
import sys

SHIPPED = ("dstack-guest-agent", "dstack-util", "dstack-volume")

BANNED = re.compile(r"SSPL|BUSL|Elastic|Commons-Clause|Proprietary|LicenseRef-.*Proprietary|CDDL", re.IGNORECASE)

# Rule 9 plus D-021 and D-050 additions, as SPDX identifiers.
ALLOWED = {
    "MIT", "MIT-0", "Apache-2.0", "Apache-2.0 WITH LLVM-exception", "BSD-2-Clause", "BSD-3-Clause", "ISC",
    "MPL-2.0", "LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later",
    "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later", "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
    "PostgreSQL", "Zlib", "0BSD", "Unlicense", "CC0-1.0", "PSF-2.0", "Python-2.0", "BSL-1.0",
    "BlueOak-1.0.0", "ZPL-2.1", "CNRI-Python",
}


def license_ok(expr):
    """Whether an SPDX expression can be satisfied with allowed licenses only (OR: any side, AND: both sides).
    A license exception (WITH) only adds permissions, so it is as acceptable as its base license. The legacy
    crates.io "A/B" form means A OR B."""
    tokens = re.findall(r"\(|\)|[^\s()]+", expr.replace("/", " OR "))
    pos = 0

    def peek():
        return tokens[pos] if pos < len(tokens) else None

    def take():
        nonlocal pos
        pos += 1
        return tokens[pos - 1]

    def factor():
        if peek() == "(":
            take()
            v = disjunction()
            if take() != ")":
                raise ValueError(expr)
            return v
        ident = take()
        if peek() == "WITH":
            take()
            take()
        return ident.rstrip("+") in ALLOWED or ident in ALLOWED

    def conjunction():
        v = factor()
        while peek() == "AND":
            take()
            v = factor() and v
        return v

    def disjunction():
        v = conjunction()
        while peek() == "OR":
            take()
            v = conjunction() or v
        return v

    try:
        ok = disjunction()
        return ok and pos == len(tokens)
    except (IndexError, ValueError):
        return False


def closure(meta):
    pkgs = {p["id"]: p for p in meta["packages"]}
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    roots = [p["id"] for p in meta["packages"] if p["name"] in SHIPPED and p["id"] in set(meta["workspace_members"])]
    missing = set(SHIPPED) - {pkgs[r]["name"] for r in roots}
    if missing:
        raise SystemExit(f"workspace has no {sorted(missing)}")
    seen, stack = set(), list(roots)
    while stack:
        pid = stack.pop()
        if pid in seen:
            continue
        seen.add(pid)
        for dep in nodes[pid]["deps"]:
            if any(k.get("kind") is None for k in dep["dep_kinds"]):
                stack.append(dep["pkg"])
    return [pkgs[i] for i in seen]


def inventory(meta):
    crates, violations, review = [], [], []
    for p in sorted(closure(meta), key=lambda p: (p["name"], p["version"])):
        lic = p.get("license")
        entry = {"name": p["name"], "version": p["version"], "license": lic, "licenseFile": p.get("license_file")}
        crates.append(entry)
        label = f'{p["name"]} {p["version"]}'
        if not lic:
            (review if p.get("license_file") else violations).append(f"{label}: no SPDX license expression")
        elif BANNED.search(lic):
            violations.append(f"{label}: banned license {lic}")
        elif not license_ok(lic):
            review.append(f"{label}: {lic}")
    return {"shipped": list(SHIPPED), "crates": crates, "review": review, "violations": violations}


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    report = inventory(json.load(sys.stdin))
    with open(sys.argv[1], "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True)
        f.write("\n")
    for r in report["review"]:
        print(f"REVIEW {r}", file=sys.stderr)
    for v in report["violations"]:
        print(f"VIOLATION {v}", file=sys.stderr)
    print(f'{len(report["crates"])} crates, {len(report["review"])} to review, {len(report["violations"])} violations')
    return 1 if report["violations"] else 0


if __name__ == "__main__":
    sys.exit(main())
