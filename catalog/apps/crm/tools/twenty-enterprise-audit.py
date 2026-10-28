#!/usr/bin/env python3
# Audit of the "@license Enterprise" files in a Twenty checkout (decision D-049, option A).
#
# Reads source files only; it never runs anything from the checkout. Run it with -I so Python
# does not import modules from the checkout or the current directory:
#
#   git clone --filter=blob:none --no-checkout https://github.com/twentyhq/twenty.git tmp/twenty
#   git -C tmp/twenty checkout 62c9c99746abbe3392de76ba77fd32cc93883335   # tag twenty/v2.52.0
#   python3 -I catalog/apps/crm/tools/twenty-enterprise-audit.py tmp/twenty [--json out.json]
#
# It resolves the TypeScript imports of twenty-server, twenty-front and twenty-shared (path
# aliases src/*, test/*, @/*, ~/* and twenty-shared/*) and reports:
#   - every marked file, by package and area;
#   - the AGPL files (not marked) that import a marked file directly, split into production
#     code and tests: each of those needs an edit or a stub before the marked files can go;
#   - the marked files that production code imports (the stub surface) and how many marked
#     files production code reaches through them;
#   - the core paths among the importers (ORM, query runners, module wiring, metadata engine).
# The numbers are the evidence for the D-049a decision in catalog/apps/crm/README.md.

import collections
import json
import os
import re
import sys

MARKER = "@license Enterprise"
ROOTS = [
    "packages/twenty-server/src",
    "packages/twenty-server/test",
    "packages/twenty-front/src",
    "packages/twenty-shared/src",
]
IMPORT_RE = re.compile(
    r"""(?:import|export)\s+(?:type\s+)?([\s\S]*?)\s+from\s+['"]([^'"]+)['"]"""
    r"""|import\s*\(\s*['"]([^'"]+)['"]\s*\)"""
    r"""|require\(\s*['"]([^'"]+)['"]\s*\)"""
    r"""|import\s+['"]([^'"]+)['"]"""
)
EXTENSIONS = ["", ".ts", ".tsx", "/index.ts", "/index.tsx"]
CORE_PATHS = [
    "src/main.ts",
    "src/app.module.ts",
    "engine/core-modules/core-engine.module.ts",
    "engine/twenty-orm/",
    "engine/api/",
    "engine/metadata-modules/flat-entity/",
    "engine/metadata-modules/role/",
    "engine/workspace-manager/workspace-migration/",
    "engine/workspace-cache/",
    "engine/core-modules/auth/",
    "engine/core-modules/workspace/",
    "packages/twenty-shared/src/types/",
    "packages/twenty-front/src/modules/users/",
    "packages/twenty-front/src/modules/app/",
]


def is_test(path):
    return (
        "/test/" in path
        or "__tests__" in path
        or "__mocks__" in path
        or "/__stories__/" in path
        or "/testing/" in path
        or path.endswith((".spec.ts", ".spec.tsx", ".test.ts", ".test.tsx", ".stories.tsx"))
    )


def read_text(path):
    # The LICENSE says the marker is at the top of the file, but some files carry it after their
    # imports (for example SettingsSsoSamlForm.tsx at line 16), so the whole file is searched.
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except (UnicodeDecodeError, OSError):
        return ""


def list_sources(repo):
    files = []
    for root in ROOTS:
        for d, dirs, names in os.walk(os.path.join(repo, root)):
            dirs[:] = [x for x in dirs if x != "node_modules"]
            for name in names:
                if name.endswith((".ts", ".tsx")):
                    files.append(os.path.relpath(os.path.join(d, name), repo))
    return sorted(files)


def resolver(fileset):
    def resolve(src, spec):
        base = None
        if spec.startswith("."):
            base = os.path.normpath(os.path.join(os.path.dirname(src), spec))
        elif src.startswith("packages/twenty-server") and spec.startswith(("src/", "test/")):
            base = "packages/twenty-server/" + spec
        elif src.startswith("packages/twenty-front") and spec.startswith("@/"):
            base = "packages/twenty-front/src/modules/" + spec[2:]
        elif src.startswith("packages/twenty-front") and spec.startswith("~/"):
            base = "packages/twenty-front/src/" + spec[2:]
        elif spec == "twenty-shared" or spec.startswith("twenty-shared/"):
            sub = spec[len("twenty-shared/"):] if "/" in spec else ""
            base = "packages/twenty-shared/src/" + sub if sub else "packages/twenty-shared/src"
        if base is None:
            return None
        for ext in EXTENSIONS:
            if base + ext in fileset:
                return base + ext
        return None

    return resolve


def area(path):
    parts = path.split("/")
    if parts[1] == "twenty-server" and parts[2] == "src":
        rest = parts[3:]
        depth = 2 if rest[0] == "modules" else 3
        return "twenty-server/" + "/".join(rest[:depth])
    return "/".join(parts[1:3])


def audit(repo):
    files = list_sources(repo)
    fileset = set(files)
    resolve = resolver(fileset)
    marked = {f for f in files if MARKER in read_text(os.path.join(repo, f))}
    marked_all = []
    for d, dirs, names in os.walk(repo):
        dirs[:] = [x for x in dirs if x not in ("node_modules", ".git")]
        for name in names:
            path = os.path.relpath(os.path.join(d, name), repo)
            if path != "LICENSE" and MARKER in read_text(os.path.join(repo, path)):
                marked_all.append(path)

    edges = collections.defaultdict(set)
    for f in files:
        try:
            with open(os.path.join(repo, f), encoding="utf-8") as fh:
                text = fh.read()
        except (UnicodeDecodeError, OSError):
            continue
        for m in IMPORT_RE.finditer(text):
            spec = m.group(2) or m.group(3) or m.group(4) or m.group(5)
            target = resolve(f, spec)
            if target:
                edges[f].add(target)

    importers = collections.defaultdict(set)
    for f, targets in edges.items():
        if f in marked:
            continue
        for t in targets:
            if t in marked:
                importers[f].add(t)
    prod = {f: sorted(t) for f, t in importers.items() if not is_test(f)}
    tests = {f: sorted(t) for f, t in importers.items() if is_test(f)}
    surface = sorted({t for ts in prod.values() for t in ts})

    reached, stack = set(), list(surface)
    while stack:
        x = stack.pop()
        if x in reached:
            continue
        reached.add(x)
        stack.extend(y for y in edges.get(x, ()) if y in marked)

    core = {f: ts for f, ts in prod.items() if any(p in f for p in CORE_PATHS)}
    by_area = collections.Counter(area(f) for f in marked)
    return {
        "marked_files_total": len(marked_all),
        "marked_files_in_sources": len(marked),
        "marked_by_area": dict(by_area.most_common()),
        "agpl_production_importers": len(prod),
        "agpl_test_importers": len(tests),
        "stub_surface_files": len(surface),
        "marked_files_reached_from_production": len(reached),
        "core_importers": core,
        "marked_files": sorted(marked_all),
    }


def main(argv):
    if len(argv) < 2:
        print("usage: twenty-enterprise-audit.py <twenty checkout> [--json out.json]", file=sys.stderr)
        return 2
    report = audit(argv[1])
    if "--json" in argv:
        with open(argv[argv.index("--json") + 1], "w", encoding="utf-8") as f:
            json.dump(report, f, indent=1, sort_keys=True)
    print(f"marked files: {report['marked_files_total']} ({report['marked_files_in_sources']} in TypeScript sources)")
    for k, v in report["marked_by_area"].items():
        print(f"  {v:4d} {k}")
    print(f"AGPL production files importing marked files: {report['agpl_production_importers']}")
    print(f"AGPL test files importing marked files: {report['agpl_test_importers']}")
    print(f"marked files imported by production code (stub surface): {report['stub_surface_files']}")
    print(f"marked files reached from production code: {report['marked_files_reached_from_production']}")
    print(f"core-path importers: {len(report['core_importers'])}")
    for f, ts in sorted(report["core_importers"].items()):
        print(f"  {f} ({len(ts)})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
