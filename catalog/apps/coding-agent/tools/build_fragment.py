"""Render compose fragments from their *.in.yaml templates by embedding the bootstrap scripts.

A template line of the form `<indent>@@include <path>@@` (directly under a `- |` block
scalar) is replaced by the file's lines at that indent, so the scripts in bootstrap/ are
the single source and the fragment carries them verbatim (and so they are measured).

    python tools/build_fragment.py           # rewrite the fragments
    python tools/build_fragment.py --check   # exit 1 if a fragment is out of date
"""
from __future__ import annotations

import os
import re
import sys

APP_DIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
TEMPLATE = "compose.fragment.in.yaml"
INCLUDE = re.compile(r"^(?P<indent>[ ]*)@@include (?P<path>[A-Za-z0-9_./-]+)@@[ ]*$")


class BuildError(Exception):
    pass


def header(template: str) -> str:
    return (f"# GENERATED from {os.path.basename(template)} by tools/build_fragment.py. "
            "Edit the template or bootstrap/*.py, then rerun the tool.\n")


def render(template_path: str) -> str:
    with open(template_path, encoding="utf-8") as handle:
        lines = handle.read().splitlines(keepends=True)
    out = [header(template_path)]
    for line in lines:
        match = INCLUDE.match(line.rstrip("\n"))
        if not match:
            out.append(line)
            continue
        source = os.path.join(APP_DIR, match.group("path"))
        with open(source, encoding="utf-8") as handle:
            text = handle.read()
        if "$" in text or "\t" in text:
            raise BuildError(f"{match.group('path')}: '$' and tabs cannot be embedded in a fragment")
        indent = match.group("indent")
        for src_line in text.splitlines():
            out.append((indent + src_line).rstrip() + "\n" if src_line.strip() else "\n")
    return "".join(out)


def targets() -> list[tuple[str, str]]:
    """Every compose.fragment.in.yaml in the app dir or one level below (variants such as fallback-opencode/)."""
    found = []
    for rel in [""] + sorted(d for d in os.listdir(APP_DIR) if os.path.isdir(os.path.join(APP_DIR, d))):
        if os.path.exists(os.path.join(APP_DIR, rel, TEMPLATE)):
            found.append((os.path.join(rel, TEMPLATE), os.path.join(rel, "compose.fragment.yaml")))
    return found


def main(argv: list[str]) -> int:
    check = "--check" in argv
    stale = []
    for template, target in targets():
        template_path = os.path.join(APP_DIR, template)
        target_path = os.path.join(APP_DIR, target)
        rendered = render(template_path)
        current = None
        if os.path.exists(target_path):
            with open(target_path, encoding="utf-8") as handle:
                current = handle.read()
        if current == rendered:
            continue
        if check:
            stale.append(target)
        else:
            with open(target_path, "w", encoding="utf-8") as handle:
                handle.write(rendered)
            print(f"wrote {target}")
    if stale:
        print("out of date: " + ", ".join(stale) + " (run tools/build_fragment.py)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
