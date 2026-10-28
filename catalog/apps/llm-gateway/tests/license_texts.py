"""Checks the upstream license texts an app ships in LICENSES/ (license audit F10, D-069).

LICENSE-NOTICE names every text with the place it was copied from:

    Text:    LICENSES/<file>
             (<owner>/<repo> <ref> <path>, git blob <40 hex>)

The git blob hash is what `gh api repos/<owner>/<repo>/contents/<path>?ref=<ref>` reports as
`sha`, so a text that differs from upstream by a single byte (line endings included) fails.
Used by the llm-gateway and coding-agent tests.
"""
from __future__ import annotations

import hashlib
import os
import re
from typing import NamedTuple

ENTRY = re.compile(
    r"LICENSES/(?P<file>[\w.-]+)\s*\n\s*\((?P<repo>[\w.-]+/[\w.-]+) (?P<ref>\S+) (?P<path>\S+), "
    r"git blob (?P<blob>[0-9a-f]{40})\)"
)


class Text(NamedTuple):
    file: str
    repo: str
    ref: str
    path: str
    blob: str


def git_blob_hash(path: str) -> str:
    """The git blob id of a file: sha1 over "blob <size>\\0" and the content, as git hash-object."""
    with open(path, "rb") as handle:
        data = handle.read()
    return hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()


def notice_texts(notice: str) -> list[Text]:
    """The provenance entries of a LICENSE-NOTICE, in file order."""
    return [Text(**m.groupdict()) for m in ENTRY.finditer(notice)]


def problems(app_dir: str) -> list[str]:
    """What is wrong with the app's LICENSES/ against its LICENSE-NOTICE; empty when all is well."""
    with open(os.path.join(app_dir, "LICENSE-NOTICE"), encoding="utf-8") as handle:
        notice = handle.read()
    texts = notice_texts(notice)
    out = []
    named = [t.file for t in texts]
    if len(set(named)) != len(named):
        out.append(f"a file is named twice: {named}")
    mentioned = set(re.findall(r"LICENSES/([\w.-]+)", notice))
    for name in sorted(mentioned - set(named)):
        out.append(f"LICENSES/{name} is named without its upstream source and git blob")
    licenses_dir = os.path.join(app_dir, "LICENSES")
    present = sorted(n for n in os.listdir(licenses_dir) if not n.startswith(".")) if os.path.isdir(licenses_dir) else []
    for name in present:
        if name not in named:
            out.append(f"LICENSES/{name} is not named in LICENSE-NOTICE")
    for text in texts:
        path = os.path.join(licenses_dir, text.file)
        if not os.path.isfile(path):
            out.append(f"LICENSES/{text.file} is missing")
            continue
        actual = git_blob_hash(path)
        if actual != text.blob:
            out.append(f"LICENSES/{text.file}: git blob {actual}, upstream {text.repo} {text.ref} {text.path} is {text.blob}")
    return out
