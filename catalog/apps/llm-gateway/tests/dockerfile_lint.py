"""Tiny Dockerfile reader for packaging tests (no docker daemon needed).

It joins continuation lines, drops comments, and groups instructions by stage so tests
can assert pinning, flattening and the final ENV/ENTRYPOINT.
"""
from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass, field

DIGEST_REF = re.compile(r"@sha256:[0-9a-f]{64}$")


@dataclass
class Stage:
    base: str
    name: str = ""
    instructions: list[tuple[str, str]] = field(default_factory=list)

    def all(self, op: str) -> list[str]:
        return [arg for o, arg in self.instructions if o == op]

    def env(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for arg in self.all("ENV"):
            for token in shlex.split(arg):
                if "=" in token:
                    key, value = token.split("=", 1)
                    out[key] = value
        return out

    def exec_form(self, op: str) -> list[str]:
        values = self.all(op)
        if not values:
            return []
        return json.loads(values[-1])


def instructions(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    buf = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if not buf and (not line.strip() or line.lstrip().startswith("#")):
            continue
        if buf and line.lstrip().startswith("#"):
            continue
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        op, _, arg = buf.strip().partition(" ")
        out.append((op.upper(), arg.strip()))
        buf = ""
    return out


def stages(text: str) -> tuple[dict[str, str], list[Stage]]:
    """Return (global ARG defaults, stages)."""
    args: dict[str, str] = {}
    result: list[Stage] = []
    for op, arg in instructions(text):
        if op == "FROM":
            parts = [p for p in arg.split() if not p.startswith("--platform")]
            base = parts[0]
            for key, value in args.items():
                base = base.replace("${" + key + "}", value).replace("$" + key, value)
            name = parts[2] if len(parts) >= 3 and parts[1].upper() == "AS" else ""
            result.append(Stage(base=base, name=name))
        elif not result and op == "ARG":
            key, _, value = arg.partition("=")
            args[key] = value
        elif result:
            result[-1].instructions.append((op, arg))
    return args, result


def is_digest_pinned(ref: str) -> bool:
    return bool(DIGEST_REF.search(ref))
