#!/usr/bin/env node
// Copies the bootstrap script into compose.fragment.yaml, between the marker comments
//   # >>> embedded: <path relative to the app dir> ...
//   # <<< embedded
// as a YAML literal block, with every "$" doubled so compose interpolation leaves it alone.
// Usage: node tools/embed-bootstrap.mjs [--check]   (--check exits 1 if the fragment is stale)

import { readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const BEGIN = /^(?<indent> *)# >>> embedded: (?<path>\S+)/;
const END = /^ *# <<< embedded\s*$/;

export function escapeForCompose(text) {
  return text.replace(/\$/g, () => "$$");
}

export function unescapeFromCompose(text) {
  return text.replace(/\$\$/g, () => "$");
}

// Returns the marker blocks of a fragment: [{begin, end, indent, path}] with line indexes.
export function findBlocks(fragmentText) {
  const lines = fragmentText.split("\n");
  const blocks = [];
  for (let i = 0; i < lines.length; i++) {
    const m = BEGIN.exec(lines[i]);
    if (!m) continue;
    const end = lines.findIndex((line, j) => j > i && END.test(line));
    if (end < 0) throw new Error(`no "# <<< embedded" after line ${i + 1}`);
    blocks.push({ begin: i, end, indent: m.groups.indent, path: m.groups.path });
    i = end;
  }
  return blocks;
}

export function render(fragmentText, readScript) {
  const lines = fragmentText.split("\n");
  const out = [];
  let cursor = 0;
  for (const block of findBlocks(fragmentText)) {
    out.push(...lines.slice(cursor, block.begin + 1));
    const script = readScript(block.path);
    if (!script.endsWith("\n")) throw new Error(`${block.path} must end with a newline`);
    if (/\t/.test(script)) throw new Error(`${block.path} must not contain tabs`);
    const pad = `${block.indent}  `;
    out.push(`${block.indent}- |`);
    for (const line of escapeForCompose(script).slice(0, -1).split("\n")) {
      out.push(line === "" ? "" : `${pad}${line}`);
    }
    cursor = block.end;
  }
  out.push(...lines.slice(cursor));
  return out.join("\n");
}

async function main() {
  const appDir = join(dirname(fileURLToPath(import.meta.url)), "..");
  const fragmentPath = join(appDir, "compose.fragment.yaml");
  const current = await readFile(fragmentPath, "utf8");
  const scripts = new Map();
  for (const block of findBlocks(current)) {
    scripts.set(block.path, await readFile(join(appDir, block.path), "utf8"));
  }
  const next = render(current, (path) => scripts.get(path));
  if (process.argv.includes("--check")) {
    if (next !== current) {
      console.error("compose.fragment.yaml is stale: run node tools/embed-bootstrap.mjs");
      process.exit(1);
    }
    return;
  }
  if (next !== current) await writeFile(fragmentPath, next);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await main();
