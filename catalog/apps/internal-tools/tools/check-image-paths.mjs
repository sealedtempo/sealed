#!/usr/bin/env node
// Fails if an image file listing contains a path from the manifest's license_exclusions.
// Feed it the flattened filesystem of a built image, for example:
//   crane export --platform linux/amd64 <image@digest> - | tar -t | node tools/check-image-paths.mjs
// An exclusion ending in "/" matches that directory and everything under it; any other
// exclusion matches that exact path. Paths are compared without a leading "/" or "./".

import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { parse } from "yaml";

export function normalize(path) {
  return path.trim().replace(/^\.?\/+/, "");
}

export function findExcluded(listing, exclusions) {
  const rules = exclusions.map((e) => {
    const p = normalize(e);
    return p.endsWith("/") ? { dir: p.slice(0, -1) } : { file: p };
  });
  const hits = [];
  for (const raw of listing) {
    const path = normalize(raw).replace(/\/+$/, "");
    if (!path) continue;
    const rule = rules.find((r) => (r.dir ? path === r.dir || path.startsWith(`${r.dir}/`) : path === r.file));
    if (rule) hits.push(path);
  }
  return hits;
}

async function main() {
  const appDir = join(dirname(fileURLToPath(import.meta.url)), "..");
  const manifest = parse(await readFile(join(appDir, "manifest.yaml"), "utf8"));
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const listing = Buffer.concat(chunks).toString("utf8").split("\n");
  const hits = findExcluded(listing, manifest.license_exclusions ?? []);
  if (hits.length > 0) {
    console.error(`excluded paths present (${hits.length}):`);
    for (const hit of hits.slice(0, 50)) console.error(`  ${hit}`);
    process.exit(1);
  }
  console.log(`ok: ${listing.filter((l) => l.trim()).length} paths, none excluded`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await main();
