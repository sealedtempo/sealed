#!/usr/bin/env node
// Fails if an image file listing contains a path from the manifest's license_exclusions.
// Feed it the flattened filesystem of a built image, for example:
//   crane export --platform linux/amd64 <image@digest> - | tar -t | node tools/check-image-paths.mjs
// An exclusion ending in "/" matches that directory and everything under it; any other
// exclusion matches that exact path. Paths are compared without a leading "/" or "./".
// An exclusion of a single directory name, such as "/ee/" (the open-core layout: server/ee,
// frontend/ee and their build output), matches a directory of that name at any depth, except
// below node_modules/ and usr/share/locale/, where "ee" is the Ewe language code of third-party
// locale data and never ToolJet's enterprise code. A "**" segment matches any number of segments
// and "*" anything within one segment, as in the composer lint's path globs (license audit F6), so
// "/app/**/ee/" is an ee directory at any depth under app/, with the same exemptions.

import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { parse } from "yaml";

export function normalize(path) {
  return path.trim().replace(/^\.?\/+/, "");
}

const SEGMENT_EXEMPT = [/(^|\/)node_modules\//, /^usr\/share\/locale\//];

// A glob ("**" any segments, "*" within a segment) as a regular expression over a path prefix; the
// shortest prefix is matched, so an exemption below it cannot hide a match above it.
function globRegExp(glob) {
  const parts = glob.split("/").map((seg) => {
    if (seg === "**") return "(?:[^/]+/)*?";
    return `${seg.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]*")}/`;
  });
  return new RegExp(`^${parts.join("")}`);
}

export function findExcluded(listing, exclusions) {
  const rules = exclusions.map((e) => {
    const p = normalize(e);
    if (p.includes("*")) return { glob: globRegExp(p.replace(/\/$/, "")) };
    if (!p.endsWith("/")) return { file: p };
    const dir = p.slice(0, -1);
    return dir.includes("/") ? { dir } : { segment: dir };
  });
  const matches = (r, path) => {
    if (r.glob) {
      // Only where the matched directory itself sits outside the exempt trees, as for a single segment.
      const m = r.glob.exec(`${path}/`);
      if (!m) return false;
      const matched = m[0].slice(0, -1);
      return !SEGMENT_EXEMPT.some((re) => re.test(matched.slice(0, matched.lastIndexOf("/") + 1)));
    }
    if (r.file) return path === r.file;
    if (r.dir) return path === r.dir || path.startsWith(`${r.dir}/`);
    if (!`/${path}/`.includes(`/${r.segment}/`)) return false;
    // Only where the segment itself sits outside the exempt trees.
    const at = `/${path}/`.indexOf(`/${r.segment}/`);
    return !SEGMENT_EXEMPT.some((re) => re.test(path.slice(0, at + 1)));
  };
  const hits = [];
  for (const raw of listing) {
    const path = normalize(raw).replace(/\/+$/, "");
    if (!path) continue;
    if (rules.some((r) => matches(r, path))) hits.push(path);
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
