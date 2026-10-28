import { existsSync, readFileSync, realpathSync } from 'node:fs';
import { dirname, join, parse } from 'node:path';

// The runner's installed production dependency closure, found with Node's own lookup rules from
// package.json files, so it works for a standalone install and inside the root workspace alike.

export interface InstalledPackage {
  name: string;
  version: string;
  license: string;
  dir: string;
}

interface Manifest {
  name: string;
  version: string;
  license?: string | string[] | { type?: string };
  licenses?: { type?: string }[];
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

const readManifest = (dir: string) => JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as Manifest;

function licenseOf(m: Manifest): string {
  if (typeof m.license === 'string') return m.license;
  // An old-style list means the user may choose.
  if (Array.isArray(m.license)) return m.license.join(' OR ');
  if (m.license?.type) return m.license.type;
  const types = (m.licenses ?? []).map((l) => l.type).filter(Boolean);
  return types.length > 0 ? types.join(' OR ') : 'Unknown';
}

function resolvePackage(name: string, fromDir: string): string | null {
  const { root } = parse(fromDir);
  for (let dir = fromDir; ; dir = dirname(dir)) {
    const candidate = join(dir, 'node_modules', name);
    if (existsSync(join(candidate, 'package.json'))) return realpathSync(candidate);
    if (dir === root) return null;
  }
}

export function productionTree(packageDir: string, { optional = true } = {}): InstalledPackage[] {
  const root = readManifest(packageDir);
  const seen = new Map<string, InstalledPackage>();
  const queue: { name: string; from: string; optional: boolean }[] = [
    ...Object.keys(root.dependencies ?? {}).map((name) => ({ name, from: packageDir, optional: false })),
    ...(optional ? Object.keys(root.optionalDependencies ?? {}).map((name) => ({ name, from: packageDir, optional: true })) : []),
  ];
  while (queue.length > 0) {
    const next = queue.shift()!;
    const dir = resolvePackage(next.name, next.from);
    if (!dir) {
      if (next.optional) continue;
      throw new Error(`${next.name} (needed from ${next.from}) is not installed`);
    }
    if (seen.has(dir)) continue;
    const m = readManifest(dir);
    seen.set(dir, { name: m.name, version: m.version, license: licenseOf(m), dir });
    for (const name of Object.keys(m.dependencies ?? {})) queue.push({ name, from: dir, optional: false });
    for (const name of Object.keys(m.optionalDependencies ?? {})) queue.push({ name, from: dir, optional: true });
  }
  return [...seen.values()];
}
