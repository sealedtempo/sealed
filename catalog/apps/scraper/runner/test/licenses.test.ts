import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { productionTree, type InstalledPackage } from './helpers/prod-tree.js';

// License policy for what the images ship (BUILD_SPEC rule 9, D-021, D-050), checked against the
// installed production tree so a new dependency with another license fails here, and
// LICENSE-NOTICE cannot drift from what is actually shipped.

const RUNNER = resolve(import.meta.dirname, '..');
const NOTICE = readFileSync(resolve(RUNNER, '../LICENSE-NOTICE'), 'utf8');

const RULE_9 = ['MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'MPL-2.0', 'GPL-3.0', 'AGPL-3.0'];
const D_021 = ['PostgreSQL', 'Zlib', '0BSD', 'Unlicense', 'CC0-1.0', 'PSF-2.0', 'Python-2.0', 'BSL-1.0'];
// D-050: OSI-approved permissive licenses added to the allowlist.
const D_050 = ['BlueOak-1.0.0', 'ZPL-2.1', 'CNRI-Python'];
const ALLOWED = new Set([...RULE_9, ...D_021, ...D_050]);

// D-050 allows CC-BY-4.0 for data-only packages. Only the packages named here are known to be data
// (no code that runs), so any other CC-BY-4.0 package fails until someone checks it.
const DATA_ONLY: Record<string, string[]> = {
  'CC-BY-4.0': ['caniuse-lite'], // browser usage tables, pulled in by got-scraping
};

// Packages whose package.json names no license, with the license their bundled file grants.
const UNDECLARED: Record<string, { file: string; license: string; marker: string }> = {
  'map-stream': { file: 'LICENCE', license: 'MIT', marker: 'Permission is hereby granted, free of charge' },
};

function allowedExpression(expr: string): boolean {
  const bare = expr.replace(/^\((.*)\)$/, '$1').trim();
  if (bare.includes(' OR ')) return bare.split(' OR ').some((part) => allowedExpression(part));
  if (bare.includes(' AND ')) return bare.split(' AND ').every((part) => allowedExpression(part));
  return ALLOWED.has(bare) || /^LGPL-/.test(bare);
}

function problems(tree: InstalledPackage[]): string[] {
  const out: string[] = [];
  for (const pkg of tree) {
    if (pkg.license === 'Unknown') {
      const known = UNDECLARED[pkg.name];
      const text = known ? readFileSync(join(pkg.dir, known.file), 'utf8') : '';
      if (!known || !text.includes(known.marker)) out.push(`${pkg.name}@${pkg.version}: no license declared`);
      continue;
    }
    if (allowedExpression(pkg.license)) continue;
    if (DATA_ONLY[pkg.license]?.includes(pkg.name)) continue;
    out.push(`${pkg.name}@${pkg.version}: ${pkg.license}`);
  }
  return out;
}

describe('production dependency licenses', () => {
  const full = productionTree(RUNNER);
  const slim = productionTree(RUNNER, { optional: false });

  it('finds the whole tree', () => {
    expect(full.length).toBeGreaterThan(100);
    expect(full.some((p) => p.name === 'playwright')).toBe(true);
    expect(slim.some((p) => p.name === 'playwright')).toBe(false);
    expect(slim.some((p) => p.name === '@crawlee/cheerio')).toBe(true);
  });

  it('uses only allowed licenses, and CC-BY-4.0 only for the data-only packages named (D-050)', () => {
    expect(problems(full)).toEqual([]);
    expect(full.find((p) => p.name === 'sax')?.license).toBe('BlueOak-1.0.0');
  });

  it('the data-only packages hold no code that runs', () => {
    for (const [license, names] of Object.entries(DATA_ONLY)) {
      for (const name of names) {
        const pkg = full.find((p) => p.name === name);
        expect(pkg?.license, name).toBe(license);
        const manifest = JSON.parse(readFileSync(join(pkg!.dir, 'package.json'), 'utf8')) as {
          dependencies?: Record<string, string>;
          scripts?: Record<string, string>;
          bin?: unknown;
        };
        expect(manifest.dependencies ?? {}, name).toEqual({});
        expect(Object.keys(manifest.scripts ?? {}).filter((k) => /install/.test(k)), name).toEqual([]);
        expect(manifest.bin, name).toBeUndefined();
      }
    }
  });

  it('never ships the packages the manifest excludes', () => {
    // idcac-playwright is a GPL-3.0-only optional peer; @playwright/browser-chromium installs
    // Chrome for Testing (D-022). electron-to-chromium is a version table (ISC), not a browser.
    const names = full.map((p) => p.name);
    expect(names).not.toContain('idcac-playwright');
    expect(names).not.toContain('@playwright/browser-chromium');
  });

  it('LICENSE-NOTICE names every license in the tree and every exception', () => {
    const licenses = new Set(full.map((p) => p.license).filter((l) => l !== 'Unknown'));
    for (const license of licenses) expect(NOTICE, license).toContain(license);
    for (const [license, names] of Object.entries(DATA_ONLY)) {
      for (const name of names) expect(NOTICE, `${name} ${license}`).toMatch(new RegExp(`${name}[^\\n]*${license}|${license}[^\\n]*${name}`));
    }
    for (const [name, { license }] of Object.entries(UNDECLARED)) expect(NOTICE).toMatch(new RegExp(`${name}[^\\n]*${license}`));
  });
});

describe('allowedExpression', () => {
  it('reads simple SPDX expressions', () => {
    expect(allowedExpression('MIT')).toBe(true);
    expect(allowedExpression('(MIT OR CC0-1.0)')).toBe(true);
    expect(allowedExpression('MIT OR Apache2')).toBe(true);
    expect(allowedExpression('MIT AND CC-BY-4.0')).toBe(false);
    expect(allowedExpression('BlueOak-1.0.0')).toBe(true);
    expect(allowedExpression('LGPL-2.1-or-later')).toBe(true);
    expect(allowedExpression('SSPL-1.0')).toBe(false);
    expect(allowedExpression('BUSL-1.1')).toBe(false);
  });
});
