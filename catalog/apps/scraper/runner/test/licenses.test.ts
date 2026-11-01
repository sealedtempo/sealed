import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
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

// License audit F10 (D-069): LICENSES/ carries the upstream texts byte for byte. LICENSE-NOTICE
// names each file, then "(<owner>/<repo> <ref> <path>, git blob <sha1>)" as gh api reports it.
const APP = resolve(RUNNER, '..');
const TEXT_ENTRY = /LICENSES\/([\w.-]+)\s*\n\s*\(([\w.-]+\/[\w.-]+) (\S+) (\S+), git blob ([0-9a-f]{40})\)/g;

function gitBlobHash(data: Buffer): string {
  return createHash('sha1').update(Buffer.concat([Buffer.from(`blob ${data.length}\0`), data])).digest('hex');
}

type NoticeText = { file: string; repo: string; ref: string; path: string; blob: string };

function noticeTexts(notice: string): NoticeText[] {
  return [...notice.matchAll(TEXT_ENTRY)].map((m) => ({
    file: m[1] ?? '',
    repo: m[2] ?? '',
    ref: m[3] ?? '',
    path: m[4] ?? '',
    blob: m[5] ?? '',
  }));
}

describe('upstream license texts (LICENSES/)', () => {
  const texts = noticeTexts(NOTICE);

  it('ships the texts the license audit lists, for the pinned versions', () => {
    expect(Object.fromEntries(texts.map((t) => [t.file, `${t.repo} ${t.ref} ${t.path}`]))).toEqual({
      'crawlee-v3.18.2-LICENSE.md': 'apify/crawlee v3.18.2 LICENSE.md',
      'playwright-v1.64.1-LICENSE': 'microsoft/playwright v1.64.1 LICENSE',
      'playwright-v1.64.1-NOTICE': 'microsoft/playwright v1.64.1 NOTICE',
      'firefox-MPL-2.0.txt': 'mozilla/bedrock a15178c3c7c976c67b3641af77cae0b66093a175 media/MPL/2.0/index.txt',
      'postgresql-17.11-COPYRIGHT': 'postgres/postgres REL_17_11 COPYRIGHT',
      'sapphire-async-queue-1.5.5-LICENSE.md': 'sapphiredev/utilities @sapphire/async-queue@1.5.5 LICENSE.md',
      'type-fest-v2.19.0-license-mit': 'sindresorhus/type-fest v2.19.0 license-mit',
    });
    const pkg = JSON.parse(readFileSync(resolve(RUNNER, 'package.json'), 'utf8')) as {
      dependencies: Record<string, string>;
      optionalDependencies: Record<string, string>;
    };
    expect(`v${pkg.dependencies['@crawlee/core']}`).toBe(texts.find((t) => t.repo === 'apify/crawlee')?.ref);
    expect(`v${pkg.optionalDependencies.playwright}`).toBe(texts.find((t) => t.file.startsWith('playwright-'))?.ref);
    const manifest = readFileSync(resolve(APP, 'manifest.yaml'), 'utf8');
    expect(manifest).toContain('postgres:17.11');
  });

  it('every text is byte for byte the upstream file', () => {
    for (const t of texts) {
      expect(gitBlobHash(readFileSync(join(APP, 'LICENSES', t.file))), t.file).toBe(t.blob);
    }
    expect(readFileSync(join(APP, 'LICENSES', 'firefox-MPL-2.0.txt'), 'utf8')).toMatch(/^Mozilla Public License Version 2\.0\n/);
  });

  it('LICENSE-NOTICE names every file in LICENSES/ with its source, and nothing else', () => {
    const present = readdirSync(join(APP, 'LICENSES')).filter((n) => !n.startsWith('.')).sort();
    expect(texts.map((t) => t.file).sort()).toEqual(present);
    const mentioned = new Set([...NOTICE.matchAll(/LICENSES\/([\w.-]+)/g)].map((m) => m[1]));
    expect([...mentioned].sort()).toEqual(present);
  });

  it('the hash is git\'s blob id', () => {
    // printf 'hello\n' | git hash-object --stdin
    expect(gitBlobHash(Buffer.from('hello\n'))).toBe('ce013625030ba8dba906f756967f9e9ca394464a');
  });
});

// The image ships the production node_modules as npm published them. A package whose npm tarball
// has no license text of its own (no LICENSE, COPYING or COPYRIGHT file, and no grant in its
// README) must be listed here: with the upstream text LICENSES/ carries for it, or with the words
// LICENSE-NOTICE uses to say why there is none (review policy-5, the PUB-D audit of every image).
const WITHOUT_OWN_TEXT: Record<string, { text: string } | { none: string }> = {
  '@sapphire/async-queue@1.5.5': { text: 'sapphire-async-queue-1.5.5-LICENSE.md' },
  'type-fest@2.19.0': { text: 'type-fest-v2.19.0-license-mit' },
  // Upstream has no license file; the Apache License 2.0 text is Crawlee's.
  'got-scraping@4.2.2': { text: 'crawlee-v3.18.2-LICENSE.md' },
  'boolbase@1.0.0': { none: 'so there is no text of this version to ship' },
};

const TEXT_FILE = /^(un)?(licen[cs]e|copying|copyright)([._-].*)?$/i;
const README_GRANT =
  /Permission is hereby granted|Permission to use, copy, modify|Licensed under the Apache License, Version 2\.0|Redistribution and use in source and binary forms/;

function ownText(pkg: InstalledPackage): boolean {
  const files = readdirSync(pkg.dir);
  if (files.some((f) => TEXT_FILE.test(f))) return true;
  const readme = files.find((f) => /^readme(\.|$)/i.test(f));
  return readme !== undefined && README_GRANT.test(readFileSync(join(pkg.dir, readme), 'utf8'));
}

describe('npm packages without a license text of their own', () => {
  const full = productionTree(RUNNER);
  const without = full
    .filter((p) => !p.name.startsWith('@sealed/') && !ownText(p))
    .map((p) => `${p.name}@${p.version}`)
    .sort();

  it('are exactly the listed ones', () => {
    expect(without).toEqual(Object.keys(WITHOUT_OWN_TEXT).sort());
  });

  it('each has its upstream text in LICENSES/, or LICENSE-NOTICE says why there is none', () => {
    const files = new Set(noticeTexts(NOTICE).map((t) => t.file));
    for (const [id, entry] of Object.entries(WITHOUT_OWN_TEXT)) {
      const at = id.lastIndexOf('@');
      expect(NOTICE, id).toContain(`${id.slice(0, at)} ${id.slice(at + 1)}`);
      if ('text' in entry) expect(files.has(entry.text), `${id}: LICENSES/${entry.text}`).toBe(true);
      else expect(NOTICE, id).toContain(entry.none);
    }
    expect(readFileSync(join(APP, 'LICENSES', 'crawlee-v3.18.2-LICENSE.md'), 'utf8')).toMatch(/^\s*Apache License\n\s*Version 2\.0, January 2004\n/);
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
