#!/usr/bin/env node
// Checks that the privatemode-proxy binary links only MIT-licensed code of its own repository.
// edgelesssys/privatemode-public carries a restrictive license by default; only some directories
// are additionally MIT (LICENSE.MIT). The binary's own packages are read from its symbol table
// (`go tool nm`), so a package outside those directories fails the check. Third-party modules are
// covered by the SBOM license check of the catalog lint.
//
//   node check-privatemode-proxy.mjs --binary ./privatemode-proxy
//   node check-privatemode-proxy.mjs --image ghcr.io/edgelesssys/privatemode/privatemode-proxy@sha256:...   (needs crane)
import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

export const MAIN_MODULE = 'github.com/edgelesssys/privatemode-public'
/** Directories of the main module licensed MIT (LICENSE-NOTICE). */
export const MIT_DIRS = ['privatemode-proxy', 'internal/oss', 'sdk', 'chat']

/** Package import paths of `module` that the binary links, from `go tool nm` output. */
export function linkedPackages(nmOutput, module = MAIN_MODULE) {
  const packages = new Set()
  for (const line of nmOutput.split('\n')) {
    const symbol = line.trim().split(/\s+/).at(-1) ?? ''
    if (!symbol.startsWith(`${module}/`) && !symbol.startsWith(`${module}.`)) continue
    const slash = symbol.lastIndexOf('/')
    const dot = symbol.indexOf('.', slash + 1)
    packages.add(dot >= 0 ? symbol.slice(0, dot) : symbol)
  }
  return [...packages].sort()
}

/** Packages of the main module outside the MIT directories. */
export function violations(packages, module = MAIN_MODULE, mitDirs = MIT_DIRS) {
  return packages.filter((p) => {
    const rel = p === module ? '' : p.slice(module.length + 1)
    return !mitDirs.some((d) => rel === d || rel.startsWith(`${d}/`))
  })
}

export function checkBinary(path, go = 'go') {
  const info = execFileSync(go, ['version', '-m', path], { encoding: 'utf8' })
  const mainPath = /^\s*path\s+(\S+)/m.exec(info)?.[1]
  const mod = /^\s*mod\s+(\S+)/m.exec(info)?.[1]
  const problems = []
  if (mod !== MAIN_MODULE) problems.push(`main module is ${mod}, expected ${MAIN_MODULE}`)
  if (!mainPath?.startsWith(`${MAIN_MODULE}/privatemode-proxy`)) problems.push(`main package ${mainPath} is not under privatemode-proxy/`)
  const nm = execFileSync(go, ['tool', 'nm', path], { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 })
  const packages = linkedPackages(nm)
  for (const p of violations(packages)) problems.push(`links ${p}, outside the MIT-licensed directories`)
  return { mainPath, module: mod, packages, problems }
}

function binaryFromImage(ref) {
  const dir = mkdtempSync(join(tmpdir(), 'pm-proxy-'))
  const tar = join(dir, 'fs.tar')
  writeFileSync(tar, execFileSync('crane', ['export', '--platform', 'linux/amd64', ref, '-'], { maxBuffer: 1024 * 1024 * 1024 }))
  execFileSync('tar', ['-xf', tar, '-C', dir, 'bin/privatemode-proxy'])
  return { path: join(dir, 'bin/privatemode-proxy'), cleanup: () => rmSync(dir, { recursive: true, force: true }) }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [flag, value] = process.argv.slice(2)
  if (!value || (flag !== '--binary' && flag !== '--image')) {
    console.error('usage: check-privatemode-proxy.mjs --binary <path> | --image <ref>')
    process.exit(2)
  }
  const target = flag === '--image' ? binaryFromImage(value) : { path: value, cleanup: () => {} }
  try {
    const result = checkBinary(target.path)
    for (const p of result.problems) console.error(`privatemode-proxy license: ${p}`)
    console.log(JSON.stringify({ ok: result.problems.length === 0, module: result.module, packages: result.packages.length }))
    process.exit(result.problems.length === 0 ? 0 : 1)
  } finally {
    target.cleanup()
  }
}
