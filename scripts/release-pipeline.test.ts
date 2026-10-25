import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { parse } from 'yaml'
import { createReleasePlan } from './release-plan.mjs'
import {
  assertBinaryArchitecture,
  assertDesktopArchivePaths,
  packagedAppDirectory
} from './verify-package.mjs'
const env = {
  GITHUB_SHA: 'a'.repeat(40),
  GITHUB_REF: 'refs/heads/smart_core',
  GITHUB_RUN_NUMBER: '12',
  GITHUB_RUN_ATTEMPT: '2'
}
describe('immutable fork releases', () => {
  it('gives automatic builds unique prerelease tags without replacing stable updates', () => {
    expect(createReleasePlan('2.0.4', env)).toEqual({
      version: '2.0.4-fork.12',
      tag: 'v2.0.4-fork.12',
      commit: env.GITHUB_SHA,
      prerelease: true
    })
  })
  it('keeps a release version fixed when only failed jobs are rerun', () => {
    expect(createReleasePlan('2.0.4', { ...env, GITHUB_RUN_ATTEMPT: '3' })).toEqual(
      createReleasePlan('2.0.4', env)
    )
  })

  it('only promotes an explicit stable tag matching the source version', () => {
    expect(createReleasePlan('2.0.5', { ...env, GITHUB_REF: 'refs/tags/v2.0.5' }).prerelease).toBe(
      false
    )
    expect(() => createReleasePlan('2.0.4', { ...env, GITHUB_REF: 'refs/tags/v2.0.5' })).toThrow(
      'match'
    )
    expect(() =>
      createReleasePlan('2.0.4', { ...env, GITHUB_REF: 'refs/tags/v2.0.4;bad' })
    ).toThrow()
  })
  it.each([{ GITHUB_SHA: 'bad' }, { GITHUB_RUN_NUMBER: '../1' }, { GITHUB_RUN_ATTEMPT: '0' }])(
    'rejects unsafe identity values %j',
    (change) => {
      expect(() => createReleasePlan('2.0.4', { ...env, ...change })).toThrow()
    }
  )
  it('uses four native runners, a complete release gate and narrowly scoped publication credentials', () => {
    const source = readFileSync(new URL('../.github/workflows/build.yml', import.meta.url), 'utf8')
    const workflow = parse(source)
    expect(workflow.on.push.branches).toContain('smart_core')
    expect(workflow.on).not.toHaveProperty('pull_request')
    expect(workflow.permissions).toEqual({ contents: 'read' })
    expect(workflow.jobs.plan.permissions).toEqual({ contents: 'write' })
    expect(workflow.jobs.publish.permissions).toEqual({ contents: 'write' })
    expect(workflow.jobs.publish.needs).toEqual(['plan', 'checks', 'packages'])
    expect(workflow.jobs.checks.needs).toBe('plan')
    expect(workflow.jobs.packages.needs).toBe('checks')
    expect(workflow.jobs.plan.needs).toBeUndefined()
    expect(
      workflow.jobs.plan.steps.map((step: { run?: string }) => step.run).filter(Boolean)
    ).toEqual(['node scripts/release-plan.mjs --reserve'])
    expect(workflow.jobs.checks.permissions).toBeUndefined()
    expect(workflow.jobs.packages.permissions).toBeUndefined()
    expect(
      workflow.jobs.packages.strategy.matrix.include.map((v: { runner: string }) => v.runner)
    ).toEqual(['windows-latest', 'windows-11-arm', 'macos-15-intel', 'macos-latest'])
    expect(source).toContain(
      'node scripts/verify-package.mjs ${{ matrix.platform }} ${{ matrix.arch }}'
    )
    expect(source).not.toMatch(/write-all|Delete Dev|telegram|AUR|winget|CSC_LINK/)
    expect(workflow.jobs.publish.env.GH_REPO).toBe('${{ github.repository }}')
    expect(workflow.jobs.plan.env.GH_REPO).toBe('${{ github.repository }}')
  })
})
describe('binary architecture gates', () => {
  it('resolves electron-builder native output directories', () => {
    expect(packagedAppDirectory('darwin', 'x64')).toBe('dist/mac/Clash Party.app')
    expect(packagedAppDirectory('darwin', 'arm64')).toBe('dist/mac-arm64/Clash Party.app')
    expect(packagedAppDirectory('win32', 'x64')).toBe('dist/win-unpacked')
    expect(packagedAppDirectory('win32', 'arm64')).toBe('dist/win-arm64-unpacked')
  })

  it.each([
    ['win32', 'x64', 0x8664],
    ['win32', 'arm64', 0xaa64]
  ])('checks PE %s/%s', (platform, arch, machine) => {
    const bytes = Buffer.alloc(256)
    bytes.write('MZ')
    bytes.writeUInt32LE(128, 60)
    bytes.write('PE\0\0', 128)
    bytes.writeUInt16LE(Number(machine), 132)
    expect(() => assertBinaryArchitecture(bytes, String(platform), String(arch))).not.toThrow()
    expect(() =>
      assertBinaryArchitecture(bytes, String(platform), arch === 'x64' ? 'arm64' : 'x64')
    ).toThrow('mismatch')
    bytes.writeUInt32LE(4096, 60)
    expect(() => assertBinaryArchitecture(bytes, String(platform), String(arch))).toThrow(
      'Invalid PE'
    )
  })
  it.each([
    ['x64', 0x1000007],
    ['arm64', 0x100000c]
  ])('checks Mach-O %s', (arch, cpu) => {
    const bytes = Buffer.alloc(32)
    bytes.writeUInt32LE(0xfeedfacf)
    bytes.writeUInt32LE(Number(cpu), 4)
    expect(() => assertBinaryArchitecture(bytes, 'darwin', String(arch))).not.toThrow()
    expect(() =>
      assertBinaryArchitecture(bytes, 'darwin', arch === 'x64' ? 'arm64' : 'x64')
    ).toThrow('mismatch')
  })
  it('rejects a corrupt binary and unsupported package platform', () => {
    expect(() => assertBinaryArchitecture(Buffer.alloc(4), 'win32', 'x64')).toThrow('PE')
    expect(() => assertBinaryArchitecture(Buffer.alloc(4), 'darwin', 'arm64')).toThrow('Mach-O')
    expect(() => assertBinaryArchitecture(Buffer.alloc(4), 'linux', 'x64')).toThrow('Unsupported')
  })
})

describe('monorepo package boundary', () => {
  it('rejects mobile source and generated frameworks at the archive root on both hosts', () => {
    for (const entry of [
      '/apps/ios/ClashParty/App.swift',
      '\\modules\\mihomo-ios-core\\go.mod',
      'apps/ios/Vendor/MihomoMobile.xcframework/a'
    ])
      expect(() => assertDesktopArchivePaths([entry])).toThrow('leaked')
  })
  it('allows dependencies with their own internal modules directories', () => {
    expect(() =>
      assertDesktopArchivePaths(['/out/main/index.js', '/node_modules/package/modules/index.js'])
    ).not.toThrow()
  })
})
