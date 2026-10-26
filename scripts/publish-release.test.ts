import { createHash } from 'node:crypto'
import path from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  readFileSync: vi.fn(),
  readdirSync: vi.fn(),
  spawnSync: vi.fn(),
  execFileSync: vi.fn()
}))
vi.mock('node:fs', () => ({
  readFileSync: mocks.readFileSync,
  readdirSync: mocks.readdirSync,
  copyFileSync: vi.fn(),
  writeFileSync: vi.fn(),
  mkdirSync: vi.fn()
}))
vi.mock('node:child_process', () => ({
  spawnSync: mocks.spawnSync,
  execFileSync: mocks.execFileSync
}))

const commit = 'a'.repeat(40)
const repository = 'example/fork'
const plan = { version: '2.0.4-fork.4', tag: 'v2.0.4-fork.4', commit, prerelease: true }
const files = new Map<string, string | Buffer>()
let actualCommit: string | null
let existingRelease: Record<string, unknown> | null

beforeEach(() => {
  vi.resetModules()
  vi.clearAllMocks()
  for (const [key, value] of Object.entries({
    GITHUB_REPOSITORY: repository,
    GH_REPO: repository,
    GITHUB_SHA: commit,
    GITHUB_REF: 'refs/heads/smart_core',
    GITHUB_RUN_NUMBER: '4',
    GITHUB_RUN_ATTEMPT: '2'
  }))
    vi.stubEnv(key, value)
  actualCommit = commit
  existingRelease = null
  files.clear()
  files.set('package.json', JSON.stringify({ version: '2.0.4' }))
  files.set('release-metadata/release-plan.json', JSON.stringify(plan))
  const assets: string[] = []
  for (const platform of ['win32', 'darwin'])
    for (const arch of ['x64', 'arm64']) {
      const names =
        platform === 'darwin'
          ? [`clash-party-macos-${plan.version}-${arch}.pkg`]
          : [
              `clash-party-windows-${plan.version}-${arch}-setup.exe`,
              `clash-party-windows-${plan.version}-${arch}-portable.7z`
            ]
      for (const name of names) {
        const bytes = Buffer.from(name)
        files.set(path.join('release-assets', name), bytes)
        files.set(
          path.join('release-assets', `${name}.sha256`),
          createHash('sha256').update(bytes).digest('hex')
        )
        assets.push(name, `${name}.sha256`)
      }
      const manifest = `build-manifest-${platform}-${arch}.json`
      files.set(
        path.join('release-assets', manifest),
        JSON.stringify({ ...plan, platform, arch, nativeModuleLoaded: true })
      )
      assets.push(manifest)
    }
  for (const name of ['ClashParty-ios-device-unsigned.zip', 'ClashParty-ios-simulator-arm64.zip']) {
    const bytes = Buffer.from(name)
    files.set(path.join('release-assets', name), bytes)
    files.set(
      path.join('release-assets', `${name}.sha256`),
      createHash('sha256').update(bytes).digest('hex')
    )
    assets.push(name, `${name}.sha256`)
  }
  files.set(
    path.join('release-assets', 'ios-build-manifest.json'),
    JSON.stringify({ commit, signed: false })
  )
  files.set(
    path.join('release-assets', 'SIGNING.txt'),
    'Unsigned device archive; private signing required.'
  )
  assets.push('ios-build-manifest.json', 'SIGNING.txt')
  mocks.readFileSync.mockImplementation((name: string) => {
    if (!files.has(name)) throw new Error(`Unexpected file: ${name}`)
    return files.get(name)
  })
  mocks.readdirSync.mockReturnValue(assets)
  mocks.spawnSync.mockImplementation((_command: string, args: string[]) => {
    if (args[0] === 'api') {
      const status = actualCommit === null ? 404 : 200
      const data = { object: { type: 'commit', sha: actualCommit } }
      return {
        status: status === 200 ? 0 : 1,
        stdout: `HTTP/2.0 ${status}\nContent-Type: application/json\n\n${JSON.stringify(data)}`
      }
    }
    return { status: existingRelease ? 0 : 1, stdout: JSON.stringify(existingRelease) }
  })
})

afterEach(() => vi.unstubAllEnvs())

describe('release publication uses the reserved Git tag', () => {
  it('rejects an iOS artifact from another commit', async () => {
    files.set(
      path.join('release-assets', 'ios-build-manifest.json'),
      JSON.stringify({ commit: 'b'.repeat(40), signed: false })
    )
    await expect(import('./publish-release.mjs')).rejects.toThrow('Invalid iOS build manifest')
    expect(mocks.execFileSync).not.toHaveBeenCalled()
  })
  it('rejects corrupted mobile archives before publishing desktop assets', async () => {
    files.set(
      path.join('release-assets', 'ClashParty-ios-device-unsigned.zip'),
      Buffer.from('corrupt')
    )
    await expect(import('./publish-release.mjs')).rejects.toThrow('Checksum mismatch')
    expect(mocks.execFileSync).not.toHaveBeenCalled()
  })
  it('creates from an existing verified tag without the historical target parameter', async () => {
    await import('./publish-release.mjs')
    const args = mocks.execFileSync.mock.calls[0][1] as string[]
    expect(args.slice(0, 3)).toEqual(['release', 'create', plan.tag])
    expect(args).toContain('--verify-tag')
    expect(args).not.toContain('--target')
    expect(args).toContain(repository)
  })

  it('rejects a conflicting real tag even if release metadata claims the planned commit', async () => {
    actualCommit = 'b'.repeat(40)
    existingRelease = { targetCommitish: commit, tagName: plan.tag, isPrerelease: true }
    await expect(import('./publish-release.mjs')).rejects.toThrow('another commit')
    expect(mocks.execFileSync).not.toHaveBeenCalled()
  })

  it('requires a real ref and does not create one from a draft', async () => {
    actualCommit = null
    existingRelease = {
      tagName: plan.tag,
      targetCommitish: commit,
      isDraft: true,
      isPrerelease: true
    }
    await expect(import('./publish-release.mjs')).rejects.toThrow('missing')
    expect(mocks.execFileSync).not.toHaveBeenCalled()
  })

  it('uses the real source for a draft even when targetCommitish is a branch name', async () => {
    existingRelease = {
      tagName: plan.tag,
      targetCommitish: 'smart_core',
      isDraft: true,
      isPrerelease: true,
      assets: []
    }
    await import('./publish-release.mjs')
    const commands = mocks.execFileSync.mock.calls.map(([, args]) => args as string[])
    expect(commands.map((args) => args[1])).toEqual(['upload', 'edit'])
    expect(commands[1]).toContain('--verify-tag')
    expect(commands[1]).not.toContain('--target')
  })

  it('still rejects a package manifest from another commit', async () => {
    files.set(
      path.join('release-assets', 'build-manifest-win32-x64.json'),
      JSON.stringify({
        ...plan,
        commit: 'b'.repeat(40),
        platform: 'win32',
        arch: 'x64',
        nativeModuleLoaded: true
      })
    )
    await expect(import('./publish-release.mjs')).rejects.toThrow('Invalid package manifest')
    expect(mocks.execFileSync).not.toHaveBeenCalled()
  })
})
