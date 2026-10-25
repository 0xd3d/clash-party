import { createHash } from 'node:crypto'
import path from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  files: new Map<string, Buffer>(),
  get: vi.fn(),
  writeFile: vi.fn(),
  rm: vi.fn(),
  spawn: vi.fn(),
  exec: vi.fn(),
  execFile: vi.fn(),
  quit: vi.fn(),
  openPath: vi.fn(),
  getVersion: vi.fn()
}))

vi.mock('fs', () => ({ existsSync: (file: string) => mocks.files.has(file) }))
vi.mock('fs/promises', () => ({
  readFile: async (file: string) => mocks.files.get(file),
  writeFile: mocks.writeFile,
  rm: mocks.rm,
  copyFile: vi.fn()
}))
vi.mock('child_process', () => ({
  spawn: mocks.spawn,
  exec: mocks.exec,
  execFile: mocks.execFile,
  execSync: vi.fn()
}))
vi.mock('os', () => ({ default: { release: () => '10.0.0' } }))
vi.mock('electron', () => ({
  app: { getVersion: mocks.getVersion, quit: mocks.quit, relaunch: vi.fn() },
  shell: { openPath: mocks.openPath }
}))
vi.mock('i18next', () => ({ default: { t: (key: string) => key } }))
vi.mock('../window', () => ({ mainWindow: null }))
vi.mock('../utils/logger', () => ({
  appLogger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() }
}))
vi.mock('../utils/dirs', () => ({
  dataDir: () => '/test-data',
  exeDir: () => '/test-app',
  exePath: () => '/test-app/app.exe',
  resourcesFilesDir: () => '/test-resources',
  isPortable: () => false
}))
vi.mock('../config', () => ({
  getAppConfig: async () => ({ githubProxy: 'direct' }),
  getControledMihomoConfig: async () => ({ 'mixed-port': 0 })
}))
vi.mock('../core/manager', () => ({ checkAdminPrivileges: async () => true }))
vi.mock('../utils/chromeRequest', () => ({ get: mocks.get }))
vi.mock('../utils/yaml', () => ({ parse: JSON.parse }))

const originalPlatform = process.platform
const originalArch = process.arch
const installer = Buffer.from('fork installer')
const digest = createHash('sha256').update(installer).digest('hex')
const file = 'clash-party-windows-2.0.5-x64-setup.exe'
const installerPath = path.join('/test-data', file)
const repository = 'example/custom-fork'
const base = `https://github.com/${repository}/releases/download/v2.0.5/`

function response(data: unknown): { data: unknown; status: number } {
  return { data, status: 200 }
}

beforeEach(() => {
  vi.resetModules()
  vi.clearAllMocks()
  vi.stubGlobal('__UPDATE_REPOSITORY__', repository)
  Object.defineProperty(process, 'platform', { configurable: true, value: 'win32' })
  Object.defineProperty(process, 'arch', { configurable: true, value: 'x64' })
  mocks.files.clear()
  mocks.getVersion.mockReturnValue('2.0.4')
  mocks.spawn.mockReturnValue({ unref: vi.fn() })
  mocks.writeFile.mockImplementation(async (name: string, content: Buffer) => {
    mocks.files.set(name, content)
  })
  mocks.rm.mockImplementation(async (name: string) => {
    mocks.files.delete(name)
  })
  mocks.get.mockImplementation(async (url: string) => {
    if (url === `https://api.github.com/repos/${repository}/releases/tags/v2.0.5`) {
      return response({ assets: [{ name: file, digest: `sha256:${digest}` }] })
    }
    if (url.endsWith('/latest.yml')) return response(JSON.stringify({ version: '2.0.5' }))
    if (url === `${base}${file}.sha256`) return response(digest)
    if (url === `${base}${file}`) return response(installer)
    throw new Error(`Unexpected URL: ${url}`)
  })
})

afterEach(() => {
  Object.defineProperty(process, 'platform', { configurable: true, value: originalPlatform })
  Object.defineProperty(process, 'arch', { configurable: true, value: originalArch })
  vi.unstubAllGlobals()
})

describe('fork updater source and cached installers', () => {
  it('checks only the configured fork metadata', async () => {
    const { checkUpdate } = await import('./autoUpdater')
    await expect(checkUpdate()).resolves.toEqual({ version: '2.0.5' })
    expect(mocks.get).toHaveBeenCalledOnce()
    expect(mocks.get.mock.calls[0][0]).toBe(
      `https://github.com/${repository}/releases/latest/download/latest.yml`
    )
  })

  it('downloads and verifies a fork asset before handing it to the mocked installer', async () => {
    const { downloadAndInstallUpdate } = await import('./autoUpdater')
    await downloadAndInstallUpdate('2.0.5')
    expect(mocks.get.mock.calls.map(([url]) => url)).toEqual([
      `https://api.github.com/repos/${repository}/releases/tags/v2.0.5`,
      `${base}${file}`
    ])
    expect(mocks.files.get(installerPath)).toEqual(installer)
    expect(mocks.spawn).toHaveBeenCalledWith(installerPath, ['/S', '--updated', '--force-run'], {
      detached: true,
      stdio: 'ignore'
    })
  })

  it('replaces an upstream or stale cached installer using the fork checksum', async () => {
    mocks.files.set(installerPath, Buffer.from('old upstream installer'))
    const { downloadAndInstallUpdate } = await import('./autoUpdater')
    await downloadAndInstallUpdate('2.0.5')
    expect(mocks.rm).toHaveBeenCalledWith(installerPath, { force: true })
    expect(mocks.files.get(installerPath)).toEqual(installer)
    expect(mocks.get.mock.calls.map(([url]) => url)).toContain(`${base}${file}`)
    expect(mocks.spawn).toHaveBeenCalledOnce()
  })

  it('checks a valid cached installer against the fork instead of downloading again', async () => {
    mocks.files.set(installerPath, installer)
    const { downloadAndInstallUpdate } = await import('./autoUpdater')
    await downloadAndInstallUpdate('2.0.5')
    expect(mocks.get.mock.calls.map(([url]) => url)).toEqual([
      `https://api.github.com/repos/${repository}/releases/tags/v2.0.5`
    ])
    expect(mocks.writeFile).not.toHaveBeenCalled()
    expect(mocks.spawn).toHaveBeenCalledOnce()
  })

  it('keeps checksum fallback in the fork and refuses corrupt downloads', async () => {
    mocks.get.mockImplementation(async (url: string) => {
      if (url.startsWith('https://api.github.com/')) throw new Error('API unavailable')
      if (url === `${base}${file}.sha256`) return response(digest)
      if (url === `${base}${file}`) return response(Buffer.from('corrupt installer'))
      throw new Error(`Unexpected URL: ${url}`)
    })
    const { downloadAndInstallUpdate } = await import('./autoUpdater')
    await expect(downloadAndInstallUpdate('2.0.5')).rejects.toThrow('integrity check failed')
    expect(mocks.get.mock.calls.map(([url]) => url)).toContain(`${base}${file}.sha256`)
    expect(mocks.spawn).not.toHaveBeenCalled()
    expect(mocks.quit).not.toHaveBeenCalled()
  })

  it('does not install a cached file when the fork cannot provide a checksum', async () => {
    mocks.files.set(installerPath, installer)
    mocks.get.mockRejectedValue(new Error('Fork release unavailable'))
    const { downloadAndInstallUpdate } = await import('./autoUpdater')
    await expect(downloadAndInstallUpdate('2.0.5')).rejects.toThrow('Fork release unavailable')
    expect(mocks.spawn).not.toHaveBeenCalled()
    expect(mocks.openPath).not.toHaveBeenCalled()
    expect(mocks.quit).not.toHaveBeenCalled()
  })

  it('rejects an unsafe version without fetching or starting anything', async () => {
    const { downloadAndInstallUpdate } = await import('./autoUpdater')
    await expect(downloadAndInstallUpdate('../2.0.5')).rejects.toThrow('Invalid update version')
    expect(mocks.get).not.toHaveBeenCalled()
    expect(mocks.spawn).not.toHaveBeenCalled()
    expect(mocks.exec).not.toHaveBeenCalled()
    expect(mocks.execFile).not.toHaveBeenCalled()
  })
})
