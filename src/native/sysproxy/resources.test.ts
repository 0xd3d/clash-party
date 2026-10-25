import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import path from 'node:path'
import vm from 'node:vm'
import { describe, expect, it } from 'vitest'
const require = createRequire(import.meta.url)
const source = readFileSync(new URL('./index.js', import.meta.url), 'utf8')
function load(platform: string, packaged: boolean) {
  const paths = platform === 'win32' ? path.win32 : path.posix
  const cwd = platform === 'win32' ? 'C:\\checkout' : '/checkout'
  const resources = platform === 'win32' ? 'C:\\App\\resources' : '/App/Resources'
  const binding =
    platform === 'win32' ? 'sysproxy.win32-x64-msvc.node' : 'sysproxy.darwin-arm64.node'
  const loaded: string[] = []
  const values = Object.fromEntries(
    [
      'getAutoProxy',
      'setAutoProxy',
      'getSystemProxy',
      'setSystemProxy',
      'triggerAutoProxy',
      'triggerManualProxy'
    ].map((k) => [k, () => {}])
  )
  const module = { exports: {} }
  vm.runInNewContext(source, {
    module,
    __dirname: paths.join(cwd, 'src', 'native', 'sysproxy'),
    process: {
      platform,
      arch: platform === 'win32' ? 'x64' : 'arm64',
      resourcesPath: packaged ? resources : undefined,
      cwd: () => cwd
    },
    require: (name: string) => {
      if (name === 'path') return paths
      if (name === 'os') return { release: () => '10.0.26100' }
      if (name === 'fs')
        return {
          existsSync: (p: string) =>
            p === paths.join(cwd, 'extra', 'sidecar') ||
            (packaged && p === paths.join(resources, 'sidecar')) ||
            p === paths.join(packaged ? resources : paths.join(cwd, 'extra'), 'sidecar', binding)
        }
      if (name === './windows-version') return require('./windows-version.js')
      if (name.endsWith('.node')) {
        loaded.push(name)
        return values
      }
      throw new Error(name)
    }
  })
  return {
    loaded,
    expected: paths.join(packaged ? resources : paths.join(cwd, 'extra'), 'sidecar', binding)
  }
}
describe('native resource ownership', () => {
  it.each(['win32', 'darwin'])(
    'uses package resources on %s even when cwd is a checkout',
    (platform) => {
      const result = load(platform, true)
      expect(result.loaded).toEqual([result.expected])
    }
  )
  it('retains development resource fallback', () => {
    const result = load('darwin', false)
    expect(result.loaded).toEqual([result.expected])
  })
})
