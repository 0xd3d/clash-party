import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({ exec: vi.fn() }))
vi.mock('child_process', () => ({ execFile: mocks.exec }))
const platform = Object.getOwnPropertyDescriptor(process, 'platform') as PropertyDescriptor
const uid = Object.getOwnPropertyDescriptor(process, 'getuid')
let guard: typeof import('./macDNSGuard')

beforeEach(async () => {
  vi.resetModules()
  mocks.exec.mockReset()
  Object.defineProperty(process, 'platform', { configurable: true, value: 'darwin' })
  Object.defineProperty(process, 'getuid', { configurable: true, value: () => 501 })
  guard = await import('./macDNSGuard')
})
afterEach(() => {
  Object.defineProperty(process, 'platform', platform)
  if (uid) Object.defineProperty(process, 'getuid', uid)
  else Reflect.deleteProperty(process, 'getuid')
})

describe('fixed-purpose native DNS guard transport', () => {
  it('rejects invalid identities and states instead of treating output as protection', () => {
    for (const raw of [
      'null',
      '{}',
      '{"active":true,"ownerUid":502,"corePid":12}',
      '{"active":"true","ownerUid":501,"corePid":12}',
      '{"active":true,"ownerUid":501,"corePid":-1}'
    ])
      expect(() => guard.parseMacDNSGuardStatus(raw, 501)).toThrow()
  })
  it('only invokes a fixed helper with structured PID arguments and a minimal environment', async () => {
    mocks.exec.mockImplementation((_file, _args, _options, callback) => {
      callback(null, { stdout: '{"active":true,"ownerUid":501,"corePid":4321}', stderr: '' })
    })
    await expect(guard.acquireMacDNSGuard(4321)).resolves.toMatchObject({ active: true })
    expect(mocks.exec).toHaveBeenCalledWith(
      '/Library/PrivilegedHelperTools/party.mihomo.dns-guard',
      ['start', '4321'],
      expect.objectContaining({
        maxBuffer: 16384,
        env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C' }
      }),
      expect.any(Function)
    )
    await expect(guard.acquireMacDNSGuard(Number.NaN)).rejects.toThrow('PID')
    expect(mocks.exec).toHaveBeenCalledOnce()
  })
  it('serializes exit after a pending start so it cannot reactivate a completed exit', async () => {
    const complete: Array<(error: null, value: { stdout: string }) => void> = []
    mocks.exec.mockImplementation((_file, _args, _options, callback) => complete.push(callback))
    const starting = guard.acquireMacDNSGuard(4321)
    const stopping = guard.releaseMacDNSGuard()
    await vi.waitFor(() => expect(complete).toHaveLength(1))
    expect(mocks.exec.mock.calls[0][1]).toEqual(['start', '4321'])
    complete[0](null, { stdout: '{"active":true,"ownerUid":501,"corePid":4321}' })
    await starting
    await vi.waitFor(() => expect(complete).toHaveLength(2))
    expect(mocks.exec.mock.calls[1][1]).toEqual(['stop'])
    complete[1](null, { stdout: '{"active":false,"ownerUid":501,"corePid":null}' })
    await stopping
  })
  it('does not execute a macOS helper on Windows', async () => {
    Object.defineProperty(process, 'platform', { configurable: true, value: 'win32' })
    await expect(guard.inspectMacDNSGuard()).rejects.toThrow('platform')
    expect(mocks.exec).not.toHaveBeenCalled()
  })
  it('rejects a helper that reports protection for a different core', async () => {
    mocks.exec.mockImplementation((_file, _args, _options, callback) => {
      callback(null, { stdout: '{"active":true,"ownerUid":501,"corePid":4322}', stderr: '' })
    })
    await expect(guard.acquireMacDNSGuard(4321)).rejects.toThrow('this core')
  })
})
