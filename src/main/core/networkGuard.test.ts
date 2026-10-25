import { describe, expect, it, vi } from 'vitest'
import {
  NetworkGuardSession,
  parseTrafficGuardStatus,
  type NetworkGuardAdapter,
  type NetworkGuardStatus
} from './networkGuard'
vi.mock('electron', () => ({ app: { isPackaged: false, getAppPath: () => '/mock/app' } }))
function adapter(): NetworkGuardAdapter {
  return {
    arm: vi.fn().mockResolvedValue({ active: true, corePid: null }),
    bind: vi
      .fn()
      .mockResolvedValue({ active: true, corePid: 42, coreAlive: true, tunName: 'virtual' }),
    inspect: vi.fn().mockResolvedValue({ active: true, corePid: 42 }),
    release: vi.fn().mockResolvedValue({ active: false, corePid: null })
  }
}
function deferred<T>() {
  let resolve!: (v: T) => void
  const promise = new Promise<T>((r) => {
    resolve = r
  })
  return { resolve, promise }
}
describe('independent traffic protection session', () => {
  it('arms before binding and keeps its lease across a core crash', async () => {
    const native = adapter()
    const guard = new NetworkGuardSession(native)
    await guard.arm('/core', 'virtual')
    await guard.bind('/core', 42, 'virtual')
    vi.mocked(native.inspect).mockResolvedValue({ active: true, corePid: 42, coreAlive: false })
    expect((await guard.inspect()).active).toBe(true)
    expect(guard.enabled).toBe(true)
    expect(native.release).not.toHaveBeenCalled()
    await guard.arm('/core', 'virtual')
    await guard.bind('/core', 42, 'virtual')
    expect(native.release).not.toHaveBeenCalled()
  })
  it('does not remove protection after failed startup or reload', async () => {
    const native = adapter()
    const guard = new NetworkGuardSession(native)
    await guard.arm('/core', 'virtual')
    vi.mocked(native.bind).mockRejectedValue(new Error('TUN unavailable'))
    await expect(guard.bind('/core', 42, 'virtual')).rejects.toThrow('TUN unavailable')
    expect(native.release).not.toHaveBeenCalled()
    expect(guard.enabled).toBe(true)
  })
  it('requires the actual core and virtual adapter, not only a config flag', async () => {
    const native = adapter()
    const guard = new NetworkGuardSession(native)
    await guard.arm('/core', 'virtual')
    vi.mocked(native.bind).mockResolvedValue({ active: true, corePid: 43, tunName: 'physical' })
    await expect(guard.bind('/core', 42, 'virtual')).rejects.toThrow('actual core')
  })
  it('cancels delayed startup then releases in command order', async () => {
    const native = adapter()
    const pending = deferred<NetworkGuardStatus>()
    vi.mocked(native.arm).mockReturnValue(pending.promise)
    const guard = new NetworkGuardSession(native)
    const starting = guard.arm('/core', 'virtual')
    await Promise.resolve()
    const stopped = guard.release()
    pending.resolve({ active: true, corePid: null })
    await expect(starting).rejects.toThrow('cancelled')
    await stopped
    expect(native.release).toHaveBeenCalledOnce()
    expect(guard.enabled).toBe(false)
  })
  it('allows a new session only after an older release completes', async () => {
    const native = adapter()
    const guard = new NetworkGuardSession(native)
    await guard.arm('/core', 'virtual')
    const waiting = deferred<NetworkGuardStatus>()
    vi.mocked(native.release).mockReturnValue(waiting.promise)
    const stopping = guard.release()
    await Promise.resolve()
    const restarting = guard.arm('/core', 'virtual')
    waiting.resolve({ active: false, corePid: null })
    await stopping
    await restarting
    await guard.bind('/core', 42, 'virtual')
    expect(guard.enabled).toBe(true)
  })
  it('does not mistake a remaining DNS lease for an unreleased traffic lease', async () => {
    const native = adapter()
    const guard = new NetworkGuardSession(native)
    await guard.arm('/core', 'virtual')
    vi.mocked(native.release).mockResolvedValue({
      active: true,
      corePid: null,
      trafficLease: false,
      protection: 'dns'
    })
    await guard.release()
    expect(guard.enabled).toBe(false)
  })
  it('keeps recovery incomplete when the traffic lease remains', async () => {
    const native = adapter()
    const guard = new NetworkGuardSession(native)
    await guard.arm('/core', 'virtual')
    vi.mocked(native.release).mockResolvedValue({ active: true, corePid: 42, trafficLease: true })
    await expect(guard.release()).rejects.toThrow('incomplete')
    expect(guard.enabled).toBe(true)
  })
})
describe('native traffic status validation', () => {
  it('requires protocol identity and a valid Windows core lifetime field', () => {
    expect(() =>
      parseTrafficGuardStatus(JSON.stringify({ active: true, corePid: 42 }), 'win32')
    ).toThrow('protocol')
    expect(
      parseTrafficGuardStatus(
        JSON.stringify({
          protocolVersion: 1,
          active: false,
          corePid: null,
          coreAlive: false,
          guardPid: null,
          corePath: null,
          filterCount: 0
        }),
        'win32'
      ).active
    ).toBe(false)
  })
  it('rejects an active Windows response without actual helper/filter ownership', () => {
    expect(() =>
      parseTrafficGuardStatus(
        JSON.stringify({
          protocolVersion: 1,
          active: true,
          corePid: 42,
          coreAlive: true,
          guardPid: null,
          corePath: '/core',
          filterCount: 0
        }),
        'win32'
      )
    ).toThrow('filter ownership')
  })
  it('rejects mismatched macOS ownership and missing traffic proof', () => {
    expect(() =>
      parseTrafficGuardStatus(
        JSON.stringify({ active: true, corePid: 42, ownerUid: -1, trafficLease: true }),
        'darwin'
      )
    ).toThrow('ownership')
    expect(() =>
      parseTrafficGuardStatus(
        JSON.stringify({ active: true, corePid: 42, ownerUid: process.getuid?.() }),
        'darwin'
      )
    ).toThrow('ownership')
  })
})
