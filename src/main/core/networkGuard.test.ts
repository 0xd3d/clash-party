import { describe, expect, it, vi } from 'vitest'
import {
  NetworkGuardSession,
  armWindowsNetworkGuard,
  parseTrafficGuardStatus,
  type NetworkGuardAdapter,
  type NetworkGuardStatus
} from './networkGuard'
vi.mock('electron', () => ({ app: { isPackaged: false, getAppPath: () => '/mock/app' } }))
vi.mock('../utils/logger', () => ({ managerLogger: { info: vi.fn(), error: vi.fn() } }))
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

describe('Windows independent helper startup', () => {
  const absent = { active: false, corePid: null, guardPid: null }
  const ready = { active: false, corePid: null, guardPid: 101 }
  const armed = { active: true, corePid: null, guardPid: 101 }
  it('confirms a native independent server before arming exactly once', async () => {
    const call = vi
      .fn()
      .mockResolvedValueOnce(absent)
      .mockResolvedValueOnce(ready)
      .mockResolvedValueOnce(armed)
    await expect(
      armWindowsNetworkGuard('C:\\Core App\\mihomo.exe', 'Mihomo', call)
    ).resolves.toEqual(armed)
    expect(call.mock.calls.map(([args]) => args)).toEqual([
      ['status'],
      ['start'],
      ['arm', '--core-path', 'C:\\Core App\\mihomo.exe', '--tun-name', 'Mihomo']
    ])
  })
  it('reuses an existing server without spawning or releasing it', async () => {
    const call = vi.fn().mockResolvedValueOnce(ready).mockResolvedValueOnce(armed)
    await armWindowsNetworkGuard('/core', 'virtual', call)
    expect(call.mock.calls.map(([args]) => args[0])).toEqual(['status', 'arm'])
  })
  it('preserves the actual native startup reason instead of retrying arm against a missing pipe', async () => {
    const call = vi
      .fn()
      .mockResolvedValueOnce(absent)
      .mockRejectedValueOnce(
        new Error('Network protection: Create private local command pipe failed (5)')
      )
    await expect(armWindowsNetworkGuard('/core', 'virtual', call)).rejects.toThrow(
      'Create private local command pipe'
    )
    expect(call.mock.calls.map(([args]) => args[0])).toEqual(['status', 'start'])
  })
  it('uses the broker only for a confirmed inherited-job failure then authenticates the guard', async () => {
    const call = vi
      .fn()
      .mockResolvedValueOnce(absent)
      .mockRejectedValueOnce(
        new Error(
          'Network protection: Windows retained the guard in a parent job; protection was not started'
        )
      )
      .mockResolvedValueOnce(ready)
      .mockResolvedValueOnce(armed)
    const broker = vi.fn().mockResolvedValue(101)
    await expect(armWindowsNetworkGuard('/core', 'virtual', call, broker)).resolves.toEqual(armed)
    expect(broker).toHaveBeenCalledOnce()
    expect(call.mock.calls.map(([args]) => args[0])).toEqual(['status', 'start', 'status', 'arm'])
  })
  it('does not arm after broker failure or a missing authenticated guard', async () => {
    for (const brokerFails of [true, false]) {
      const call = vi
        .fn()
        .mockResolvedValueOnce(absent)
        .mockRejectedValueOnce(
          new Error(
            'Network protection: Start independent guard; parent Windows job must permit breakaway failed (5)'
          )
        )
        .mockResolvedValue(absent)
      const broker = brokerFails
        ? vi.fn().mockRejectedValue(new Error('Local WMI unavailable'))
        : vi.fn().mockResolvedValue(101)
      await expect(armWindowsNetworkGuard('/core', 'virtual', call, broker)).rejects.toThrow(
        brokerFails ? 'Local WMI unavailable' : 'identity changed before arming'
      )
      expect(call.mock.calls.some(([args]) => args[0] === 'arm' || args[0] === 'release')).toBe(
        false
      )
    }
  })
  it('rejects a different authenticated helper after broker launch without releasing it', async () => {
    const call = vi
      .fn()
      .mockResolvedValueOnce(absent)
      .mockRejectedValueOnce(
        new Error(
          'Network protection: Windows retained the guard in a parent job; protection was not started'
        )
      )
      .mockResolvedValueOnce({ ...ready, guardPid: 202 })
    await expect(armWindowsNetworkGuard('/core', 'virtual', call, async () => 101)).rejects.toThrow(
      'identity changed before arming'
    )
    expect(call.mock.calls.map(([args]) => args[0])).toEqual(['status', 'start', 'status'])
  })
  it('rejects unconfirmed startup without arming or disabling protection', async () => {
    const call = vi.fn().mockResolvedValue(absent)
    await expect(armWindowsNetworkGuard('/core', 'virtual', call)).rejects.toThrow(
      'startup was not confirmed'
    )
    expect(call.mock.calls.map(([args]) => args[0])).toEqual(['status', 'start'])
  })
  it('preserves a previous lease when policy replacement fails', async () => {
    const call = vi
      .fn()
      .mockResolvedValueOnce(armed)
      .mockRejectedValueOnce(new Error('WFP replacement failed'))
    await expect(armWindowsNetworkGuard('/core', 'virtual', call)).rejects.toThrow(
      'WFP replacement failed'
    )
    expect(call.mock.calls.map(([args]) => args[0])).toEqual(['status', 'arm'])
  })
})
