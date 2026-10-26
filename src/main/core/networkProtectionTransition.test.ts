import { describe, expect, it, vi } from 'vitest'
import {
  transitionNetworkProtection,
  type NetworkProtectionTransition
} from './networkProtectionTransition'
function runtime(): Partial<IMihomoConfig> {
  return {
    mode: 'rule',
    tun: { enable: true, device: 'virtual' },
    proxies: [{ name: 'Node', type: 'vless', server: '198.51.100.10', port: 443 }],
    'proxy-groups': [{ name: 'Safe', type: 'select', proxies: ['Node'] }],
    rules: ['MATCH,Safe'],
    dns: {
      enable: true,
      'default-nameserver': ['https://1.1.1.1/dns-query'],
      nameserver: ['https://1.1.1.1/dns-query#Safe']
    }
  } as unknown as Partial<IMihomoConfig>
}
function actions(snapshot = runtime()): NetworkProtectionTransition {
  return {
    readSettings: vi.fn().mockResolvedValue({ autoSetDNS: true, networkProtection: false }),
    readRuntime: vi.fn().mockResolvedValue(snapshot),
    persist: vi.fn().mockResolvedValue(undefined),
    stop: vi.fn().mockResolvedValue(undefined),
    recover: vi.fn().mockResolvedValue(undefined),
    restart: vi.fn().mockResolvedValue(undefined)
  }
}
describe('network protection settings transition', () => {
  it('does not persist an ineligible target or bootstrap and leaves the shared snapshot untouched', async () => {
    for (const kind of ['bootstrap', 'target']) {
      const snapshot = runtime()
      if (kind === 'bootstrap')
        snapshot.dns = { ...snapshot.dns, 'default-nameserver': ['https://1.1.1.1/dns-query#Safe'] }
      else snapshot.rules = ['MATCH,DIRECT'] as unknown as []
      const original = structuredClone(snapshot),
        calls = actions(snapshot)
      await expect(transitionNetworkProtection({ enabled: true }, calls)).rejects.toThrow()
      expect(snapshot).toEqual(original)
      for (const method of [calls.persist, calls.restart, calls.stop, calls.recover])
        expect(method).not.toHaveBeenCalled()
    }
  })
  it('preflights a clone before saving normalized settings and restarting', async () => {
    const snapshot = runtime(),
      original = structuredClone(snapshot),
      calls = actions(snapshot),
      order: string[] = []
    vi.mocked(calls.readRuntime).mockImplementation(async () => {
      order.push('preflight')
      return snapshot
    })
    vi.mocked(calls.persist).mockImplementation(async () => {
      expect(snapshot).toEqual(original)
      order.push('persist')
    })
    vi.mocked(calls.restart).mockImplementation(async () => {
      order.push('restart')
    })
    await transitionNetworkProtection(
      { enabled: true, proxyGroup: ' Safe ', protectPublicUDP: true },
      calls
    )
    expect(order).toEqual(['preflight', 'persist', 'restart'])
    expect(calls.persist).toHaveBeenCalledWith({
      networkProtection: true,
      networkProtectionProxyGroup: 'Safe',
      networkProtectionPublicUDP: true
    })
    expect(calls.recover).not.toHaveBeenCalled()
  })
  it('can disable and recover even with no eligible runtime', async () => {
    const calls = actions({}),
      order: string[] = []
    vi.mocked(calls.stop).mockImplementation(async () => {
      order.push('stop')
    })
    vi.mocked(calls.recover).mockImplementation(async () => {
      order.push('recover')
    })
    vi.mocked(calls.persist).mockImplementation(async () => {
      order.push('persist')
    })
    vi.mocked(calls.restart).mockImplementation(async () => {
      order.push('restart')
    })
    await transitionNetworkProtection({ enabled: false }, calls)
    expect(order).toEqual(['stop', 'recover', 'persist', 'restart'])
    expect(calls.readRuntime).not.toHaveBeenCalled()
    expect(calls.persist).toHaveBeenCalledWith({
      networkProtection: false,
      networkProtectionProxyGroup: '',
      networkProtectionPublicUDP: true
    })
  })
  it('retains enabled intent after a start/arm failure without automatic recovery', async () => {
    const calls = actions()
    vi.mocked(calls.restart).mockRejectedValue(new Error('Native acquire failed after arming'))
    await expect(transitionNetworkProtection({ enabled: true }, calls)).rejects.toThrow(
      'after arming'
    )
    expect(calls.persist).toHaveBeenCalledOnce()
    expect(calls.persist).toHaveBeenCalledWith({
      networkProtection: true,
      networkProtectionProxyGroup: '',
      networkProtectionPublicUDP: true
    })
    expect(calls.recover).not.toHaveBeenCalled()
    expect(calls.stop).not.toHaveBeenCalled()
  })
})
