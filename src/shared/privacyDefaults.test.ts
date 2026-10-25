import { describe, expect, it } from 'vitest'
import { parse } from 'yaml'
import { deepMerge } from '../main/utils/merge'
import { DEFAULT_MIHOMO_TUN_CONFIG } from './appConfig'
import { defaultSimpleDraft } from './simple-config'

describe('privacy defaults and saved settings', () => {
  it('retains an existing user routing/interception choice during a defaults merge', () => {
    const saved = {
      enable: false,
      'strict-route': false,
      'dns-hijack': ['udp://192.0.2.53:53'],
      'route-exclude-address': ['192.0.2.1/32']
    }
    const merged = deepMerge<{ tun: Partial<typeof DEFAULT_MIHOMO_TUN_CONFIG> }>(
      { tun: structuredClone(DEFAULT_MIHOMO_TUN_CONFIG) },
      { tun: saved }
    )
    expect(merged.tun).toMatchObject(saved)
    expect(DEFAULT_MIHOMO_TUN_CONFIG['strict-route']).toBe(true)
    expect(DEFAULT_MIHOMO_TUN_CONFIG['dns-hijack']).toEqual(['any:53', 'tcp://any:53'])
  })

  it('new simple profiles use core protection defaults without enabling the tunnel', () => {
    const tun = parse(defaultSimpleDraft().modules.tun)
    expect(tun).toMatchObject({
      enable: false,
      'strict-route': true,
      'dns-hijack': ['any:53', 'tcp://any:53']
    })
  })
})
