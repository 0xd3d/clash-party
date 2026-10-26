import { describe, expect, it } from 'vitest'
import {
  applyNetworkProtectionPolicy,
  QQ_MUSIC_DNS_EXCEPTION
} from '../core/networkProtectionPolicy'
import { deepMerge } from '../utils/merge'
import { planProtectionSetup } from './setupPlan'

const settings = () =>
  ({
    operationMode: 'simple',
    modeSelected: true,
    controlDns: true,
    autoSetDNS: true,
    systemDNSRestoreMode: 'automatic',
    networkProtection: false
  }) as IAppConfig
const control = () =>
  ({
    mode: 'global',
    'allow-lan': true,
    'bind-address': '*',
    'mixed-port': 8888,
    'interface-name': 'a-physical-interface',
    tun: {
      enable: false,
      device: 'copied-device',
      'strict-route': false,
      mtu: 1400,
      'route-exclude-address': ['192.168.3.4/32']
    },
    dns: { nameserver: ['223.5.5.5'] }
  }) as Partial<IMihomoConfig>
const profile = () =>
  ({
    proxies: [{ name: 'PrivateNode', type: 'vless', server: '198.51.100.50', port: 443 }],
    'proxy-groups': [{ name: 'Outbound', type: 'select', proxies: ['PrivateNode'] }],
    rules: ['RULE-SET,domestic,DIRECT', 'MATCH,Outbound'],
    dns: {
      enable: true,
      nameserver: ['https://192.0.2.53/dns-query#Outbound'],
      'default-nameserver': ['https://192.0.2.54/dns-query#DIRECT'],
      'nameserver-policy': {
        'aqqmusic.tc.qq.com': [QQ_MUSIC_DNS_EXCEPTION],
        '+.stream.qqmusic.qq.com': [QQ_MUSIC_DNS_EXCEPTION]
      }
    }
  }) as unknown as IMihomoConfig

describe('one-click protection plan', () => {
  it.each(['darwin', 'win32'] as const)(
    'enables required settings on %s without touching imported node or domestic policy',
    (platform) => {
      const app = settings(),
        source = control(),
        nodeProfile = profile()
      const original = structuredClone({ app, source, nodeProfile })
      const plan = planProtectionSetup(app, source, platform)
      expect(plan.appPatch).toMatchObject({
        operationMode: 'standard',
        controlDns: false,
        networkProtection: true,
        networkProtectionPublicUDP: true
      })
      expect(plan.control).toMatchObject({
        mode: 'rule',
        'allow-lan': false,
        'bind-address': '127.0.0.1',
        'mixed-port': 8888,
        tun: {
          enable: true,
          'auto-route': true,
          'strict-route': true,
          'auto-detect-interface': true,
          'dns-hijack': ['any:53', 'tcp://any:53'],
          mtu: 1400,
          'route-exclude-address': ['192.168.3.4/32']
        }
      })
      expect(plan.control.tun?.device).toBe(platform === 'darwin' ? 'utun1500' : 'Mihomo')
      const generatedControl = structuredClone(plan.control)
      delete generatedControl.dns // factory disables app DNS override
      const runtime = deepMerge(structuredClone(nodeProfile), generatedControl)
      applyNetworkProtectionPolicy(runtime, { ...app, ...plan.appPatch })
      expect(runtime.proxies).toEqual(original.nodeProfile.proxies)
      expect(runtime.dns?.['nameserver-policy']).toEqual(
        original.nodeProfile.dns?.['nameserver-policy']
      )
      expect(runtime.dns?.['default-nameserver']).toEqual(
        original.nodeProfile.dns?.['default-nameserver']
      )
      expect(runtime.rules).toContain('RULE-SET,domestic,DIRECT')
      expect(runtime.rules).toContain('IP-CIDR,192.168.0.0/16,DIRECT,no-resolve')
      expect(runtime.rules).toContain('NETWORK,UDP,Outbound')
      expect(runtime).not.toHaveProperty('interface-name')
      expect({ app, source, nodeProfile }).toEqual(original)
    }
  )
  it('preserves Mac DNS exit recovery and does not add Mac settings on Windows', () => {
    const app = settings()
    expect(planProtectionSetup(app, control(), 'darwin').appPatch).toMatchObject({
      autoSetDNS: true,
      systemDNSAddress: '127.0.0.1',
      systemDNSRestoreMode: 'automatic'
    })
    const windows = planProtectionSetup(app, control(), 'win32')
    expect(windows.appPatch).not.toHaveProperty('autoSetDNS')
    expect(windows.appPatch).not.toHaveProperty('systemDNSAddress')
  })
  it('is idempotent and rejects unsupported platforms or malformed targets', () => {
    const first = planProtectionSetup(settings(), control(), 'darwin', ' Outbound ')
    const next = planProtectionSetup(
      { ...settings(), ...first.appPatch },
      first.control,
      'darwin',
      'Outbound'
    )
    expect(next.settingsChanged).toBe(false)
    expect(() => planProtectionSetup(settings(), control(), 'linux')).toThrow('macOS or Windows')
    expect(() => planProtectionSetup(settings(), control(), 'win32', 'x'.repeat(257))).toThrow(
      'Invalid'
    )
  })
})
