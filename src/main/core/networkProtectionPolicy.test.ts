import { describe, expect, it } from 'vitest'
import {
  applyNetworkProtectionPolicy,
  QQ_MUSIC_DNS_EXCEPTION,
  protectionTarget
} from './networkProtectionPolicy'

function profile(): IMihomoConfig & { dns: IMihomoDNSConfig } {
  return {
    mode: 'rule',
    tun: { enable: true, device: 'virtual-test' },
    ipv6: true,
    'interface-name': 'old-manual-interface',
    proxies: [{ name: 'Node', type: 'vless', server: '198.51.100.10', port: 443 }],
    'proxy-groups': [{ name: 'Protected', type: 'select', proxies: ['Node'] }],
    rules: ['DOMAIN-SUFFIX,qq.com,DIRECT', 'GEOIP,CN,DIRECT', 'MATCH,Protected'],
    dns: {
      enable: true,
      'default-nameserver': ['https://1.1.1.1/dns-query'],
      nameserver: ['https://dns.google/dns-query#DIRECT&h3=true'],
      'nameserver-policy': {
        'aqqmusic.tc.qq.com': [QQ_MUSIC_DNS_EXCEPTION],
        '+.stream.qqmusic.qq.com': QQ_MUSIC_DNS_EXCEPTION,
        '+.other.test': ['https://doh.pub/dns-query#DIRECT']
      }
    }
  } as unknown as IMihomoConfig & { dns: IMihomoDNSConfig }
}
const enabled = { networkProtection: true }
describe('protected runtime policy', () => {
  it('does not allow later or percent-encoded DNS fragment adapters to override protection', () => {
    for (const fragment of [
      'h3=true&DIRECT',
      'h3=true%26DIRECT',
      'h3=true%2526DIRECT',
      'Proxy&%44IRECT'
    ]) {
      const value = profile()
      value.dns.nameserver = [`https://dns.google/dns-query#${fragment}`]
      applyNetworkProtectionPolicy(value, enabled)
      const decoded = decodeURIComponent(new URL(value.dns.nameserver[0]).hash.slice(1))
      const adapters = decoded.split('&').filter((part) => !part.includes('='))
      expect(adapters).toEqual(['Protected'])
    }
    const value = profile()
    value.dns['default-nameserver'] = ['https://1.1.1.1/dns-query#DIRECT&Protected']
    expect(() => applyNetworkProtectionPolicy(value, enabled)).toThrow('independent')
  })
  it('makes all reachable filtered groups reject an empty result instead of COMPATIBLE direct', () => {
    const value = profile()
    const group = {
      name: 'Protected',
      type: 'select',
      proxies: ['Node'],
      'exclude-filter': '.*',
      'empty-fallback': 'DIRECT'
    }
    value['proxy-groups'] = [group] as unknown as []
    applyNetworkProtectionPolicy(value, enabled)
    expect(group['empty-fallback']).toBe('REJECT')
  })

  it('keeps stored domestic/LAN/QQ exceptions and routes public DNS/UDP before country shortcuts', () => {
    const value = profile()
    const original = [...(value.rules ?? [])]
    applyNetworkProtectionPolicy(value, enabled)
    const rules = value.rules as unknown as string[]
    expect(rules.indexOf('NETWORK,UDP,Protected')).toBeLessThan(rules.indexOf('GEOIP,CN,DIRECT'))
    expect(rules).toContain('IP-CIDR,127.0.0.0/8,DIRECT,no-resolve')
    expect(rules.indexOf('DST-PORT,53,Protected')).toBeLessThan(
      rules.indexOf('IP-CIDR,192.168.0.0/16,DIRECT,no-resolve')
    )
    expect(rules.indexOf('DST-PORT,853,Protected')).toBeLessThan(
      rules.indexOf('IP-CIDR6,fe80::/10,DIRECT,no-resolve')
    )
    expect(rules).toContain('IP-CIDR6,fe80::/10,DIRECT,no-resolve')
    // Even a known resolver mapped to a LAN address must not win the LAN DIRECT rule.
    expect(rules.indexOf('DOMAIN-SUFFIX,dns.google,Protected')).toBeLessThan(
      rules.indexOf('IP-CIDR,192.168.0.0/16,DIRECT,no-resolve')
    )
    expect(rules.slice(-3)).toEqual(original)
    expect(value.dns?.nameserver).toEqual(['https://dns.google/dns-query#h3=true&Protected'])
    expect(value.dns?.['nameserver-policy']?.['aqqmusic.tc.qq.com']).toEqual([
      QQ_MUSIC_DNS_EXCEPTION
    ])
    expect(value.dns?.['nameserver-policy']?.['+.stream.qqmusic.qq.com']).toEqual([
      QQ_MUSIC_DNS_EXCEPTION
    ])
    expect(value.dns?.['nameserver-policy']?.['+.other.test']).toEqual([
      'https://doh.pub/dns-query#Protected'
    ])
    expect(value).not.toHaveProperty('interface-name')
    expect(value.tun?.['auto-detect-interface']).toBe(true)
    expect(value.dns?.['proxy-server-nameserver']).toEqual(['https://1.1.1.1/dns-query'])
    const once = structuredClone(value)
    applyNetworkProtectionPolicy(value, enabled)
    expect(value).toEqual(once)
  })
  it('changes only the policy field when a target name equals a rule predicate', () => {
    for (const name of ['local', '53', '1.1.1.1/32']) {
      const value = profile()
      value['proxy-groups'] = [{ name, type: 'select', proxies: ['Node'] }] as unknown as []
      value.rules = [`MATCH,${name}`] as unknown as []
      applyNetworkProtectionPolicy(value, enabled)
      const rules = value.rules as unknown as string[]
      expect(rules).toContain(`DST-PORT,53,${name}`)
      expect(rules).toContain('DST-PORT,53,REJECT')
      expect(rules).toContain('DOMAIN-SUFFIX,local,DIRECT')
      expect(rules).not.toContain('DST-PORT,REJECT,53')
    }
  })
  it('does not modify any unprotected profile or silently enable a TUN', () => {
    const value = profile()
    const saved = structuredClone(value)
    applyNetworkProtectionPolicy(value, { networkProtection: false })
    expect(value).toEqual(saved)
    value.tun = { enable: false }
    expect(() => applyNetworkProtectionPolicy(value, enabled)).toThrow('enabled TUN')
  })
  it('reports an unavailable saved target without falling back to a different profile exit', () => {
    const value = profile()
    const original = structuredClone(value)
    expect(() => protectionTarget(value, 'Previous profile')).toThrow(
      '"Previous profile" references missing proxy or group "Previous profile"'
    )
    expect(value).toEqual(original)
    expect(protectionTarget(value)).toBe('Protected')
  })
  it('identifies missing nested members and duplicate names rather than reporting empty rules', () => {
    const value = profile()
    value['proxy-groups'] = [
      { name: 'Protected', type: 'select', proxies: ['Deleted node'] }
    ] as unknown as []
    expect(() => protectionTarget(value)).toThrow(
      '"Protected" references missing proxy or group "Deleted node"'
    )
    value['proxy-groups'] = [
      { name: 'Protected', type: 'select', proxies: ['Node'] }
    ] as unknown as []
    value.proxies = [
      ...(value.proxies ?? []),
      { name: 'Node', type: 'socks5', server: '198.51.100.20', port: 1080 }
    ] as unknown as []
    expect(() => protectionTarget(value)).toThrow('duplicate proxy/group name "Node"')
  })
  it('rejects direct fallback, provider membership and recursive groups', () => {
    const value = profile()
    value['proxy-groups'] = [{ name: 'Protected', proxies: ['Node', 'DIRECT'] }] as unknown as []
    expect(() => protectionTarget(value)).toThrow('direct fallback')
    value['proxy-groups'] = [{ name: 'Protected', proxies: ['Protected'] }] as unknown as []
    expect(() => protectionTarget(value)).toThrow('cycle')
    value['proxy-groups'] = [{ name: 'Protected', use: ['subscription'] }] as unknown as []
    expect(() => protectionTarget(value)).toThrow('Opaque')
    value['proxy-groups'] = [{ name: 'Protected', type: 'select' }] as unknown as []
    expect(() => protectionTarget(value)).toThrow('implicit')
  })
  it('rejects recursive/domain bootstrap and preserves only the exact authorized QQ exception', () => {
    const value = profile()
    value.dns['default-nameserver'] = ['https://dns.google/dns-query#Protected']
    expect(() => applyNetworkProtectionPolicy(value, enabled)).toThrow('literal IP')
    value.dns['default-nameserver'] = ['https://1.1.1.1/dns-query']
    value.dns['nameserver-policy'] = {
      'aqqmusic.tc.qq.com': 'https://another.test/dns-query#DIRECT'
    }
    applyNetworkProtectionPolicy(value, enabled)
    expect(value.dns['nameserver-policy']['aqqmusic.tc.qq.com']).toEqual([
      'https://another.test/dns-query#Protected'
    ])
  })
  it('preserves DNS URL query/options and supports deliberately retaining domestic UDP', () => {
    const value = profile()
    value.dns.nameserver = ['https://dns.google/dns-query?x=1#h3=true']
    applyNetworkProtectionPolicy(value, { ...enabled, networkProtectionPublicUDP: false })
    expect(value.dns.nameserver).toEqual(['https://dns.google/dns-query?x=1#h3=true&Protected'])
    expect(value.rules as unknown as string[]).not.toContain('NETWORK,UDP,Protected')
    expect(value.rules as unknown as string[]).toContain('DST-PORT,3478,Protected')
  })
})
