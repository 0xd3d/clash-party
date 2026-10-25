import { describe, expect, it } from 'vitest'
import { auditPrivacyConfig } from './privacyAudit'

function profile(overrides: Record<string, unknown> = {}): Partial<IMihomoConfig> {
  return {
    mode: 'rule',
    'allow-lan': false,
    ipv6: false,
    tun: {
      enable: true,
      'auto-route': true,
      'strict-route': true,
      'dns-hijack': ['any:53', 'tcp://any:53']
    },
    dns: {
      enable: true,
      ipv6: false,
      nameserver: ['https://resolver.example.test/dns-query#My%20Route'],
      'proxy-server-nameserver': ['tls://192.0.2.53'],
      'nameserver-policy': {
        '+.media.example.test': '192.0.2.53',
        '+.local.example.test': ['192.0.2.54']
      }
    },
    proxies: [{ name: 'Example Node', type: 'socks5', server: '192.0.2.1', port: 1080 }],
    'proxy-groups': [{ name: 'My Route', type: 'select', proxies: ['Example Node'] }],
    rules: [
      'IP-CIDR,192.168.0.0/16,DIRECT,no-resolve',
      'IP-CIDR6,fc00::/7,DIRECT,no-resolve',
      'NETWORK,udp,My Route',
      'MATCH,My Route'
    ],
    ...overrides
  } as unknown as Partial<IMihomoConfig>
}

function finding(config: Partial<IMihomoConfig>, id: string, platform: NodeJS.Platform = 'win32') {
  return auditPrivacyConfig(config, platform).find((entry) => entry.id === id)
}

describe('privacy configuration audit', () => {
  it('checks Windows configuration without equating it with a network measurement', () => {
    const config = profile()
    const findings = auditPrivacyConfig(config, 'win32')
    expect(findings).toContainEqual({ id: 'scope', level: 'info' })
    expect(findings).toContainEqual({ id: 'windowsRouting', level: 'info' })
    for (const id of [
      'tunEnabled',
      'autoRoute',
      'strictRoute',
      'dnsHijackUdp',
      'dnsHijackTcp',
      'dnsEnabled',
      'dnsEncrypted',
      'dnsProxyOutbound',
      'lanAccess',
      'udpRouting'
    ]) {
      expect(findings.find((entry) => entry.id === id)?.level).toBe('pass')
    }
    expect(findings).toContainEqual({ id: 'ipv6Config', level: 'info', detail: 'false / false' })
    expect(findings.some((entry) => entry.id === 'udpRuleOrdering')).toBe(false)
  })

  it('treats macOS system DNS automation as configuration state only', () => {
    expect(auditPrivacyConfig(profile(), 'darwin', { autoSetDNS: true })).toContainEqual({
      id: 'macSystemDNS',
      level: 'info'
    })
    expect(auditPrivacyConfig(profile(), 'darwin', { autoSetDNS: false })).toContainEqual({
      id: 'macSystemDNS',
      level: 'warning'
    })
    expect(finding(profile(), 'strictRoute', 'darwin')?.level).toBe('info')
    expect(finding(profile(), 'windowsRouting', 'darwin')).toBeUndefined()
  })

  it('preserves custom groups, names, and both DNS exceptions without exposing domains', () => {
    const config = profile()
    const before = structuredClone(config)
    const findings = auditPrivacyConfig(config, 'win32')
    expect(config).toEqual(before)
    expect(findings).toContainEqual({ id: 'dnsPolicy', level: 'info', detail: '2' })
    expect(findings.find((entry) => entry.id === 'dnsEncrypted')?.level).toBe('pass')
    expect(JSON.stringify(findings)).not.toContain('media.example.test')
    expect(JSON.stringify(findings)).not.toContain('My Route')
  })

  it('flags plaintext regular, fallback and auxiliary DNS separately', () => {
    const config = profile({
      dns: {
        enable: true,
        nameserver: ['https://resolver.example.test/dns-query#My%20Route', '192.0.2.53'],
        fallback: ['tcp://192.0.2.54'],
        'default-nameserver': ['192.0.2.55']
      }
    })
    expect(finding(config, 'dnsEncrypted')?.level).toBe('warning')
    expect(finding(config, 'dnsProxyOutbound')?.level).toBe('warning')
    expect(finding(config, 'dnsAuxiliary')?.level).toBe('warning')
  })

  it('warns about an unspecified DNS outbound without asserting a leak', () => {
    const config = profile({
      dns: { enable: true, nameserver: ['https://resolver.example.test/dns-query'] }
    })
    expect(finding(config, 'dnsEncrypted')?.level).toBe('pass')
    expect(finding(config, 'dnsProxyOutbound')).toEqual({
      id: 'dnsProxyOutbound',
      level: 'warning'
    })
  })

  it('does not confuse #RULES, an interface, or DNS options with a verified proxy outbound', () => {
    for (const suffix of ['RULES', 'en0', 'h3=true', 'h3', 'ecs=192.0.2.0/24']) {
      const config = profile({
        dns: { enable: true, nameserver: [`https://resolver.example.test/dns-query#${suffix}`] }
      })
      expect(finding(config, 'dnsProxyOutbound')?.level).toBe('warning')
    }
    const config = profile({
      dns: { enable: true, 'respect-rules': true, nameserver: ['tls://192.0.2.53#RULES'] }
    })
    expect(finding(config, 'dnsRuleRouting')?.level).toBe('info')
    expect(finding(config, 'dnsBootstrap')?.level).toBe('warning')
  })

  it('requires both broad UDP and TCP port 53 hijacks', () => {
    const config = profile({
      tun: { enable: true, 'dns-hijack': ['192.0.2.53:53', 'tcp://any:53'] }
    })
    expect(finding(config, 'dnsHijackUdp')?.level).toBe('warning')
    expect(finding(config, 'dnsHijackTcp')?.level).toBe('pass')
    expect(
      finding(profile({ tun: { 'dns-hijack': ['udp://any:53'] } }), 'dnsHijackTcp')?.level
    ).toBe('warning')
  })

  it('reports a blanket UDP DIRECT route as an error', () => {
    expect(
      finding(profile({ rules: ['NETWORK,udp,DIRECT', 'MATCH,My Route'] }), 'udpDirect')
    ).toEqual({
      id: 'udpDirect',
      level: 'error'
    })
  })

  it('warns about potentially public DIRECT matches before the blanket route', () => {
    for (const rule of [
      'DOMAIN-SUFFIX,example.test,DIRECT',
      'IP-CIDR,192.168.0.0/8,DIRECT,no-resolve',
      'IP-CIDR,203.0.113.0/24,DIRECT,no-resolve',
      'AND,((NETWORK,udp),(DOMAIN,example.test)),DIRECT'
    ]) {
      const config = profile({ rules: [rule, 'NETWORK,udp,REJECT', 'MATCH,My Route'] })
      expect(finding(config, 'udpRuleOrdering')?.level).toBe('warning')
    }
  })

  it('recognizes only the explicit local-domain allowlist before UDP routing', () => {
    for (const type of ['DOMAIN', 'DOMAIN-SUFFIX']) {
      for (const domain of ['localhost', 'lan', 'local', 'LOCALHOST']) {
        const config = profile({ rules: [`${type},${domain},DIRECT`, 'NETWORK,udp,REJECT'] })
        expect(finding(config, 'udpRuleOrdering')).toBeUndefined()
      }
      for (const domain of ['example.test', 'local.example.test', 'example.localhost.test']) {
        const config = profile({ rules: [`${type},${domain},DIRECT`, 'NETWORK,udp,REJECT'] })
        expect(finding(config, 'udpRuleOrdering')?.level).toBe('warning')
      }
    }
  })

  it('respects rule order and does not flag unreachable later DIRECT rules', () => {
    const config = profile({
      rules: ['NETWORK,udp,REJECT', 'DOMAIN-SUFFIX,example.test,DIRECT', 'MATCH,DIRECT']
    })
    expect(finding(config, 'udpRouting')?.level).toBe('pass')
    expect(finding(config, 'udpRuleOrdering')).toBeUndefined()
    expect(finding(config, 'udpDirect')).toBeUndefined()
  })

  it('warns about earlier rule sets and possible DIRECT group selections', () => {
    const config = profile({
      'proxy-groups': [
        { name: 'My Route', type: 'select', proxies: ['Nested Route'] },
        { name: 'Nested Route', type: 'select', proxies: ['My Route', 'DIRECT'] }
      ],
      rules: ['RULE-SET,custom,My Route', 'NETWORK,udp,My Route']
    })
    expect(finding(config, 'udpGroupSelection')?.level).toBe('warning')
    expect(finding(config, 'udpComplexRules')?.level).toBe('warning')
    expect(finding(config, 'dnsProxyOutbound')?.level).toBe('warning')
  })

  it('recognizes a named direct outbound without changing custom routing', () => {
    const config = profile({
      proxies: [{ name: 'Local Exit', type: 'direct' }],
      'proxy-groups': [{ name: 'My Route', type: 'select', proxies: ['Local Exit'] }],
      rules: ['NETWORK,udp,Local Exit']
    })
    const before = structuredClone(config)
    expect(finding(config, 'udpDirect')?.level).toBe('error')
    expect(finding(config, 'dnsProxyOutbound')?.level).toBe('warning')
    expect(config).toEqual(before)
  })

  it('does not verify unknown provider members or include-all selections as proxy routes', () => {
    for (const source of [
      { use: ['Example Provider'] },
      { 'include-all': true },
      { 'include-all-providers': true },
      { 'include-all-proxies': true }
    ]) {
      const config = profile({
        'proxy-groups': [
          { name: 'My Route', type: 'select', proxies: ['Nested Route'] },
          { name: 'Nested Route', type: 'select', proxies: ['Example Node'], ...source }
        ]
      })
      const before = structuredClone(config)
      expect(finding(config, 'dnsProxyOutbound')?.level).toBe('warning')
      expect(finding(config, 'udpRouting')?.level).toBe('warning')
      expect(config).toEqual(before)
    }
  })

  it('warns about empty, unresolved, or cyclic group members without inferring node selection', () => {
    for (const members of [[], ['Unknown Node'], ['My Route']]) {
      const config = profile({
        'proxy-groups': [{ name: 'My Route', type: 'select', proxies: members }]
      })
      expect(finding(config, 'dnsProxyOutbound')?.level).toBe('warning')
      expect(finding(config, 'udpRouting')?.level).toBe('warning')
    }
    const config = profile({ 'proxy-groups': [{ name: 'My Route', type: 'select' }] })
    expect(finding(config, 'dnsProxyOutbound')?.level).toBe('warning')
    expect(finding(config, 'udpRouting')?.level).toBe('warning')
  })

  it('does not infer protection from IPv6 flags, direct/global mode, or missing configuration', () => {
    const ipv6 = finding(profile({ ipv6: true, dns: { ipv6: true } }), 'ipv6Config')
    expect(ipv6).toEqual({ id: 'ipv6Config', level: 'info', detail: 'true / true' })
    expect(finding(profile({ mode: 'direct' }), 'udpDirectMode')?.level).toBe('error')
    expect(finding(profile({ mode: 'global' }), 'udpGlobalMode')?.level).toBe('warning')
    expect(finding({}, 'tunEnabled')?.level).toBe('error')
    expect(finding({}, 'dnsEnabled')?.level).toBe('error')
    expect(finding({}, 'dnsUpstreamsMissing')?.level).toBe('warning')
    expect(finding(profile({ rules: [] }), 'udpRouting')?.level).toBe('warning')
  })

  it('keeps route exclusions and LAN access visible for review', () => {
    const config = profile({
      'allow-lan': true,
      tun: { 'route-exclude-address': ['192.168.0.0/16'] }
    })
    expect(finding(config, 'routeExclusions')?.level).toBe('warning')
    expect(finding(config, 'lanAccess')?.level).toBe('warning')
  })
})
