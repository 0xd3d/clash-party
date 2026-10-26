import { describe, expect, it } from 'vitest'
import { auditPrivacyConfig } from './privacyAudit'
import {
  ipRange,
  isLocalDestination,
  sameHost,
  traceTunRoutes,
  splitRuleFields
} from './privacyRouting'
const profile = (rules: string[] = []): Partial<IMihomoConfig> =>
  ({
    mode: 'rule',
    proxies: [{ name: 'Node', type: 'vless', server: '203.0.113.8' }],
    'proxy-groups': [{ name: 'Proxy', type: 'select', proxies: ['Node'] }],
    rules: [...rules, 'NETWORK,UDP,Proxy', 'MATCH,Proxy']
  }) as unknown as Partial<IMihomoConfig>
const risk = (rule: string) =>
  auditPrivacyConfig(profile([rule]), 'win32').filter(
    (f) => f.id.startsWith('udp') && f.level === 'warning'
  )

describe('full destination-range checks', () => {
  it.each([
    '127.255.255.255/8',
    '10.255.255.255/8',
    '172.31.255.255/12',
    '192.168.99.1/16',
    '169.254.0.1/16',
    '100.127.255.255/10',
    '239.255.255.255/4',
    '255.255.255.255/32',
    'fc00::/7',
    'fdff:ffff::/7',
    'fe80::/10',
    'febf:ffff::/10',
    'ff02::1/8',
    '::1/128',
    '::ffff/128'
  ])('recognizes the complete non-public range %s', (value) => {
    // ::ffff is not an unspecified/loopback destination, even though it shares their prefix.
    expect(isLocalDestination(value)).toBe(value !== '::ffff/128')
  })
  it.each([
    '10.0.0.0/7',
    '127.0.0.0/7',
    '172.16.0.0/11',
    '192.168.0.0/8',
    '169.254.0.0/15',
    '100.64.0.0/9',
    '224.0.0.0/3',
    '255.255.255.255/31',
    'fc00::/6',
    'fe80::/9',
    'ff00::/7',
    '::1/0',
    '::1/127',
    '192.0.2.1/32',
    '::ffff:192.168.1.1/128',
    '10.0.0.1/',
    '1.2.3.4/33',
    'fe80::/129',
    '1.2.3.999',
    '010.0.0.1',
    'fe80:::1',
    'fe80::%en9'
  ])('does not allow broader, public or invalid ranges %s', (value) =>
    expect(isLocalDestination(value)).toBe(false)
  )
  it('matches only exact proxy host exclusions, including IPv6 spelling variations', () => {
    expect(sameHost('203.0.113.8/32', '203.0.113.8')).toBe(true)
    expect(sameHost('203.0.113.8/24', '203.0.113.8')).toBe(false)
    expect(sameHost('2001:db8::1/128', '[2001:0db8:0:0:0:0:0:1]')).toBe(true)
    expect(ipRange('0.0.0.0/0')?.end).toBe(4294967295n)
  })
})
describe('public UDP rule ordering', () => {
  it.each([
    'IP-CIDR,224.0.0.0/4,DIRECT',
    'IP-CIDR,255.255.255.255/32,DIRECT',
    'IP-CIDR,169.254.0.0/16,DIRECT',
    'IP-CIDR,100.64.0.0/10,DIRECT',
    'IP-CIDR6,ff00::/8,DIRECT',
    'IP-CIDR6,fe80::/10,DIRECT',
    'AND,((NETWORK,tcp),(GEOIP,cn)),DIRECT',
    'AND,((NETWORK,udp),(IP-CIDR,192.168.0.0/16)),DIRECT',
    'OR,((IP-CIDR,127.0.0.0/8),(IP-CIDR6,ff00::/8)),DIRECT',
    'NOT,((NETWORK,udp)),DIRECT'
  ])('accepts bounded local or TCP-only exception %s', (rule) => expect(risk(rule)).toEqual([]))
  it.each([
    'IP-CIDR,224.0.0.0/3,DIRECT',
    'IP-CIDR6,ff00::/7,DIRECT',
    'SRC-IP-CIDR,192.168.0.0/16,DIRECT',
    'AND,((NETWORK,udp),(GEOIP,cn)),DIRECT',
    'OR,((NETWORK,tcp),(DOMAIN,public.example)),DIRECT',
    'NOT,((IP-CIDR,192.168.0.0/16)),DIRECT'
  ])('retains public direct risk for %s', (rule) =>
    expect(risk(rule).some((f) => f.id === 'udpRuleOrdering' && f.detail === rule)).toBe(true)
  )
  it('keeps unknown compound and rule-set matching pending', () => {
    for (const rule of [
      'AND,((NETWORK,udp),(RULE-SET,opaque)),Proxy',
      'RULE-SET,opaque,Proxy',
      'SUB-RULE,(NETWORK,udp),opaque'
    ])
      expect(risk(rule).some((f) => f.id === 'udpComplexRules')).toBe(true)
  })
  it('does not warn about opaque conditions restricted to TCP or local destinations', () => {
    expect(risk('AND,((NETWORK,tcp),(RULE-SET,opaque)),DIRECT')).toEqual([])
    expect(risk('AND,((IP-CIDR,10.0.0.0/8),(RULE-SET,opaque)),DIRECT')).toEqual([])
  })
  it('detects DIRECT in nested groups and explicit empty fallbacks', () => {
    const config = profile()
    config['proxy-groups'] = [
      { name: 'Proxy', type: 'select', proxies: ['Node'], 'empty-fallback': 'DIRECT' }
    ] as unknown as []
    expect(auditPrivacyConfig(config, 'win32').some((f) => f.id === 'udpGroupSelection')).toBe(true)
  })
})
describe('route exclusion purposes and recorded origins', () => {
  it('distinguishes nodes, local ranges, public ranges and unknown sets without changing configuration', () => {
    const config = profile()
    config.tun = {
      'route-exclude-address': ['203.0.113.8/32', '192.168.0.0/16', '203.0.113.0/24', 'invalid'],
      'route-exclude-address-set': ['opaque']
    }
    const before = structuredClone(config)
    const findings = auditPrivacyConfig(config, 'darwin').filter((f) => f.id.startsWith('route'))
    expect(findings.map((f) => [f.id, f.level])).toEqual([
      ['routeProxyEndpoint', 'info'],
      ['routeLocalExclusion', 'info'],
      ['routePublicExclusion', 'warning'],
      ['routeUnknownExclusion', 'warning'],
      ['routeScopeLimit', 'warning']
    ])
    expect(findings.every((f) => f.origin?.source === 'runtime')).toBe(true)
    expect(config).toEqual(before)
  })
  it('tracks observed profile, override, global and automatic additions without stale removed addresses', () => {
    const config = profile()
    config.tun = { 'route-exclude-address': ['10.0.0.0/8'] }
    let origins = traceTunRoutes(config, [], { source: 'profile', name: 'Main' })
    config.tun['route-exclude-address'] = [
      ...(config.tun['route-exclude-address'] ?? []),
      '192.0.2.8/32'
    ]
    origins = traceTunRoutes(config, origins, { source: 'override', name: 'Custom' })
    expect(origins.map((o) => o.source)).toEqual(['profile', 'override'])
    origins = traceTunRoutes(config, origins, { source: 'globalTun' }, ['route-exclude-address'])
    config.tun['route-exclude-address'] = [
      ...(config.tun['route-exclude-address'] ?? []),
      '203.0.113.8/32'
    ]
    origins = traceTunRoutes(config, origins, { source: 'automatic' })
    expect(origins.map((o) => o.source)).toEqual(['globalTun', 'globalTun', 'automatic'])
    config.tun['route-exclude-address'] = ['203.0.113.8/32']
    origins = traceTunRoutes(config, origins, { source: 'override' })
    expect(origins).toHaveLength(1)
    expect(
      auditPrivacyConfig(config, 'darwin', undefined, origins).find(
        (f) => f.id === 'routeProxyEndpoint'
      )?.origin?.source
    ).toBe('automatic')
  })
})

describe('unknown and recursive fallback outlets', () => {
  it.each(['Missing', 'Cycle', 'Provider'])(
    'does not confirm an unknown %s fallback as proxy-only',
    (fallback) => {
      const config = profile()
      config['proxy-groups'] = [
        { name: 'Proxy', type: 'select', proxies: ['Node'], 'empty-fallback': fallback },
        { name: 'Cycle', type: 'select', proxies: ['Proxy'] },
        { name: 'Provider', type: 'select', use: ['opaque'] }
      ] as unknown as []
      config.dns = { enable: true, nameserver: ['https://1.1.1.1/dns-query#Proxy'] }
      const findings = auditPrivacyConfig(config, 'win32')
      expect(findings.find((f) => f.id === 'dnsProxyOutbound')?.level).toBe('warning')
      expect(findings.find((f) => f.id === 'udpRouting')?.level).toBe('warning')
    }
  )
  it('does not recognize a synthetic direct outbound as a real proxy endpoint', () => {
    const config = profile()
    config.proxies = [{ name: 'NotProxy', type: 'direct', server: '203.0.113.8' }] as unknown as []
    config.tun = { 'route-exclude-address': ['203.0.113.8/32'] }
    expect(
      auditPrivacyConfig(config, 'win32').find((f) => f.id === 'routePublicExclusion')?.level
    ).toBe('warning')
  })
})

describe('compound rules in profile editors', () => {
  it('keeps nested conditions and the selected proxy as separate fields without changing the rule', () => {
    for (const rule of [
      'AND,((NETWORK,tcp),(OR,((DOMAIN,a.example),(DOMAIN,b.example)))),Overseas',
      '12,AND,((NETWORK,tcp),(GEOIP,CN)),DIRECT,no-resolve',
      'MATCH,Overseas'
    ]) {
      const fields = splitRuleFields(rule)
      expect(fields.join(',')).toBe(rule)
      const typeOffset = rule.startsWith('12,') ? 1 : 0
      if (fields[typeOffset] !== 'MATCH') expect(fields[typeOffset + 1]).toMatch(/^\(/)
    }
  })
})
