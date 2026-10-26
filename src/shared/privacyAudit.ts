import {
  TUN_SCOPE_KEYS,
  isLocalDestination,
  ipRange,
  sameHost,
  parseAuditRule,
  publicUDPMatch,
  type TunRouteOrigin
} from './privacyRouting'
export type PrivacyAuditFinding = {
  id: string
  level: 'pass' | 'warning' | 'error' | 'info'
  detail?: string
  origin?: TunRouteOrigin
  reason?:
    | 'inactive'
    | 'previousConnection'
    | 'tunnelUnavailable'
    | 'trafficUnconfirmed'
    | 'statusUnavailable'
}

export type PrivacyProtectionReport = {
  platform: NodeJS.Platform
  source: 'applied' | 'unavailable'
  findings: PrivacyAuditFinding[]
  diagnostics?: { id: string; value: string }[]
}

type NamedOutbound = {
  name: string
  type?: string
  proxies?: string[]
  dynamicMembers: boolean
  isGroup: boolean
  emptyFallback?: string
}

function strings(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === 'string')
    : []
}

function namedOutbounds(value: unknown, isGroup = false): NamedOutbound[] {
  if (!Array.isArray(value)) return []
  return value.flatMap((item: unknown) => {
    if (!item || typeof item !== 'object' || !('name' in item) || typeof item.name !== 'string') {
      return []
    }
    return [
      {
        name: item.name,
        type: 'type' in item && typeof item.type === 'string' ? item.type : undefined,
        proxies: 'proxies' in item ? strings(item.proxies) : undefined,
        dynamicMembers:
          ('use' in item && strings(item.use).length > 0) ||
          ('include-all' in item && item['include-all'] === true) ||
          ('include-all-providers' in item && item['include-all-providers'] === true) ||
          ('include-all-proxies' in item && item['include-all-proxies'] === true),
        isGroup,
        emptyFallback:
          'empty-fallback' in item && typeof item['empty-fallback'] === 'string'
            ? item['empty-fallback']
            : undefined
      }
    ]
  })
}

function isReject(target: string): boolean {
  return ['REJECT', 'REJECT-DROP', 'REJECT-TINYGIF'].includes(target.toUpperCase())
}

function isDirect(target: string, outbounds: NamedOutbound[]): boolean {
  return (
    target.toUpperCase() === 'DIRECT' ||
    outbounds.find((outbound) => outbound.name === target)?.type?.toLowerCase() === 'direct'
  )
}

function maySelectDirect(
  target: string,
  outbounds: NamedOutbound[],
  seen = new Set<string>()
): boolean {
  if (isDirect(target, outbounds) || ['GLOBAL', 'COMPATIBLE'].includes(target.toUpperCase()))
    return true
  if (seen.has(target)) return false
  seen.add(target)
  const group = outbounds.find((item) => item.name === target)
  return [...(group?.proxies ?? []), ...(group?.emptyFallback ? [group.emptyFallback] : [])].some(
    (member) => maySelectDirect(member, outbounds, seen)
  )
}

function hasUnknownMembers(
  target: string,
  outbounds: NamedOutbound[],
  seen = new Set<string>()
): boolean {
  if (isReject(target) || target.toUpperCase() === 'DIRECT') return false
  const outbound = outbounds.find((item) => item.name === target)
  if (!outbound || seen.has(target) || outbound.dynamicMembers) return true
  if (!outbound.isGroup) return false
  if (!outbound.proxies?.length) return true
  seen.add(target)
  const unknown = [
    ...outbound.proxies,
    ...(outbound.emptyFallback ? [outbound.emptyFallback] : [])
  ].some((member) => hasUnknownMembers(member, outbounds, seen))
  seen.delete(target)
  return unknown
}

function dnsOutbound(server: string): string | undefined {
  const fragment = server.split('#')[1]
  if (!fragment) return undefined
  const target = fragment.split('&').find((option) => {
    return !option.includes('=') && !['h3', 'skip-cert-verify'].includes(option.toLowerCase())
  })
  if (!target) return undefined
  try {
    return decodeURIComponent(target)
  } catch {
    return target
  }
}

/** Read-only configuration hints. No sockets, OS changes, or network leak measurements. */
export function auditPrivacyConfig(
  profile: Partial<IMihomoConfig>,
  platform: NodeJS.Platform,
  appConfig?: Pick<IAppConfig, 'autoSetDNS'>,
  origins: TunRouteOrigin[] = []
): PrivacyAuditFinding[] {
  const findings: PrivacyAuditFinding[] = []
  const add = (id: string, level: PrivacyAuditFinding['level'], detail?: string): void => {
    findings.push({ id, level, ...(detail === undefined ? {} : { detail }) })
  }
  const tun = profile.tun
  add('tunEnabled', tun?.enable === true ? 'pass' : 'error')
  add('autoRoute', tun?.['auto-route'] === true ? 'pass' : 'warning')
  add(
    'strictRoute',
    tun?.['strict-route'] === true ? (platform === 'darwin' ? 'info' : 'pass') : 'warning'
  )

  const hijack = strings(tun?.['dns-hijack']).map((entry) => entry.trim().toLowerCase())
  add(
    'dnsHijackUdp',
    hijack.some((entry) => /^(udp:\/\/)?(any|0\.0\.0\.0):53$/.test(entry)) ? 'pass' : 'warning'
  )
  add(
    'dnsHijackTcp',
    hijack.some((entry) => /^tcp:\/\/(any|0\.0\.0\.0):53$/.test(entry)) ? 'pass' : 'warning'
  )
  if (platform === 'win32') {
    add('windowsRouting', 'info')
    const mode = tun?.['dns-mode'] || (tun?.['auto-route'] ? 'hijack' : 'disabled')
    add(
      'windowsDnsMode',
      mode === 'disabled'
        ? 'error'
        : mode === 'hijack' && tun?.['auto-route'] === true && tun?.['strict-route'] === true
          ? 'pass'
          : 'warning'
    )
  }
  if (platform === 'darwin') {
    add('macSystemDNS', appConfig?.autoSetDNS === true ? 'info' : 'warning')
  }
  for (const key of TUN_SCOPE_KEYS) {
    const values = tun?.[key]
    if (!Array.isArray(values)) continue
    for (const value of values) {
      const address = String(value)
      const origin = origins.find((entry) => entry.key === key && entry.value === address) ?? {
        key,
        value: address,
        source: 'runtime' as const
      }
      let id = 'routeScopeLimit'
      let level: PrivacyAuditFinding['level'] = 'warning'
      if (key === 'route-exclude-address') {
        const node = (
          profile.proxies as unknown as { server?: unknown; type?: string }[] | undefined
        )?.some(
          (proxy) =>
            !!proxy.type &&
            !/^(direct|reject|pass|compatible)$/i.test(proxy.type) &&
            typeof proxy.server === 'string' &&
            sameHost(address, proxy.server)
        )
        if (node) {
          id = 'routeProxyEndpoint'
          level = 'info'
        } else if (isLocalDestination(address)) {
          id = 'routeLocalExclusion'
          level = 'info'
        } else id = ipRange(address) ? 'routePublicExclusion' : 'routeUnknownExclusion'
      } else if (
        key === 'route-address' &&
        strings(tun?.['route-address']).includes('0.0.0.0/0') &&
        strings(tun?.['route-address']).includes('::/0')
      ) {
        id = 'routeCaptureRange'
        level = 'info'
      }
      findings.push({ id, level, detail: address, origin })
    }
  }

  const dns = profile.dns
  add('dnsEnabled', dns?.enable === true ? 'pass' : 'error')
  const groups = namedOutbounds(profile['proxy-groups'], true)
  const outbounds = [...namedOutbounds(profile.proxies), ...groups]
  const upstreams = [...strings(dns?.nameserver), ...strings(dns?.fallback)]
  if (upstreams.length === 0) {
    add('dnsUpstreamsMissing', 'warning')
  } else {
    const encrypted = upstreams.filter((server) => /^(https|tls|quic):\/\//i.test(server.trim()))
    add('dnsEncrypted', encrypted.length === upstreams.length ? 'pass' : 'warning')
    const explicitProxyCount = upstreams.filter((server) => {
      const outbound = dnsOutbound(server)
      return (
        outbound &&
        !['DIRECT', 'RULES', 'GLOBAL'].includes(outbound.toUpperCase()) &&
        outbounds.some((item) => item.name === outbound) &&
        !maySelectDirect(outbound, outbounds) &&
        !hasUnknownMembers(outbound, outbounds)
      )
    }).length
    add('dnsProxyOutbound', explicitProxyCount === upstreams.length ? 'pass' : 'warning')
  }
  if (dns?.['respect-rules'] || upstreams.some((server) => dnsOutbound(server) === 'RULES')) {
    add('dnsRuleRouting', 'info')
    if (strings(dns?.['proxy-server-nameserver']).length === 0) add('dnsBootstrap', 'warning')
  }
  const auxiliaryUpstreams = [
    ...strings(dns?.['default-nameserver']),
    ...strings(dns?.['proxy-server-nameserver']),
    ...strings(dns?.['direct-nameserver'])
  ]
  if (auxiliaryUpstreams.some((server) => !/^(https|tls|quic):\/\//i.test(server.trim()))) {
    add('dnsAuxiliary', 'warning')
  }
  const policyCount = Object.keys(dns?.['nameserver-policy'] ?? {}).length
  if (policyCount > 0) add('dnsPolicy', 'info', String(policyCount))
  add('ipv6Config', 'info', `${profile.ipv6 === true} / ${dns?.ipv6 === true}`)
  add('lanAccess', profile['allow-lan'] === true ? 'warning' : 'pass')

  const rules = strings(profile.rules).map(parseAuditRule)
  const blanketIndex = rules.findIndex(
    (rule) =>
      (rule.type === 'NETWORK' && rule.payload.toLowerCase() === 'udp') || rule.type === 'MATCH'
  )
  if (profile.mode === 'direct') {
    add('udpDirectMode', 'error')
  } else if (profile.mode === 'global') {
    add('udpGlobalMode', 'warning')
  } else if (blanketIndex === -1) {
    add('udpRouting', 'warning')
  } else {
    const blanket = rules[blanketIndex]
    if (isDirect(blanket.target, outbounds)) {
      add('udpDirect', 'error')
    } else {
      add(
        'udpRouting',
        isReject(blanket.target) ||
          (outbounds.some((item) => item.name === blanket.target) &&
            !hasUnknownMembers(blanket.target, outbounds))
          ? 'pass'
          : 'warning'
      )
      if (!isReject(blanket.target)) add('udpProxySupport', 'info')
      if (maySelectDirect(blanket.target, outbounds))
        add('udpGroupSelection', 'warning', blanket.raw)
    }
    for (const rule of rules.slice(0, blanketIndex)) {
      const scope = publicUDPMatch(rule.type, rule.payload)
      if (scope === 'excluded') continue
      if (maySelectDirect(rule.target, outbounds)) add('udpRuleOrdering', 'warning', rule.raw)
      if (scope === 'unknown') add('udpComplexRules', 'warning', rule.raw)
      else if (
        !isReject(rule.target) &&
        !maySelectDirect(rule.target, outbounds) &&
        hasUnknownMembers(rule.target, outbounds)
      )
        add('udpUnknownTarget', 'warning', rule.raw)
    }
  }

  return findings
}

export function requiredNativeChecks(platform: NodeJS.Platform): string[] {
  return platform === 'darwin' ? ['macDNSGuard', 'networkGuard'] : ['networkGuard']
}
export function nativeProtectionConfirmed(report: PrivacyProtectionReport): boolean {
  return (
    report.source === 'applied' &&
    requiredNativeChecks(report.platform).every((id) =>
      report.findings.some((finding) => finding.id === id && finding.level === 'pass')
    )
  )
}

export function nativeGuardReason(
  guard: { active: boolean; corePid?: number | null; coreAlive?: boolean; trafficLease?: boolean },
  expectedPid: number
): PrivacyAuditFinding['reason'] {
  if (!guard.active) return 'inactive'
  if (guard.corePid !== expectedPid) return 'previousConnection'
  if (guard.coreAlive === false) return 'tunnelUnavailable'
  if (guard.trafficLease === false) return 'trafficUnconfirmed'
  return undefined
}
