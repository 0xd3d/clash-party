export type PrivacyAuditFinding = {
  id: string
  level: 'pass' | 'warning' | 'error' | 'info'
  detail?: string
}

export type PrivacyProtectionReport = {
  platform: NodeJS.Platform
  source: 'applied' | 'unavailable'
  findings: PrivacyAuditFinding[]
}

type NamedOutbound = {
  name: string
  type?: string
  proxies?: string[]
  dynamicMembers: boolean
  isGroup: boolean
}
type Rule = { type: string; payload: string; target: string }

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
        isGroup
      }
    ]
  })
}

// Logical rules contain commas inside parentheses. Only split the outer rule fields.
function parseRule(value: string): Rule {
  const fields: string[] = []
  let depth = 0
  let start = 0
  for (let index = 0; index < value.length; index++) {
    if (value[index] === '(') depth++
    if (value[index] === ')') depth--
    if (value[index] === ',' && depth === 0) {
      fields.push(value.slice(start, index).trim())
      start = index + 1
    }
  }
  fields.push(value.slice(start).trim())
  if (fields.at(-1)?.toLowerCase() === 'no-resolve') fields.pop()
  return {
    type: fields[0]?.toUpperCase() ?? '',
    payload: fields.length > 2 ? fields[1] : '',
    target: fields.at(-1) ?? ''
  }
}

function isLocalIPv4CIDR(value: string): boolean {
  const [address, prefixText] = value.split('/')
  const parts = address.split('.').map(Number)
  const prefix = prefixText === undefined ? 32 : Number(prefixText)
  if (
    parts.length !== 4 ||
    parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255) ||
    !Number.isInteger(prefix) ||
    prefix < 0 ||
    prefix > 32
  ) {
    return false
  }
  const [a, b] = parts
  return (
    (a === 10 && prefix >= 8) ||
    (a === 127 && prefix >= 8) ||
    (a === 172 && b >= 16 && b <= 31 && prefix >= 12) ||
    (a === 192 && b === 168 && prefix >= 16) ||
    (a === 169 && b === 254 && prefix >= 16)
  )
}

function isLocalRule(rule: Rule): boolean {
  if (rule.type === 'DOMAIN' || rule.type === 'DOMAIN-SUFFIX') {
    return ['localhost', 'lan', 'local'].includes(rule.payload.toLowerCase())
  }
  if (rule.type === 'IP-CIDR') return isLocalIPv4CIDR(rule.payload)
  if (rule.type === 'IP-CIDR6') {
    const [address, prefixText] = rule.payload.toLowerCase().split('/')
    const prefix = prefixText === undefined ? 128 : Number(prefixText)
    return (
      (address === '::1' && prefix === 128) ||
      (/^f[cd][0-9a-f]{2}:/.test(address) && prefix >= 7 && prefix <= 128) ||
      (/^fe[89ab][0-9a-f]:/.test(address) && prefix >= 10 && prefix <= 128)
    )
  }
  return rule.type === 'GEOIP' && rule.payload.toLowerCase() === 'private'
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
  return (
    outbounds
      .find((group) => group.name === target)
      ?.proxies?.some((member) => maySelectDirect(member, outbounds, seen)) ?? false
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
  const unknown = outbound.proxies.some((member) => hasUnknownMembers(member, outbounds, seen))
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
  appConfig?: Pick<IAppConfig, 'autoSetDNS'>
): PrivacyAuditFinding[] {
  const findings: PrivacyAuditFinding[] = [{ id: 'scope', level: 'info' }]
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
  const exclusions = [
    'route-address',
    'route-address-set',
    'route-exclude-address',
    'route-exclude-address-set',
    'include-interface',
    'exclude-interface',
    'include-uid',
    'include-uid-range',
    'exclude-uid',
    'exclude-uid-range',
    'include-package',
    'exclude-package'
  ] as const
  if (exclusions.some((key) => (tun?.[key]?.length ?? 0) > 0)) add('routeExclusions', 'warning')

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

  const rules = strings(profile.rules).map(parseRule)
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
      if (maySelectDirect(blanket.target, outbounds)) add('udpGroupSelection', 'warning')
    }
    const earlierRules = rules.slice(0, blanketIndex)
    if (
      earlierRules.some(
        (rule) =>
          maySelectDirect(rule.target, outbounds) &&
          !(rule.type === 'NETWORK' && rule.payload.toLowerCase() === 'tcp') &&
          !isLocalRule(rule)
      )
    ) {
      add('udpRuleOrdering', 'warning')
    }
    if (
      earlierRules.some((rule) => ['RULE-SET', 'SUB-RULE', 'AND', 'OR', 'NOT'].includes(rule.type))
    ) {
      add('udpComplexRules', 'warning')
    }
  }
  return findings
}
