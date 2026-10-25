import { isIP } from 'node:net'

export const QQ_MUSIC_DNS_KEYS = new Set(['aqqmusic.tc.qq.com', '+.stream.qqmusic.qq.com'])
export const QQ_MUSIC_DNS_EXCEPTION = 'https://doh.pub/dns-query#DIRECT'
export const LOCAL_NETWORKS = [
  '127.0.0.0/8',
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '169.254.0.0/16',
  '100.64.0.0/10',
  '224.0.0.0/4',
  '255.255.255.255/32',
  '::1/128',
  'fc00::/7',
  'fe80::/10',
  'ff00::/8'
]
export const ENCRYPTED_DNS_DOMAINS = [
  'cloudflare-dns.com',
  'one.one.one.one',
  'dns.google',
  'dns.quad9.net',
  'doh.pub',
  'dot.pub',
  'dns.alidns.com',
  'dns.nextdns.io',
  'dns.adguard-dns.com',
  'dns.adguard.com',
  'dns.controld.com',
  'dns.mullvad.net',
  'dns.opendns.com'
]
export const ENCRYPTED_DNS_IPS = [
  '1.1.1.1',
  '1.0.0.1',
  '8.8.8.8',
  '8.8.4.4',
  '9.9.9.9',
  '149.112.112.112',
  '223.5.5.5',
  '223.6.6.6',
  '1.12.12.12',
  '120.53.53.53',
  '94.140.14.14',
  '94.140.15.15',
  '208.67.222.222',
  '208.67.220.220',
  '76.76.2.0',
  '76.76.10.0',
  '2606:4700:4700::1111',
  '2606:4700:4700::1001',
  '2001:4860:4860::8888',
  '2001:4860:4860::8844',
  '2620:fe::fe',
  '2620:fe::9'
]

type Settings = Pick<
  IAppConfig,
  'networkProtection' | 'networkProtectionProxyGroup' | 'networkProtectionPublicUDP' | 'autoSetDNS'
>
type Entry = {
  name?: string
  type?: string
  proxies?: string[]
  use?: string[]
  'include-all'?: boolean
  'include-all-proxies'?: boolean
  'include-all-providers'?: boolean
}

/** A protected target cannot include a DIRECT fallback, opaque providers or cycles. */
export function protectionTarget(profile: Partial<IMihomoConfig>, selected = ''): string {
  const rules = (profile.rules ?? []) as string[]
  const name =
    selected.trim() ||
    [...rules]
      .reverse()
      .find((r) => r.startsWith('MATCH,'))
      ?.split(',')[1]
      ?.trim()
  if (!name || /[,&#\r\n]/.test(name))
    throw new Error('Choose a proxy-only protection group or a MATCH proxy target')
  const groups = (profile['proxy-groups'] ?? []) as Entry[]
  const entries = [...(profile.proxies ?? []), ...groups] as Entry[]
  const verify = (target: string, ancestors: Set<string>): void => {
    if (
      ancestors.has(target) ||
      /^(GLOBAL|DNS|DIRECT|COMPATIBLE|PASS|REJECT(?:-DROP)?)$/i.test(target)
    )
      throw new Error('Protection target has a direct fallback, unsupported target or cycle')
    const matches = entries.filter((e) => e.name === target)
    if (matches.length !== 1)
      throw new Error('Protection target must resolve to one explicit proxy or group')
    const entry = matches[0]
    if (
      entry.use?.length ||
      entry['include-all'] ||
      entry['include-all-proxies'] ||
      entry['include-all-providers']
    )
      throw new Error('Opaque provider membership cannot establish a proxy-only protection target')
    if (groups.includes(entry)) {
      if (!Array.isArray(entry.proxies) || !entry.proxies.length)
        throw new Error('Empty or implicit protection group')
      for (const child of entry.proxies) verify(child, new Set([...ancestors, target]))
    } else if (!entry.type || /^(direct|reject|pass|compatible)$/i.test(entry.type)) {
      throw new Error('Protection requires a concrete proxy transport')
    }
  }
  verify(name, new Set())
  return name
}

function encryptedServer(value: string): { base: string; fragment: string[]; host: string } {
  if (!/^(https|tls|quic|h3):\/\//i.test(value))
    throw new Error('Protection requires encrypted DNS upstreams')
  const hash = value.indexOf('#')
  const base = hash < 0 ? value : value.slice(0, hash)
  let fragment: string
  try {
    fragment = hash < 0 ? '' : decodeURIComponent(value.slice(hash + 1))
  } catch {
    throw new Error('Invalid encrypted DNS fragment encoding')
  }
  let host: string
  try {
    host = new URL(base).hostname.replace(/^\[|\]$/g, '')
  } catch {
    throw new Error('Invalid encrypted DNS endpoint')
  }
  if (!host) throw new Error('Missing encrypted DNS endpoint')
  return { base, fragment: fragment.split('&').filter(Boolean), host }
}

function bindDNS(value: string, target: string): string {
  const parsed = encryptedServer(value)
  const options = parsed.fragment
    .filter((part) => part.includes('='))
    .map((part) => {
      const equals = part.indexOf('=')
      return `${encodeURIComponent(part.slice(0, equals))}=${encodeURIComponent(part.slice(equals + 1))}`
    })
  // Go URL parsing decodes Fragment before splitting '&'. Encode parameter values and
  // put the single proxy token last so an upstream cannot override the selected proxy.
  return `${parsed.base}#${[...options, encodeURIComponent(target)].join('&')}`
}

/** Node/bootstrap DNS is independent of the node it resolves: no recursive proxy dependency. */
function assertBootstrap(values: string[] | undefined): void {
  if (!values?.length) throw new Error('Provide independent IP-address encrypted bootstrap DNS')
  for (const value of values) {
    const server = encryptedServer(value)
    const adapters = server.fragment.filter((part) => !part.includes('='))
    if (!isIP(server.host) || adapters.length > 1 || adapters.some((name) => name !== 'DIRECT'))
      throw new Error(
        'Bootstrap DNS must be encrypted, use a literal IP, and be independent of the proxy'
      )
  }
}

/** Applied after overrides, in both standard and simple compilation paths. No stored profile edits. */
export function applyNetworkProtectionPolicy(profile: IMihomoConfig, settings: Settings): void {
  if (!settings.networkProtection) return
  if (process.platform === 'darwin' && settings.autoSetDNS === false)
    throw new Error('Enable local system DNS takeover before network protection')
  if (profile.tun?.enable !== true || profile.mode !== 'rule')
    throw new Error('Network protection requires an enabled TUN in rule mode')
  const target = protectionTarget(profile, settings.networkProtectionProxyGroup)
  const groups = (profile['proxy-groups'] ?? []) as Array<Entry & { 'empty-fallback'?: string }>
  const hardened = new Set<string>()
  const harden = (name: string): void => {
    if (hardened.has(name)) return
    hardened.add(name)
    const group = groups.find((entry) => entry.name === name)
    if (!group) return
    group['empty-fallback'] = 'REJECT'
    for (const member of group.proxies ?? []) harden(member)
  }
  harden(target)
  if (!profile.dns?.enable) throw new Error('Network protection requires the core DNS listener')
  const dns = structuredClone(profile.dns)
  assertBootstrap(dns['default-nameserver'])
  if (!dns['proxy-server-nameserver']?.length)
    dns['proxy-server-nameserver'] = [...(dns['default-nameserver'] ?? [])]
  assertBootstrap(dns['proxy-server-nameserver'])
  for (const key of ['nameserver', 'fallback', 'direct-nameserver'] as const) {
    if (dns[key]?.length) dns[key] = dns[key].map((s) => bindDNS(s, target))
  }
  if (!dns.nameserver?.length) throw new Error('Network protection requires encrypted business DNS')
  const policy: NonNullable<IMihomoDNSConfig['nameserver-policy']> = {}
  for (const [key, raw] of Object.entries(dns['nameserver-policy'] ?? {})) {
    const values = typeof raw === 'string' ? [raw] : raw
    policy[key] = values.map((server) =>
      QQ_MUSIC_DNS_KEYS.has(key) && server === QQ_MUSIC_DNS_EXCEPTION
        ? server
        : bindDNS(server, target)
    )
  }
  dns['nameserver-policy'] = policy
  const nodePolicy = (dns as unknown as Record<string, unknown>)['proxy-server-nameserver-policy']
  if (nodePolicy !== undefined) {
    if (!nodePolicy || typeof nodePolicy !== 'object' || Array.isArray(nodePolicy))
      throw new Error('Invalid node bootstrap DNS policy')
    for (const value of Object.values(nodePolicy))
      assertBootstrap(typeof value === 'string' ? [value] : (value as string[]))
  }
  const resolverHosts = new Set([...ENCRYPTED_DNS_DOMAINS, ...ENCRYPTED_DNS_IPS])
  for (const values of [
    dns.nameserver,
    dns.fallback,
    dns['direct-nameserver'],
    dns['proxy-server-nameserver'],
    dns['default-nameserver'],
    ...Object.values(policy)
  ]) {
    for (const value of typeof values === 'string' ? [values] : (values ?? []))
      resolverHosts.add(encryptedServer(value).host.toLowerCase())
  }
  dns['respect-rules'] = false // Every business upstream is explicitly bound; exceptions remain explicit.
  const prefix = [
    // A hardcoded router/LAN resolver must not bypass business DNS through DIRECT.
    ...[53, 853].map((port) => `DST-PORT,${port},${target}`),
    ...LOCAL_NETWORKS.map(
      (cidr) => `${cidr.includes(':') ? 'IP-CIDR6' : 'IP-CIDR'},${cidr},DIRECT,no-resolve`
    ),
    'DOMAIN-SUFFIX,local,DIRECT',
    'DOMAIN-SUFFIX,lan,DIRECT',
    ...[...resolverHosts]
      .filter((host) => !isIP(host))
      .map((domain) => `DOMAIN-SUFFIX,${domain},${target}`),
    ...[...resolverHosts]
      .filter((host) => isIP(host))
      .map(
        (ip) =>
          `${ip.includes(':') ? 'IP-CIDR6' : 'IP-CIDR'},${ip}/${ip.includes(':') ? 128 : 32},${target},no-resolve`
      ),
    ...[3478, 5349].map((port) => `DST-PORT,${port},${target}`),
    ...(settings.networkProtectionPublicUDP !== false ? [`NETWORK,UDP,${target}`] : [])
  ]
  const guardedPrefix = prefix.flatMap((rule) => {
    const fields = rule.split(',')
    const policyIndex = fields.length - (fields.at(-1) === 'no-resolve' ? 2 : 1)
    if (fields[policyIndex] !== target) return [rule]
    fields[policyIndex] = 'REJECT'
    return [rule, fields.join(',')]
  })
  profile.rules = [
    ...guardedPrefix,
    ...(profile.rules ?? []).filter((r) => !guardedPrefix.includes(r))
  ] as []
  profile.dns = dns
  profile.tun = {
    ...profile.tun,
    'auto-route': true,
    'auto-detect-interface': true,
    'strict-route': true,
    'dns-hijack': ['any:53', 'tcp://any:53']
  }
  delete (profile as unknown as Record<string, unknown>)['interface-name']
}
