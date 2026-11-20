import { isIP } from 'net'

/** Pure boot-leak egress allowlist / arm decision logic (macOS daemon + unit tests). */
export type BootLeakPolicySnapshot = {
  disabled: boolean
  mixedPort: number
  dnsListenPort: number
  proxyServers: string[]
}

const PRIVATE_CIDRS_V4 = [
  '127.0.0.0/8',
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '169.254.0.0/16',
  '224.0.0.0/24'
] as const

const PRIVATE_CIDRS_V6 = ['::1/128', 'fc00::/7', 'fe80::/10', 'ff02::/16'] as const

export function shouldArmBootLeakGuard(snapshot: {
  disabled: boolean
  coreListening: boolean
}): boolean {
  if (snapshot.disabled) return false
  return !snapshot.coreListening
}

export function normalizeBootLeakProxyServers(values: unknown): string[] {
  if (!Array.isArray(values)) return []
  const result = new Set<string>()
  for (const value of values) {
    if (typeof value !== 'string' && typeof value !== 'number') continue
    const host = String(value)
      .trim()
      .replace(/^\[(.*)\]$/, '$1')
      .toLowerCase()
    if (isIP(host)) result.add(host)
  }
  return [...result].sort()
}

export function collectLiteralProxyServerIPs(proxies: unknown): string[] {
  if (!Array.isArray(proxies)) return []
  const servers: string[] = []
  for (const proxy of proxies) {
    if (!proxy || typeof proxy !== 'object') continue
    const server = (proxy as Record<string, unknown>).server
    if (typeof server !== 'string' && typeof server !== 'number') continue
    servers.push(String(server))
  }
  return normalizeBootLeakProxyServers(servers)
}

/** PF rule lines for self-tests and daemon parity (no live PF). */
export function bootLeakEgressRuleLines(policy: BootLeakPolicySnapshot): string[] {
  const lines: string[] = [
    'pass quick on lo0 all no state',
    ...[...PRIVATE_CIDRS_V4, ...PRIVATE_CIDRS_V6].map(
      (cidr) => `pass out quick from any to ${cidr} no state`
    ),
    ...[...PRIVATE_CIDRS_V4, ...PRIVATE_CIDRS_V6].map(
      (cidr) => `pass in quick from ${cidr} to any no state`
    ),
    'pass out quick inet proto udp from any port 68 to any port 67 no state',
    'pass in quick inet proto udp from any port 67 to any port 68 no state',
    'pass out quick inet6 proto udp from any port 546 to any port 547 no state',
    'pass in quick inet6 proto udp from any port 547 to any port 546 no state',
    'pass quick inet6 proto ipv6-icmp from any to { fe80::/10, ff02::/16 } no state',
    'pass in quick inet proto icmp icmp-type unreach no state',
    'pass in quick inet6 proto ipv6-icmp icmp6-type { toobig, unreach, paramprob } no state'
  ]
  for (const host of policy.proxyServers) {
    const v = isIP(host)
    if (!v) continue
    lines.push(`pass out quick from any to ${v === 4 ? host : `{ ${host} }`} no state`)
  }
  lines.push('block drop quick all label "ClashPartyBootLeak"')
  return lines
}

export function parseBootLeakPolicyFile(raw: string): BootLeakPolicySnapshot {
  const value: unknown = JSON.parse(raw)
  if (!value || typeof value !== 'object') throw new Error('Invalid boot leak policy')
  const record = value as Record<string, unknown>
  const mixedPort = Number(record.mixedPort)
  const dnsListenPort = Number(record.dnsListenPort)
  if (!Number.isInteger(mixedPort) || mixedPort <= 0 || mixedPort > 65535) {
    throw new Error('Invalid mixed port in boot leak policy')
  }
  if (!Number.isInteger(dnsListenPort) || dnsListenPort <= 0 || dnsListenPort > 65535) {
    throw new Error('Invalid DNS listen port in boot leak policy')
  }
  return {
    disabled: record.disabled === true,
    mixedPort,
    dnsListenPort,
    proxyServers: normalizeBootLeakProxyServers(record.proxyServers)
  }
}

export function coreListenAddresses(
  policy: Pick<BootLeakPolicySnapshot, 'mixedPort' | 'dnsListenPort'>
): string[] {
  return [
    `127.0.0.1:${policy.mixedPort}`,
    `127.0.0.1:${policy.dnsListenPort}`,
    '[::1]:' + policy.mixedPort,
    '[::1]:' + policy.dnsListenPort
  ]
}
