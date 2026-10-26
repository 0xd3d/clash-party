/** Read-only routing evidence; never changes a profile or resolves a hostname. */
export const TUN_SCOPE_KEYS = [
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
export type TunRouteOrigin = {
  key: string
  value: string
  source: 'profile' | 'override' | 'globalTun' | 'automatic' | 'simple' | 'runtime'
  name?: string
}

export function traceTunRoutes(
  profile: Partial<IMihomoConfig>,
  previous: TunRouteOrigin[],
  origin: Pick<TunRouteOrigin, 'source' | 'name'>,
  replacedKeys: string[] = []
): TunRouteOrigin[] {
  const lookup = new Map(previous.map((entry) => [entry.key + '\0' + entry.value, entry]))
  const replaced = new Set(replacedKeys)
  return TUN_SCOPE_KEYS.flatMap((key) => {
    const values = profile.tun?.[key]
    if (!Array.isArray(values)) return []
    return values.map((value) => {
      const old = lookup.get(key + '\0' + String(value))
      return old && !replaced.has(key) ? old : { key, value: String(value), ...origin }
    })
  })
}

type IPRange = { family: 4 | 6; start: bigint; end: bigint; prefix: number }
function ipv4(value: string): bigint | null {
  const parts = value.split('.')
  if (parts.length !== 4 || parts.some((p) => !/^(0|[1-9]\d{0,2})$/.test(p) || +p > 255))
    return null
  return parts.reduce((result, part) => (result << 8n) | BigInt(part), 0n)
}
function ipv6(value: string): bigint | null {
  if (value.includes('.')) {
    const index = value.lastIndexOf(':')
    const tail = ipv4(value.slice(index + 1))
    if (tail === null) return null
    value =
      value.slice(0, index + 1) + (tail >> 16n).toString(16) + ':' + (tail & 65535n).toString(16)
  }
  const halves = value.split('::')
  if (halves.length > 2) return null
  const left = halves[0] ? halves[0].split(':') : []
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : []
  if ([...left, ...right].some((p) => !/^[\da-f]{1,4}$/i.test(p))) return null
  const count = left.length + right.length
  if (halves.length === 1 ? count !== 8 : count >= 8) return null
  const parts =
    halves.length === 1 ? left : [...left, ...Array<string>(8 - count).fill('0'), ...right]
  return parts.reduce((result, part) => (result << 16n) | BigInt('0x' + part), 0n)
}
export function ipRange(value: string): IPRange | null {
  const fields = value.trim().toLowerCase().split('/')
  if (fields.length > 2) return null
  const family = fields[0].includes(':') ? 6 : 4
  const bits = family === 6 ? 128 : 32
  const number = family === 6 ? ipv6(fields[0]) : ipv4(fields[0])
  if (number === null || (fields[1] !== undefined && !/^\d+$/.test(fields[1]))) return null
  const prefix = fields[1] === undefined ? bits : Number(fields[1])
  if (prefix < 0 || prefix > bits) return null
  const size = 1n << BigInt(bits - prefix)
  const start = (number / size) * size
  return { family, prefix, start, end: start + size - 1n }
}
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
const localRanges = [...LOCAL_NETWORKS, '::/128'].flatMap((value) => {
  const range = ipRange(value)
  return range ? [range] : []
})

export function isLocalDestination(value: string): boolean {
  const range = ipRange(value)
  return (
    !!range &&
    localRanges.some(
      (local) =>
        local.family === range.family && range.start >= local.start && range.end <= local.end
    )
  )
}
export function sameHost(a: string, b: string): boolean {
  const left = ipRange(a),
    right = ipRange(b.replace(/^\[|\]$/g, ''))
  return (
    !!left &&
    !!right &&
    left.family === right.family &&
    left.start === left.end &&
    right.start === right.end &&
    left.start === right.start
  )
}

export function splitRuleFields(value: string): string[] {
  const fields: string[] = []
  let depth = 0,
    start = 0
  for (let i = 0; i < value.length; i++) {
    if (value[i] === '(') depth++
    if (value[i] === ')') depth--
    if (value[i] === ',' && depth === 0) {
      fields.push(value.slice(start, i).trim())
      start = i + 1
    }
  }
  fields.push(value.slice(start).trim())
  return fields
}
export type AuditRule = { type: string; payload: string; target: string; raw: string }
export function parseAuditRule(raw: string): AuditRule {
  const fields = splitRuleFields(raw)
  if (fields.at(-1)?.toLowerCase() === 'no-resolve') fields.pop()
  return {
    type: fields[0]?.toUpperCase() ?? '',
    payload: fields.length > 2 ? fields[1] : '',
    target: fields.at(-1) ?? '',
    raw
  }
}
function unwrapped(value: string): string {
  if (value[0] !== '(' || value.at(-1) !== ')') return value
  let depth = 0
  for (let i = 0; i < value.length - 1; i++) {
    if (value[i] === '(') depth++
    if (value[i] === ')') depth--
    if (depth === 0) return value
  }
  return value.slice(1, -1)
}
/** Whether a condition could match a public UDP destination. Unknown stays visible. */
export function publicUDPMatch(
  type: string,
  payload: string,
  depth = 0
): 'excluded' | 'possible' | 'unknown' {
  if (depth > 16) return 'unknown'
  type = type.toUpperCase()
  if (type === 'NETWORK')
    return payload.toLowerCase() === 'tcp'
      ? 'excluded'
      : payload.toLowerCase() === 'udp'
        ? 'possible'
        : 'unknown'
  if (['IP-CIDR', 'IP-CIDR6'].includes(type))
    return isLocalDestination(payload) ? 'excluded' : ipRange(payload) ? 'possible' : 'unknown'
  if (type === 'DOMAIN' || type === 'DOMAIN-SUFFIX')
    return ['localhost', 'lan', 'local'].includes(payload.toLowerCase()) ? 'excluded' : 'possible'
  if (type === 'GEOIP' && payload.toLowerCase() === 'private') return 'excluded'
  if (type === 'AND' || type === 'OR' || type === 'NOT') {
    const body = unwrapped(payload)
    const children = type === 'NOT' ? [body] : splitRuleFields(body)
    if (!children.length) return 'unknown'
    const conditions = children.map((child) => splitRuleFields(unwrapped(child)))
    const matches = conditions.map(([kind, value = '']) => publicUDPMatch(kind, value, depth + 1))
    if (type === 'NOT') {
      if (conditions.length === 1 && conditions[0][0]?.toUpperCase() === 'NETWORK') {
        if (conditions[0][1]?.toLowerCase() === 'udp') return 'excluded'
        if (conditions[0][1]?.toLowerCase() === 'tcp') return 'possible'
      }
      return 'unknown'
    }
    if (type === 'AND')
      return matches.includes('excluded')
        ? 'excluded'
        : matches.includes('unknown')
          ? 'unknown'
          : 'possible'
    return matches.includes('possible')
      ? 'possible'
      : matches.every((match) => match === 'excluded')
        ? 'excluded'
        : 'unknown'
  }
  return ['RULE-SET', 'SUB-RULE'].includes(type) ? 'unknown' : 'possible'
}
