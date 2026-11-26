import { execFile } from 'child_process'
import { readFile } from 'fs/promises'
import path from 'path'
import { promisify } from 'util'
import { parse } from '../utils/yaml'

const execFilePromise = promisify(execFile)

const PLACEHOLDER = '__IOS_PROXY__'
const SUPPORTED = new Set([
  'DOMAIN',
  'DOMAIN-SUFFIX',
  'DOMAIN-KEYWORD',
  'IP-CIDR',
  'IP-CIDR6',
  'GEOIP',
  'GEOSITE',
  'NETWORK',
  'DST-PORT',
  'MATCH'
])
const SKIPPED = new Set([
  'PROCESS-NAME',
  'PROCESS-PATH',
  'UID',
  'IN-TYPE',
  'IN-PORT',
  'AND',
  'OR',
  'NOT'
])
const PORT_SPEC = /^[0-9/,-]+$/
const LOGIC_RULES = new Set(['AND', 'OR', 'NOT'])
const MAX_RULES = 50_000
const MAX_PROVIDER_BYTES = 8 * 1024 * 1024
const PORTABLE_RULE_SET_COLLAPSE: Record<string, [string, string]> = {
  'cn-domain': ['GEOSITE', 'cn'],
  'cn-ip': ['GEOIP', 'CN'],
  'non-cn-domain': ['GEOSITE', 'geolocation-!cn']
}

function collapseRuleSet(providerName: string, target: string, flags: string[]): string | null {
  const mapping = PORTABLE_RULE_SET_COLLAPSE[providerName]
  if (!mapping) return null
  return [...mapping, target, ...flags].join(',')
}

type ProxyRecord = { now?: string }

type RuleProvider = {
  behavior?: string
  path?: string
  format?: string
}

export type ExportConfig = {
  rules?: string[]
  'rule-providers'?: Record<string, RuleProvider>
}

export type IosRoutingSnapshot = {
  version: number
  generatedAt: string
  sourceRuleCount: number
  sourceTopLevelRuleCount: number
  expandedProviderRuleCount: number
  skippedProcessRuleCount: number
  skippedDesktopOnlyRuleCount: number
  collapsedRuleSets: string[]
  policyMap: Record<string, string>
  rules: string[]
}

function leaf(proxies: Record<string, ProxyRecord>, name: string, seen: string[] = []): string {
  if (seen.includes(name)) {
    throw new Error('Cycle in desktop selector: ' + name)
  }
  const proxy = proxies[name]
  if (proxy === undefined && !['DIRECT', 'REJECT', 'REJECT-DROP'].includes(name)) {
    throw new Error('Missing desktop policy: ' + name)
  }
  if (proxy?.now) {
    return leaf(proxies, proxy.now, [...seen, name])
  }
  return name
}

function validatePortableRule(rule: string): void {
  const parts = rule.split(',')
  const kind = parts[0]
  const expected = kind === 'MATCH' ? 2 : 3
  if (
    !SUPPORTED.has(kind) ||
    ![expected, expected + 1].includes(parts.length) ||
    parts.some(
      (value) => !value || value !== value.trim() || value.includes('\n') || value.includes('\r')
    )
  ) {
    throw new Error('Malformed portable rule: ' + kind)
  }
  const target = parts[kind === 'MATCH' ? 1 : 2]
  if (!['DIRECT', 'REJECT', PLACEHOLDER].includes(target)) {
    throw new Error('Invalid portable policy: ' + kind)
  }
  if (parts.length > expected && parts[parts.length - 1] !== 'no-resolve') {
    throw new Error('Unsupported portable rule flag: ' + kind)
  }
  if (kind === 'NETWORK') {
    if (parts.length !== 3 || !['udp', 'tcp'].includes(parts[1].toLowerCase())) {
      throw new Error('NETWORK requires tcp/udp and no additional flags')
    }
  }
  if (kind.startsWith('DOMAIN') && !/^[A-Za-z0-9_.-]+$/.test(parts[1])) {
    throw new Error('Invalid portable domain rule')
  }
  if (kind === 'GEOIP' && !/^[A-Za-z]{2}$/.test(parts[1])) {
    throw new Error('Unsupported portable GeoIP selector')
  }
  if (kind === 'GEOSITE' && !/^[!a-zA-Z0-9_-]+$/.test(parts[1])) {
    throw new Error('Unsupported portable GeoSite selector')
  }
  if (kind === 'DST-PORT') {
    if (parts.length !== 3 && parts.length !== 4) {
      throw new Error('DST-PORT requires a portable port selector')
    }
    if (!PORT_SPEC.test(parts[1])) {
      throw new Error('DST-PORT requires a portable port selector')
    }
    if (parts.length === 4 && !['tcp', 'udp'].includes(parts[3].toLowerCase())) {
      throw new Error('DST-PORT transport must be tcp or udp')
    }
  }
}

async function providerRules(
  config: ExportConfig,
  name: string,
  target: string,
  flags: string[],
  baseDir: string,
  mihomoBinary: string
): Promise<string[]> {
  const provider = config['rule-providers']?.[name]
  if (!provider || typeof provider !== 'object') {
    throw new Error('Missing rule provider: ' + name)
  }
  const behavior = provider.behavior
  if (!behavior || !['domain', 'ipcidr', 'classical'].includes(behavior)) {
    throw new Error('Unsupported provider behavior: ' + String(behavior))
  }
  const relative = provider.path
  if (!relative) {
    throw new Error('Provider must have a local cached path: ' + name)
  }
  const source = path.isAbsolute(relative) ? relative : path.join(baseDir, relative)
  const { stat, mkdtemp } = await import('fs/promises')
  const sourceStat = await stat(source).catch(() => null)
  if (!sourceStat?.isFile() || sourceStat.size > MAX_PROVIDER_BYTES) {
    throw new Error('Provider cache missing or too large; update it in desktop first: ' + name)
  }
  const formatName = provider.format ?? 'yaml'
  let payload: string[]

  if (formatName === 'mrs') {
    if (!mihomoBinary) {
      throw new Error('MRS requires a desktop core binary; raw MRS is never imported on iOS')
    }
    const temporary = await mkdtemp(path.join(baseDir, 'ios-mrs-convert-'))
    const output = path.join(temporary, 'rules.txt')
    await execFilePromise(mihomoBinary, ['convert-ruleset', behavior, 'mrs', source, output], {
      timeout: 30_000
    })
    const converted = await readFile(output, 'utf8')
    if (Buffer.byteLength(converted, 'utf8') > MAX_PROVIDER_BYTES) {
      throw new Error('Converted provider is too large: ' + name)
    }
    payload = converted
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith('#'))
  } else if (formatName === 'yaml') {
    const parsed = parse<{ payload?: unknown }>(await readFile(source, 'utf8'))
    if (!Array.isArray(parsed.payload)) {
      throw new Error('Invalid or empty provider payload: ' + name)
    }
    payload = parsed.payload.filter(
      (value): value is string => typeof value === 'string' && Boolean(value)
    )
  } else if (formatName === 'text') {
    payload = (await readFile(source, 'utf8'))
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith('#'))
  } else {
    throw new Error('Unsupported provider format: ' + formatName)
  }

  if (!payload.length || payload.some((value) => typeof value !== 'string')) {
    throw new Error('Invalid or empty provider payload: ' + name)
  }

  const rules: string[] = []
  for (const value of payload) {
    if (behavior === 'domain') {
      const kind = value.startsWith('+.') ? 'DOMAIN-SUFFIX' : 'DOMAIN'
      const domain = kind === 'DOMAIN-SUFFIX' ? value.slice(2) : value
      if (!/^[A-Za-z0-9_][A-Za-z0-9_.-]*$/.test(domain)) {
        throw new Error('Provider domain pattern needs an exact mobile adapter: ' + name)
      }
      rules.push(`${kind},${domain},${target}`)
    } else if (behavior === 'ipcidr') {
      const kind = value.includes(':') ? 'IP-CIDR6' : 'IP-CIDR'
      rules.push([kind, value, target, ...flags].join(','))
    } else {
      const fields = value.split(',').map((part) => part.trim())
      const kind = fields[0]
      if (!SUPPORTED.has(kind) || kind === 'MATCH') {
        throw new Error('Classical provider needs an explicit mobile adapter: ' + kind)
      }
      rules.push([...fields.slice(0, 2), target, ...fields.slice(2), ...flags].join(','))
    }
  }
  return rules
}

export async function buildIosRoutingSnapshotFromSources(
  config: ExportConfig,
  proxies: Record<string, ProxyRecord>,
  baseDir: string,
  mihomoBinary: string
): Promise<IosRoutingSnapshot> {
  if (!Array.isArray(config.rules)) {
    throw new Error('Desktop configuration is missing rules')
  }

  const mapping: Record<string, string> = {}
  const converted: string[] = []
  let skipped = 0
  let skippedLogic = 0
  const collapsedRuleSets: string[] = []
  let expanded = 0

  for (const rule of config.rules) {
    const parts = rule.split(',').map((part) => part.trim())
    const kind = parts[0]
    if (SKIPPED.has(kind)) {
      if (LOGIC_RULES.has(kind)) {
        skippedLogic += 1
      }
      skipped += 1
      continue
    }
    if (!SUPPORTED.has(kind) && kind !== 'RULE-SET') {
      throw new Error('Rule needs an explicit iOS conversion: ' + kind)
    }
    const position = kind === 'MATCH' ? 1 : 2
    if (parts.length <= position) {
      throw new Error('Malformed rule: ' + kind)
    }
    const original = parts[position]
    const resolved = leaf(proxies, original)
    const target =
      resolved === 'DIRECT'
        ? 'DIRECT'
        : resolved === 'REJECT' || resolved === 'REJECT-DROP'
          ? 'REJECT'
          : PLACEHOLDER
    mapping[original] = target

    if (kind === 'NETWORK') {
      if (parts.length !== 3 || !['udp', 'tcp'].includes(parts[1].toLowerCase())) {
        throw new Error('NETWORK requires tcp/udp and no additional flags')
      }
      parts[1] = parts[1].toLowerCase()
    }

    if (kind === 'RULE-SET') {
      const providerName = parts[1]
      const collapsed = collapseRuleSet(providerName, target, parts.slice(position + 1))
      if (collapsed) {
        validatePortableRule(collapsed)
        converted.push(collapsed)
        collapsedRuleSets.push(providerName)
        continue
      }
      const added = await providerRules(
        config,
        parts[1],
        target,
        parts.slice(position + 1),
        baseDir,
        mihomoBinary
      )
      expanded += added.length
      converted.push(...added)
    } else {
      parts[position] = target
      converted.push(parts.join(','))
    }

    if (converted.length > MAX_RULES) {
      throw new Error(
        'Expanded policy exceeds the mobile 50000-rule limit; use public YAML providers in General Routing instead'
      )
    }
  }

  for (let index = 0; index < converted.length; index += 1) {
    const rule = converted[index]
    validatePortableRule(rule)
    if (rule.startsWith('MATCH,') && index !== converted.length - 1) {
      throw new Error('MATCH must be the final rule')
    }
  }
  if (!converted.length || !converted[converted.length - 1].startsWith('MATCH,')) {
    throw new Error('Desktop rules must end with MATCH')
  }

  const seen = new Set<string>()
  const deduped: string[] = []
  for (const rule of converted) {
    if (seen.has(rule)) continue
    seen.add(rule)
    deduped.push(rule)
  }

  return {
    version: 1,
    generatedAt: new Date().toISOString(),
    sourceRuleCount: converted.length + skipped,
    sourceTopLevelRuleCount: config.rules.length,
    expandedProviderRuleCount: expanded,
    skippedProcessRuleCount: skipped,
    skippedDesktopOnlyRuleCount: skippedLogic,
    collapsedRuleSets,
    policyMap: mapping,
    rules: deduped
  }
}
