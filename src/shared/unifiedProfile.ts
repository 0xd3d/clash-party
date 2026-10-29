/** Portable policy only. OS permissions, native guards and TUN devices remain app-owned. */
export const UNIFIED_PROFILE_FORMAT = 'clash-party-unified'
export const UNIFIED_PROFILE_VERSION = 1
export const UNIFIED_PROFILE_LIMIT = 8 * 1024 * 1024
export const unifiedPlatforms = ['macos', 'windows', 'ios'] as const
export type UnifiedPlatform = (typeof unifiedPlatforms)[number]
type ObjectValue = Record<string, unknown>
export interface UnifiedRule {
  rule: string
  platforms?: UnifiedPlatform[]
}
export interface UnifiedProfile {
  format: typeof UNIFIED_PROFILE_FORMAT
  version: 1
  revision: string
  common: ObjectValue
  rules: (string | UnifiedRule)[]
  platforms?: Partial<Record<UnifiedPlatform, { 'rule-providers': ObjectValue }>>
}
const commonKeys = new Set([
  'mode',
  'ipv6',
  'log-level',
  'find-process-mode',
  'geodata-mode',
  'geodata-loader',
  'geo-auto-update',
  'geo-update-interval',
  'geox-url',
  'dns',
  'hosts',
  'sniffer',
  'proxies',
  'proxy-groups',
  'proxy-providers',
  'rule-providers',
  'profile'
])
function fail(message: string): never {
  throw new Error(`Unified profile: ${message}`)
}
function object(value: unknown, context: string): ObjectValue {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    fail(`${context} must be an object`)
  return value as ObjectValue
}
function keys(value: ObjectValue, allowed: Set<string>, context: string): void {
  for (const key of Object.keys(value))
    if (!allowed.has(key)) fail(`${context}: unsupported field ${key}`)
}
function inspect(value: unknown, depth = 0): void {
  if (depth > 32) fail('nesting exceeds 32 levels')
  if (value && typeof value === 'object') {
    for (const [key, child] of Object.entries(value)) {
      if (['__proto__', 'constructor', 'prototype'].includes(key)) fail('unsafe object key')
      inspect(child, depth + 1)
    }
  }
}
export function desktopUnifiedPlatform(platform: string): UnifiedPlatform {
  if (platform === 'darwin') return 'macos'
  if (platform === 'win32') return 'windows'
  fail(`platform ${platform} is not supported by this profile format`)
}
export function isUnifiedProfile(value: unknown): boolean {
  return (
    !!value &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    (value as { format?: unknown }).format === UNIFIED_PROFILE_FORMAT
  )
}

function matchTarget(rule: string): string | undefined {
  const fields = rule.split(',')
  if (fields.length !== 2 || fields[0].trim().toUpperCase() !== 'MATCH') return undefined
  const target = fields[1].trim()
  return target || undefined
}
export function compileUnifiedProfile(value: unknown, platform: UnifiedPlatform): ObjectValue {
  if (!unifiedPlatforms.includes(platform)) fail('unknown platform')
  const envelope = object(value, 'document')
  inspect(envelope)
  keys(
    envelope,
    new Set(['format', 'version', 'revision', 'common', 'rules', 'platforms']),
    'document'
  )
  if (envelope.format !== UNIFIED_PROFILE_FORMAT || envelope.version !== 1)
    fail('unsupported format or version')
  if (
    typeof envelope.revision !== 'string' ||
    !envelope.revision.trim() ||
    envelope.revision.length > 128
  )
    fail('revision must be a nonempty string of at most 128 characters')
  const common = object(envelope.common, 'common')
  keys(common, commonKeys, 'common (machine settings must be configured in the app)')
  if (common.dns !== undefined && 'listen' in object(common.dns, 'common.dns'))
    fail('DNS listener belongs to local app settings, not the shared policy')
  const variants = envelope.platforms === undefined ? {} : object(envelope.platforms, 'platforms')
  keys(variants, new Set(unifiedPlatforms), 'platforms')
  for (const [name, variant] of Object.entries(variants)) {
    const fields = object(variant, name)
    keys(fields, new Set(['rule-providers']), name)
    object(fields['rule-providers'], `${name}.rule-providers`)
  }
  if (
    !Array.isArray(envelope.rules) ||
    envelope.rules.length === 0 ||
    envelope.rules.length > 50000
  )
    fail('rules must contain 1–50000 entries')
  const rules: string[] = []
  for (const entry of envelope.rules) {
    let rule: unknown = entry
    let applies = true
    if (typeof entry !== 'string') {
      const item = object(entry, 'rule')
      keys(item, new Set(['rule', 'platforms']), 'rule')
      rule = item.rule
      if (item.platforms !== undefined) {
        if (
          !Array.isArray(item.platforms) ||
          item.platforms.length === 0 ||
          item.platforms.some((p) => !unifiedPlatforms.includes(p)) ||
          new Set(item.platforms).size !== item.platforms.length
        )
          fail('invalid rule platforms')
        applies = item.platforms.includes(platform)
      }
    }
    if (typeof rule !== 'string' || !rule.trim() || /[\r\n]/.test(rule)) fail('invalid rule text')
    if (applies) rules.push(rule)
  }
  const lastRule = rules.at(-1)
  if (!lastRule || !matchTarget(lastRule) || rules.slice(0, -1).some((rule) => matchTarget(rule)))
    fail(`${platform} must have exactly one final MATCH rule`)
  const profile = JSON.parse(JSON.stringify(common)) as ObjectValue
  const variant = variants[platform] as ObjectValue | undefined
  if (variant) {
    const providers = { ...object(profile['rule-providers'] ?? {}, 'common.rule-providers') }
    for (const [name, provider] of Object.entries(
      object(variant['rule-providers'], 'platform.rule-providers')
    )) {
      if (provider === null) delete providers[name]
      else providers[name] = provider
    }
    profile['rule-providers'] = providers
  }
  const providerNames = new Set(
    Object.keys(object(profile['rule-providers'] ?? {}, 'rule-providers'))
  )
  for (const rule of rules)
    for (const match of rule.matchAll(/(?:^|[,(])RULE-SET,([^,()]+)(?=[,)])/g)) {
      if (!providerNames.has(match[1])) fail(`missing rule provider: ${match[1]}`)
    }
  if (platform === 'ios') {
    if (rules.some((rule) => /(?:^|[,(])PROCESS-(?:NAME|PATH|NAME-REGEX|PATH-REGEX),/i.test(rule)))
      fail('iOS cannot apply process rules; declare their desktop platforms explicitly')
    for (const provider of Object.values(object(profile['rule-providers'] ?? {}, 'rule-providers')))
      if (object(provider, 'rule provider').format === 'mrs')
        fail('iOS cannot read MRS; provide an explicit YAML provider variant')
  }
  profile.rules = rules
  return profile
}
/** JSON transport is deliberate: both importers consume the same bounded, alias-free format. */
export function adaptUnifiedProfile(text: string, parsed: unknown, platform: string): unknown {
  if (!isUnifiedProfile(parsed)) return parsed
  if (new TextEncoder().encode(text).length > UNIFIED_PROFILE_LIMIT) fail('file exceeds 8 MiB')
  let document: unknown
  try {
    document = JSON.parse(text)
  } catch {
    fail('use JSON syntax (a .yaml extension is supported)')
  }
  return compileUnifiedProfile(document, desktopUnifiedPlatform(platform))
}
