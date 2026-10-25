export type OperationMode = 'standard' | 'simple'

export type SimpleObject = Record<string, unknown>

export const SIMPLE_PROFILE_ID = 'simple-mode'

export const SIMPLE_BUILTIN_OUTBOUNDS: readonly string[] = [
  'DIRECT',
  'REJECT',
  'REJECT-DROP',
  'PASS',
  'PASS-RULE',
  'COMPATIBLE'
]

// These Mihomo fields are owned by the application and shared by both modes.
export const SIMPLE_SHARED_CONFIG_KEYS = [
  'dns',
  'hosts',
  'tun',
  'sniffer',
  'geox-url',
  'geodata-mode',
  'geo-auto-update',
  'geo-update-interval',
  'lgbm-auto-update',
  'lgbm-update-interval',
  'lgbm-url'
] as const

export type SimpleSharedConfigKey = (typeof SIMPLE_SHARED_CONFIG_KEYS)[number]

// Top-level Mihomo settings edited by the kernel settings page.
export const SIMPLE_GENERAL_CONFIG_KEYS = [
  'external-controller-pipe',
  'external-controller-unix',
  'external-controller',
  'external-ui',
  'external-ui-url',
  'external-controller-cors',
  'secret',
  'ipv6',
  'mode',
  'mixed-port',
  'socks-port',
  'port',
  'redir-port',
  'tproxy-port',
  'allow-lan',
  'unified-delay',
  'tcp-concurrent',
  'log-level',
  'find-process-mode',
  'skip-auth-prefixes',
  'bind-address',
  'lan-allowed-ips',
  'lan-disallowed-ips',
  'authentication',
  'profile'
] as const

export type SimpleGeneralConfigKey = (typeof SIMPLE_GENERAL_CONFIG_KEYS)[number]

export const SIMPLE_MODULES = {
  general: '基础设置',
  proxies: '节点',
  'proxy-providers': '代理集合',
  'proxy-groups': '策略组',
  rules: '规则',
  'rule-providers': '规则集合',
  'sub-rules': '子规则',
  dns: 'DNS',
  hosts: 'Hosts',
  tun: 'TUN',
  sniffer: '嗅探'
} as const

export type SimpleModule = keyof typeof SIMPLE_MODULES

export interface SimpleSubscriptionOptions {
  mode: 'group' | 'nodes'
  prefix?: string
  providerName?: string
  providerOptions?: SimpleObject
}

export interface SimpleSource {
  id: string
  name: string
  mode: 'extract' | 'inline' | 'http'
  url?: string
  content?: string
  prefix: string
  interval: number
  userAgent?: string
  authorization?: string
  ageSecretKey?: string
  proxy?: string
  providerOptions?: SimpleObject
  extra?: { upload: number; download: number; total: number; expire: number }
  proxies: SimpleObject[]
  updated?: number
  profileId?: string
  // Per-node cleanup of references from linked subscription content; no profile rewrite.
  removedDialerProxies?: Record<string, string[]>
}

export interface SimpleDraft {
  sources: SimpleSource[]
  modules: Record<SimpleModule, string>
  // Standard Mihomo fields without a dedicated simple-mode module.
  preserved?: SimpleObject
  moduleOrder?: SimpleModule[]
}

export interface SimpleState {
  version: 2
  revision: number
  inheritedProfileIds?: string[]
  draft: SimpleDraft
  published: SimpleDraft
}

export interface SimplePreview {
  yaml: string
  errors: string[]
  references: { outbounds: string[]; proxyProviders: string[]; ruleProviders: string[] }
}

export interface SimpleProxyGroupEditor {
  group: SimpleObject
  outbounds: string[]
  groupNames: string[]
  proxyProviders: string[]
  sources: string[]
  outboundDetails: Record<string, { type: string; source?: string }>
  providerTypes: Record<string, string>
}

export interface SimpleRuleEditor {
  rules: string[]
  ruleProviders: Record<string, SimpleObject>
  outbounds: string[]
  subRules: string[]
}

export type SimpleRuleChange =
  | { action: 'add'; value: string; index: number }
  | { action: 'edit'; value: string; index: number }
  | { action: 'remove'; index: number }
  | { action: 'reorder'; order: number[] }

export function defaultSimpleDraft(): SimpleDraft {
  return {
    sources: [],
    modules: {
      general:
        'mixed-port: 7890\nmode: rule\nlog-level: info\nallow-lan: false\nipv6: true\nprofile:\n  store-selected: true\n',
      proxies: '[]\n',
      'proxy-providers': '{}\n',
      'proxy-groups':
        '- name: PROXY\n  type: select\n  include-all-proxies: true\n  include-all-providers: true\n  proxies:\n    - DIRECT\n',
      rules: '- MATCH,PROXY\n',
      'rule-providers': '{}\n',
      'sub-rules': '{}\n',
      dns: 'enable: true\nlisten: 127.0.0.1:1053\nenhanced-mode: fake-ip\nfake-ip-range: 198.18.0.1/16\nnameserver:\n  - https://doh.pub/dns-query\nproxy-server-nameserver:\n  - https://dns.alidns.com/dns-query\n',
      hosts: '{}\n',
      tun: 'enable: false\nstack: mixed\nauto-route: true\nauto-detect-interface: true\nstrict-route: true\ndns-hijack:\n  - any:53\n  - tcp://any:53\n',
      sniffer: 'enable: false\n'
    },
    preserved: {},
    moduleOrder: Object.keys(SIMPLE_MODULES) as SimpleModule[]
  }
}
