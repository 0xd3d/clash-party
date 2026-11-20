import { describe, expect, it } from 'vitest'
import {
  bootLeakEgressRuleLines,
  collectLiteralProxyServerIPs,
  coreListenAddresses,
  normalizeBootLeakProxyServers,
  parseBootLeakPolicyFile,
  shouldArmBootLeakGuard
} from './bootLeakPolicy'

describe('bootLeakPolicy', () => {
  it('arms before core listen and disarms when listening unless disabled', () => {
    expect(shouldArmBootLeakGuard({ disabled: false, coreListening: false })).toBe(true)
    expect(shouldArmBootLeakGuard({ disabled: false, coreListening: true })).toBe(false)
    expect(shouldArmBootLeakGuard({ disabled: true, coreListening: false })).toBe(false)
  })

  it('collects only literal proxy server IPs', () => {
    expect(
      collectLiteralProxyServerIPs([
        { server: '210.126.232.127' },
        { server: 'example.com' },
        { server: '[2001:db8::1]' }
      ])
    ).toEqual(['2001:db8::1', '210.126.232.127'])
    expect(normalizeBootLeakProxyServers(['210.126.232.127', '210.126.232.127', 'nope'])).toEqual([
      '210.126.232.127'
    ])
  })

  it('builds LAN/DHCP/proxy allowlist then a full egress deny', () => {
    const lines = bootLeakEgressRuleLines({
      disabled: false,
      mixedPort: 7890,
      dnsListenPort: 1053,
      proxyServers: ['210.126.232.127']
    })
    expect(lines[0]).toBe('pass quick on lo0 all no state')
    expect(lines.some((line) => line.includes('192.168.0.0/16'))).toBe(true)
    expect(lines.some((line) => line.includes('210.126.232.127'))).toBe(true)
    expect(lines.at(-1)).toBe('block drop quick all label "ClashPartyBootLeak"')
    expect(lines.some((line) => line.includes('port 68'))).toBe(true)
  })

  it('omits proxy passes when server IPs cannot be read', () => {
    const lines = bootLeakEgressRuleLines({
      disabled: false,
      mixedPort: 7890,
      dnsListenPort: 1053,
      proxyServers: []
    })
    expect(lines.some((line) => line.includes('210.126.'))).toBe(false)
    expect(lines.at(-1)).toContain('block drop')
  })

  it('parses boot leak policy JSON snapshots', () => {
    expect(
      parseBootLeakPolicyFile(
        JSON.stringify({
          version: 1,
          disabled: false,
          mixedPort: 7890,
          dnsListenPort: 1053,
          proxyServers: ['210.126.232.127', 'bad']
        })
      )
    ).toEqual({
      disabled: false,
      mixedPort: 7890,
      dnsListenPort: 1053,
      proxyServers: ['210.126.232.127']
    })
    expect(() => parseBootLeakPolicyFile('{"mixedPort":0}')).toThrow(/mixed port/i)
  })

  it('tracks loopback mixed and DNS listener ports', () => {
    expect(coreListenAddresses({ mixedPort: 7890, dnsListenPort: 1053 })).toEqual([
      '127.0.0.1:7890',
      '127.0.0.1:1053',
      '[::1]:7890',
      '[::1]:1053'
    ])
  })
})
