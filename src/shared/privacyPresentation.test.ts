import { describe, expect, it } from 'vitest'
import {
  findingGroup,
  watchProtectionChanges,
  protectionErrorHint,
  isDiagnostic,
  reportFindings,
  summarizeProtectionReport
} from './privacyPresentation'
import type { PrivacyProtectionReport } from './privacyAudit'
const report = (platform: 'darwin' | 'win32'): PrivacyProtectionReport => ({
  platform,
  source: 'applied',
  findings: [
    { id: 'networkGuard', level: 'pass' },
    ...(platform === 'darwin' ? [{ id: 'macDNSGuard', level: 'pass' } as const] : [])
  ]
})
describe('protection report presentation', () => {
  it.each(['darwin', 'win32'] as const)(
    'separates native confirmation from unperformed network tests on %s',
    (platform) => {
      const r = report(platform)
      expect(summarizeProtectionReport(r)).toEqual({
        configApplied: true,
        nativeConfirmed: true,
        unresolvedCount: 0,
        networkTest: 'not-run'
      })
      r.findings.push(
        { id: 'routePublicExclusion', level: 'warning' },
        { id: 'udpDirect', level: 'error' }
      )
      expect(summarizeProtectionReport(r)).toMatchObject({
        nativeConfirmed: true,
        unresolvedCount: 2,
        networkTest: 'not-run'
      })
    }
  )
  it('does not lose missing native evidence behind a success result or a closed details group', () => {
    const r = report('darwin')
    r.findings = []
    expect(summarizeProtectionReport(r)).toMatchObject({
      nativeConfirmed: false,
      unresolvedCount: 2
    })
    expect(reportFindings(r).map((f) => f.id)).toEqual(['macDNSGuard', 'networkGuard'])
  })
  it('does not hide warnings as diagnostic information or drop unfamiliar checks', () => {
    expect(isDiagnostic({ id: 'ipv6Config', level: 'warning' })).toBe(false)
    expect(findingGroup({ id: 'newCheck', level: 'warning' })).toBe('traffic')
    expect(findingGroup({ id: 'udpRuleOrdering', level: 'warning' })).toBe('udp')
    expect(findingGroup({ id: 'macDNSGuard', level: 'pass' })).toBe('dns')
  })
})

it('invalidates old reports on configuration and core changes, and unsubscribes on exit', () => {
  const callbacks = new Map<string, () => void>()
  let revision = 0
  const stop = watchProtectionChanges(
    (event, handler) => {
      callbacks.set(event, handler)
      return () => {
        callbacks.delete(event)
      }
    },
    () => {
      revision++
    }
  )
  const ticket = revision
  for (const event of ['controledMihomoConfigUpdated', 'groupsUpdated', 'profileConfigUpdated'])
    callbacks.get(event)?.()
  expect(revision).toBeGreaterThan(ticket)
  stop()
  expect(callbacks.size).toBe(0)
})
it('maps native failure to a retained-blocking recovery hint instead of success', () => {
  expect(
    protectionErrorHint(
      'Protection setup needs attention; protection was not released. Backup: /private/test. Native protection could not be confirmed'
    )
  ).toBe('afterApply')
  expect(protectionErrorHint('Bootstrap DNS must be encrypted')).toBe('bootstrap')
  expect(protectionErrorHint('Protection setup preview expired; preview again')).toBe('preview')
  expect(protectionErrorHint('unknown failure')).toBe('unknown')
})

it('reports specific native failure reasons without declaring protection confirmed', async () => {
  const { nativeGuardReason } = await import('./privacyAudit')
  expect(nativeGuardReason({ active: false }, 123)).toBe('inactive')
  expect(nativeGuardReason({ active: true, corePid: 122 }, 123)).toBe('previousConnection')
  expect(nativeGuardReason({ active: true, corePid: 123, coreAlive: false }, 123)).toBe(
    'tunnelUnavailable'
  )
  expect(nativeGuardReason({ active: true, corePid: 123, trafficLease: false }, 123)).toBe(
    'trafficUnconfirmed'
  )
  expect(nativeGuardReason({ active: true, corePid: 123 }, 123)).toBeUndefined()
})
