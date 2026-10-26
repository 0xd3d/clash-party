import {
  nativeProtectionConfirmed,
  requiredNativeChecks,
  type PrivacyAuditFinding,
  type PrivacyProtectionReport
} from './privacyAudit'

export const PRIVACY_GROUPS = ['traffic', 'dns', 'guard', 'udp'] as const
export type PrivacyGroup = (typeof PRIVACY_GROUPS)[number]
export const isUnresolved = (finding: PrivacyAuditFinding): boolean =>
  finding.level === 'warning' || finding.level === 'error'
export const isDiagnostic = (finding: PrivacyAuditFinding): boolean =>
  finding.level === 'info' && ['scope', 'windowsRouting', 'ipv6Config'].includes(finding.id)

export function findingGroup(finding: PrivacyAuditFinding): PrivacyGroup {
  if (['networkGuard', 'networkGuardDisabled'].includes(finding.id)) return 'guard'
  if (finding.id.startsWith('udp') || finding.id === 'publicUDPProtection') return 'udp'
  if (finding.id.toLowerCase().includes('dns')) return 'dns'
  return 'traffic'
}
export function reportFindings(report: PrivacyProtectionReport): PrivacyAuditFinding[] {
  if (report.source !== 'applied') return report.findings
  const missing = requiredNativeChecks(report.platform).filter(
    (id) =>
      !report.findings.some(
        (f) => f.id === id || (id === 'networkGuard' && f.id === 'networkGuardDisabled')
      )
  )
  return [...report.findings, ...missing.map((id) => ({ id, level: 'warning' as const }))]
}
export function summarizeProtectionReport(report: PrivacyProtectionReport) {
  return {
    configApplied: report.source === 'applied',
    nativeConfirmed: nativeProtectionConfirmed(report),
    unresolvedCount: reportFindings(report).filter(isUnresolved).length,
    networkTest: 'not-run' as const
  }
}

const protectionChangeEvents = [
  'appConfigUpdated',
  'controledMihomoConfigUpdated',
  'groupsUpdated',
  'rulesUpdated',
  'profileConfigUpdated',
  'overrideConfigUpdated',
  'simpleConfigUpdated'
]
export function watchProtectionChanges(
  listen: (event: string, handler: () => void) => () => void,
  invalidate: () => void
): () => void {
  const unsubscribers = protectionChangeEvents.map((event) => listen(event, invalidate))
  return () => unsubscribers.forEach((unsubscribe) => unsubscribe())
}
export function protectionErrorHint(message: string): string {
  if (message.includes('Protection setup needs attention')) return 'afterApply'
  if (/bootstrap|encrypted DNS/i.test(message)) return 'bootstrap'
  if (/target|proxy-only/i.test(message)) return 'target'
  if (/Import and select/i.test(message)) return 'profile'
  if (/preview|Configuration changed/i.test(message)) return 'preview'
  if (/privilege|permission|administrator/i.test(message)) return 'permission'
  return 'unknown'
}
