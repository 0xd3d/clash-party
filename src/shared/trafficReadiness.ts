import type { PrivacyProtectionReport } from './privacyAudit'

export type TrafficReadinessState = 'idle' | 'warming' | 'ready' | 'blocked'

export type TrafficReadinessInput = {
  corePid?: number
  corePhase: 'initializing' | 'ready' | 'blocked' | 'shutting-down'
  tunEnabled?: boolean
  networkProtection: boolean
  report: PrivacyProtectionReport | null
}

const CRITICAL_FAILURE_IDS = new Set([
  'tunEnabled',
  'dnsEnabled',
  'dnsProxyOutbound',
  'networkGuard',
  'macDNSGuard'
])

export function deriveTrafficReadiness(input: TrafficReadinessInput): TrafficReadinessState {
  const { corePid, corePhase, tunEnabled, networkProtection, report } = input

  if (corePhase === 'shutting-down' || !corePid) {
    return 'idle'
  }
  if (corePhase === 'initializing') {
    return 'warming'
  }
  if (corePhase === 'blocked') {
    return 'blocked'
  }
  if (tunEnabled !== true) {
    return 'blocked'
  }
  if (!report || report.source === 'unavailable') {
    return 'warming'
  }

  const actionable = report.findings.filter((finding) => CRITICAL_FAILURE_IDS.has(finding.id))
  const hasCriticalError = actionable.some((finding) => finding.level === 'error')
  if (hasCriticalError) {
    return 'blocked'
  }

  const pendingGuard = report.findings.some((finding) => {
    if (!CRITICAL_FAILURE_IDS.has(finding.id)) return false
    if (finding.level === 'error') return true
    if (finding.level !== 'warning') return false
    if (finding.id === 'networkGuard' && !networkProtection) return false
    if (finding.id === 'macDNSGuard') return true
    if (finding.id === 'networkGuard' && networkProtection) return true
    return finding.level === 'warning'
  })

  if (pendingGuard) {
    return 'warming'
  }

  return 'ready'
}
