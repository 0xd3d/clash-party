import type { PrivacyProtectionReport } from './privacyAudit'

export type ProtectionSetupChange =
  'mode' | 'tun' | 'dns' | 'systemDNS' | 'lan' | 'traffic' | 'preserve'
export type ProtectionSetupPreview = {
  token: string
  profileName: string
  proxyGroup: string
  changes: ProtectionSetupChange[]
}
export type ProtectionSetupResult = {
  backupPath: string | null
  restarted: boolean
  verified: boolean
  report: PrivacyProtectionReport
}
