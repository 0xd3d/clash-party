import { access, cp, mkdir } from 'fs/promises'
import path from 'path'
import { app, dialog, type WebContents } from 'electron'
import { getAppConfig } from '../config'
import {
  getAppliedCoreConfig,
  getAppliedCoreRevision,
  getAppliedRouteOrigins,
  getCurrentCorePID
} from '../core/manager'
import { getAxios } from '../core/mihomoApi'
import { inspectMacDNSGuard } from '../core/macDNSGuard'
import { inspectNetworkGuard } from '../core/networkGuard'
import {
  auditPrivacyConfig,
  nativeGuardReason,
  type PrivacyProtectionReport
} from '../../shared/privacyAudit'

/** Covers this application's own pages, not external browser processes. */
export function protectWebContentsPrivacy(
  contents: Pick<WebContents, 'setWebRTCIPHandlingPolicy'>
): void {
  contents.setWebRTCIPHandlingPolicy('disable_non_proxied_udp')
}

export async function inspectPrivacyProtection(): Promise<PrivacyProtectionReport> {
  const unavailable = (): PrivacyProtectionReport => ({
    platform: process.platform,
    source: 'unavailable',
    findings: [{ id: 'runtimeUnavailable', level: 'warning' }]
  })
  const corePid = getCurrentCorePID()
  const snapshot = getAppliedCoreConfig()
  const revision = getAppliedCoreRevision()
  if (!snapshot || corePid === undefined || revision === undefined) return unavailable()
  try {
    const [config, instance] = await Promise.all([getAppConfig(), getAxios()])
    const live = await instance.get<never, IMihomoConfig>('/configs')
    if (getCurrentCorePID() !== corePid || getAppliedCoreRevision() !== revision)
      return unavailable()
    const applied: Partial<IMihomoConfig> = {
      ...snapshot,
      tun: live.tun,
      ipv6: live.ipv6,
      'allow-lan': live['allow-lan'],
      'bind-address': live['bind-address']
    }
    const diagnostics: { id: string; value: string }[] = [
      { id: 'dnsPolicy', value: JSON.stringify(applied.dns?.['nameserver-policy'] ?? {}) },
      { id: 'platform', value: process.platform },
      { id: 'corePid', value: String(corePid) }
    ]
    const findings = [
      ...auditPrivacyConfig(applied, process.platform, config, getAppliedRouteOrigins())
    ]
    if (process.platform === 'darwin' && config.autoSetDNS !== false && live.tun?.enable) {
      try {
        const guard = await inspectMacDNSGuard()
        diagnostics.push({
          id: 'dnsGuard',
          value: JSON.stringify({ backend: 'PF', active: guard.active, corePid: guard.corePid })
        })
        findings.push({
          id: 'macDNSGuard',
          level: guard.active && guard.corePid === corePid ? 'pass' : 'warning',
          reason: nativeGuardReason({ active: guard.active, corePid: guard.corePid }, corePid)
        })
      } catch {
        findings.push({ id: 'macDNSGuard', level: 'warning', reason: 'statusUnavailable' })
      }
    }
    if (config.networkProtection && ['darwin', 'win32'].includes(process.platform)) {
      try {
        const guard = await inspectNetworkGuard()
        diagnostics.push({
          id: 'networkGuard',
          value: JSON.stringify({
            backend: process.platform === 'darwin' ? 'PF' : 'WFP',
            active: guard.active,
            corePid: guard.corePid,
            coreAlive: guard.coreAlive,
            trafficLease: guard.trafficLease
          })
        })
        findings.push({
          id: 'networkGuard',
          level:
            guard.active &&
            guard.corePid === corePid &&
            guard.coreAlive !== false &&
            guard.trafficLease !== false
              ? 'pass'
              : 'warning',
          reason: nativeGuardReason(guard, corePid)
        })
      } catch {
        findings.push({ id: 'networkGuard', level: 'warning', reason: 'statusUnavailable' })
      }
      if (config.networkProtectionPublicUDP === false)
        findings.push({ id: 'publicUDPProtection', level: 'warning' })
    }
    if (!config.networkProtection) findings.push({ id: 'networkGuardDisabled', level: 'warning' })
    // Native status is asynchronous too; reject reports crossing a restart or hot reload.
    if (getCurrentCorePID() !== corePid || getAppliedCoreRevision() !== revision)
      return unavailable()
    return { platform: process.platform, source: 'applied', findings, diagnostics }
  } catch {
    return unavailable()
  }
}

/** Export an optional browser component; never edits browser profiles or OS policy. */
export async function exportWebRTCGuard(): Promise<string | null> {
  const source = path.join(
    app.isPackaged ? process.resourcesPath : app.getAppPath(),
    'integrations',
    'webrtc-guard'
  )
  await access(path.join(source, 'manifest.json'))
  const result = await dialog.showOpenDialog({
    properties: ['openDirectory', 'createDirectory']
  })
  if (result.canceled || !result.filePaths[0]) return null
  const destination = path.join(result.filePaths[0], 'ClashParty-WebRTC-Guard')
  // Refuse to overwrite an existing folder, including one containing user changes.
  await mkdir(destination)
  await cp(source, destination, {
    recursive: true,
    force: false,
    errorOnExist: true,
    filter: (file) => !file.endsWith('.d.ts') && !file.endsWith('.d.mts')
  })
  return destination
}
