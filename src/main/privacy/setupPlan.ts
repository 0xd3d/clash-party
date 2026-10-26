import { isDeepStrictEqual } from 'node:util'
import { DEFAULT_MIHOMO_TUN_CONFIG, getDefaultMihomoTunDevice } from '../../shared/appConfig'
import type { ProtectionSetupChange } from '../../shared/protectionSetup'

export function planProtectionSetup(
  app: IAppConfig,
  control: Partial<IMihomoConfig>,
  platform: NodeJS.Platform,
  proxyGroup = ''
): {
  appPatch: Partial<IAppConfig>
  control: Partial<IMihomoConfig>
  changes: ProtectionSetupChange[]
  settingsChanged: boolean
} {
  if (!['darwin', 'win32'].includes(platform))
    throw new Error('Protection setup requires macOS or Windows')
  if (typeof proxyGroup !== 'string' || proxyGroup.length > 256)
    throw new Error('Invalid protection target')
  const appPatch: Partial<IAppConfig> = {
    operationMode: 'standard',
    modeSelected: true,
    controlDns: false,
    networkProtection: true,
    networkProtectionProxyGroup: proxyGroup.trim(),
    networkProtectionPublicUDP: true,
    ...(platform === 'darwin'
      ? {
          autoSetDNS: true,
          systemDNSAddress: '127.0.0.1',
          systemDNSRestoreMode: app.systemDNSRestoreMode ?? 'original'
        }
      : {})
  }
  const next = structuredClone(control)
  next.mode = 'rule'
  next['allow-lan'] = false
  next['bind-address'] = '127.0.0.1'
  next.tun = {
    ...DEFAULT_MIHOMO_TUN_CONFIG,
    ...next.tun,
    enable: true,
    device: getDefaultMihomoTunDevice(platform),
    'auto-route': true,
    'auto-detect-interface': true,
    'strict-route': true,
    'dns-hijack': ['any:53', 'tcp://any:53']
  }
  // Node/DNS/provider/routing policies belong to the imported profile, not this preset.
  const changes: ProtectionSetupChange[] = [
    'mode',
    'tun',
    'dns',
    ...(platform === 'darwin' ? ['systemDNS' as const] : []),
    'lan',
    'traffic',
    'preserve'
  ]
  return {
    appPatch,
    control: next,
    changes,
    settingsChanged:
      !isDeepStrictEqual(next, control) ||
      Object.entries(appPatch).some(([key, value]) => !isDeepStrictEqual(app[key], value))
  }
}
