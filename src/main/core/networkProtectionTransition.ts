import { applyNetworkProtectionPolicy } from './networkProtectionPolicy'

export type NetworkProtectionChange = {
  enabled: boolean
  proxyGroup?: string
  protectPublicUDP?: boolean
}
type ProtectionSettings = Pick<
  IAppConfig,
  'networkProtection' | 'networkProtectionProxyGroup' | 'networkProtectionPublicUDP'
>
export interface NetworkProtectionTransition {
  readSettings(): Promise<Partial<IAppConfig>>
  readRuntime(): Promise<Partial<IMihomoConfig>>
  persist(settings: ProtectionSettings): Promise<void>
  stop(): Promise<void>
  recover(): Promise<void>
  restart(): Promise<unknown>
}

/** Reject known-ineligible cached runtime before persisting a future cold-start requirement.
 * Restart still validates the freshly compiled profile before arming or replacing the core.
 */
export async function transitionNetworkProtection(
  change: NetworkProtectionChange,
  actions: NetworkProtectionTransition
): Promise<void> {
  if (
    typeof change?.enabled !== 'boolean' ||
    (change.proxyGroup !== undefined &&
      (typeof change.proxyGroup !== 'string' || change.proxyGroup.length > 256)) ||
    (change.protectPublicUDP !== undefined && typeof change.protectPublicUDP !== 'boolean')
  )
    throw new Error('Invalid network protection settings')
  const next: ProtectionSettings = {
    networkProtection: change.enabled,
    networkProtectionProxyGroup: change.proxyGroup?.trim() ?? '',
    networkProtectionPublicUDP: change.protectPublicUDP !== false
  }
  if (change.enabled) {
    const [settings, runtime] = await Promise.all([actions.readSettings(), actions.readRuntime()])
    // The factory exposes a shared snapshot. Eligibility checks must not mutate it.
    applyNetworkProtectionPolicy(structuredClone(runtime) as IMihomoConfig, {
      ...settings,
      ...next
    })
  } else {
    // Recovery must remain available even when the cached profile is empty or invalid.
    await actions.stop()
    await actions.recover()
  }
  await actions.persist(next)
  // After persistence, failures may already have armed a guard. Do not roll back
  // the intent or release protection on this path.
  await actions.restart()
}
