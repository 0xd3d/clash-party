import { nativeProtectionConfirmed } from '../../shared/privacyAudit'
import type { ProtectionSetupResult } from '../../shared/protectionSetup'

export type ProtectionSetupTransaction<T> = {
  withSettingsLock<R>(operation: () => Promise<R>): Promise<R>
  validate(): Promise<T>
  alreadyVerified(candidate: T): Promise<ProtectionSetupResult | null>
  checkPermissions(candidate: T): Promise<void>
  backup(candidate: T): Promise<string>
  commit(candidate: T): Promise<void>
  restart(): Promise<unknown>
  verify(): Promise<ProtectionSetupResult['report']>
}

/** Never release an armed guard or undo protection intent after restart begins. */
export async function executeProtectionSetup<T>(
  actions: ProtectionSetupTransaction<T>
): Promise<ProtectionSetupResult> {
  const prepared = await actions.withSettingsLock(async () => {
    const candidate = await actions.validate()
    const existing = await actions.alreadyVerified(candidate)
    if (existing) return { existing, backupPath: null }
    await actions.checkPermissions(candidate)
    const backupPath = await actions.backup(candidate)
    await actions.commit(candidate)
    return { existing: null, backupPath }
  })
  if (prepared.existing) return prepared.existing
  const backupPath = prepared.backupPath
  if (!backupPath) throw new Error('Protection backup was not established')
  try {
    await actions.restart()
    const report = await actions.verify()
    const verified = nativeProtectionConfirmed(report)
    if (!verified) throw new Error('Native protection could not be confirmed')
    return { backupPath, restarted: true, verified, report }
  } catch (error) {
    // A failed arm/start may already be blocking traffic. Explicit recovery remains available.
    throw new Error(
      `Protection setup needs attention; protection was not released. Backup: ${backupPath}. ${error instanceof Error ? error.message : String(error)}`,
      { cause: error }
    )
  }
}
