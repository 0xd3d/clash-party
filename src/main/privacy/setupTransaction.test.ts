import { describe, expect, it, vi } from 'vitest'
import type { PrivacyProtectionReport } from '../../shared/privacyAudit'
import { executeProtectionSetup, type ProtectionSetupTransaction } from './setupTransaction'
function report(platform: 'darwin' | 'win32' = 'darwin'): PrivacyProtectionReport {
  return {
    platform,
    source: 'applied',
    findings: [
      { id: 'macDNSGuard', level: 'pass' },
      { id: 'networkGuard', level: 'pass' }
    ]
  }
}
function actions(): ProtectionSetupTransaction<string> {
  return {
    withSettingsLock: (operation) => operation(),
    validate: vi.fn().mockResolvedValue('candidate'),
    alreadyVerified: vi.fn().mockResolvedValue(null),
    checkPermissions: vi.fn().mockResolvedValue(undefined),
    backup: vi.fn().mockResolvedValue('/private-backup'),
    commit: vi.fn().mockResolvedValue(undefined),
    restart: vi.fn().mockResolvedValue(undefined),
    verify: vi.fn().mockResolvedValue(report())
  }
}
describe('one-click protection transaction', () => {
  it.each(['darwin', 'win32'] as const)(
    'backs up and commits before one restart on %s',
    async (platform) => {
      const a = actions(),
        order: string[] = []
      vi.mocked(a.verify).mockResolvedValue(report(platform))
      vi.mocked(a.checkPermissions).mockImplementation(async () => {
        order.push('checkPermissions')
      })
      vi.mocked(a.backup).mockImplementation(async () => {
        order.push('backup')
        return '/private-backup'
      })
      vi.mocked(a.commit).mockImplementation(async () => {
        order.push('commit')
      })
      vi.mocked(a.restart).mockImplementation(async () => {
        order.push('restart')
      })
      const value = await executeProtectionSetup(a)
      expect(order).toEqual(['checkPermissions', 'backup', 'commit', 'restart'])
      expect(value).toMatchObject({
        backupPath: '/private-backup',
        restarted: true,
        verified: true
      })
      expect(a.restart).toHaveBeenCalledOnce()
    }
  )
  it.each(['validate', 'checkPermissions', 'backup', 'commit'] as const)(
    'does not restart when %s fails',
    async (method) => {
      const a = actions()
      vi.mocked(a[method]).mockRejectedValue(Error('failed before restart'))
      await expect(executeProtectionSetup(a)).rejects.toThrow('before restart')
      expect(a.restart).not.toHaveBeenCalled()
      expect(a.verify).not.toHaveBeenCalled()
      if (method === 'validate' || method === 'checkPermissions')
        expect(a.backup).not.toHaveBeenCalled()
    }
  )
  it('does not repeat writes or restart an already applied and verified setup', async () => {
    const a = actions(),
      existing = { backupPath: null, restarted: false, verified: true, report: report() }
    vi.mocked(a.alreadyVerified).mockResolvedValue(existing)
    expect(await executeProtectionSetup(a)).toEqual(existing)
    for (const action of [a.checkPermissions, a.backup, a.commit, a.restart, a.verify])
      expect(action).not.toHaveBeenCalled()
  })
  it('retains committed protection after native start failure and reports the backup', async () => {
    const a = actions()
    vi.mocked(a.restart).mockRejectedValue(Error('native arm failed'))
    await expect(executeProtectionSetup(a)).rejects.toThrow(
      'protection was not released. Backup: /private-backup'
    )
    expect(a.commit).toHaveBeenCalledOnce()
    expect(a.restart).toHaveBeenCalledOnce()
    expect(a.verify).not.toHaveBeenCalled()
  })
  it('does not call an unconfirmed native state successful', async () => {
    const a = actions()
    vi.mocked(a.verify).mockResolvedValue({
      ...report(),
      findings: [{ id: 'networkGuard', level: 'pass' }]
    })
    await expect(executeProtectionSetup(a)).rejects.toThrow('needs attention')
    expect(a.commit).toHaveBeenCalledOnce()
  })
})
