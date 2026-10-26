import { describe, expect, it, vi } from 'vitest'
const mocks = vi.hoisted(() => ({ write: vi.fn(), generate: vi.fn(), patch: vi.fn() }))
vi.mock('fs', () => ({ existsSync: () => true }))
vi.mock('fs/promises', () => ({
  readFile: async () => 'mode: rule\nstandard-sentinel: keep\ntun:\n  enable: false\n'
}))
vi.mock('../utils/dirs', () => ({ controledMihomoConfigPath: () => '/control.yaml' }))
vi.mock('./app', () => ({
  getAppConfig: async () => ({ operationMode: 'simple' }),
  patchAppConfig: vi.fn()
}))
vi.mock('../simple/store', () => ({
  getSimpleState: async () => ({ published: { modules: { general: '{}' } } })
}))
vi.mock('../core/factory', () => ({ generateProfile: mocks.generate }))
vi.mock('../core/mihomoApi', () => ({ patchMihomoConfig: mocks.patch, startMihomoLogs: vi.fn() }))
vi.mock('../utils/logger', () => ({ createLogger: () => ({ warn: vi.fn(), error: vi.fn() }) }))
vi.mock('../utils/safeFile', async (original) => ({
  ...(await original<typeof import('../utils/safeFile')>()),
  atomicWriteFile: mocks.write
}))
import {
  getControledMihomoConfig,
  getStoredControledMihomoConfig,
  persistProtectionSetupControl
} from './controledMihomo'

describe('protection setup control backing store', () => {
  it('preserves standard-only fields from simple mode, commits without runtime mutation and rejects stale writes', async () => {
    const displayed = await getControledMihomoConfig()
    const stored = await getStoredControledMihomoConfig()
    expect(displayed).not.toHaveProperty('standard-sentinel')
    expect(stored).toHaveProperty('standard-sentinel', 'keep')
    const next = structuredClone(stored)
    next.tun = { ...next.tun, enable: true }
    await persistProtectionSetupControl(next, stored)
    expect(mocks.write).toHaveBeenCalledOnce()
    expect(mocks.generate).not.toHaveBeenCalled()
    expect(mocks.patch).not.toHaveBeenCalled()
    await expect(persistProtectionSetupControl(stored, stored)).rejects.toThrow('changed')
    expect(mocks.write).toHaveBeenCalledOnce()
    const copy = await getStoredControledMihomoConfig()
    if (!copy.tun) throw new Error('Missing saved TUN settings')
    copy.tun.enable = false
    expect((await getStoredControledMihomoConfig()).tun?.enable).toBe(true)
  })
})
