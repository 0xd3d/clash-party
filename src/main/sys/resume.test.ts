import { beforeEach, describe, expect, it, vi } from 'vitest'
import { initResumeRecovery, recoverAfterResume } from './resume'

const handlers: Record<string, () => void> = {}
const mocks = vi.hoisted(() => ({
  restartCore: vi.fn(),
  patchMihomoConfig: vi.fn(),
  recoverDNS: vi.fn(),
  mihomoHotReloadConfig: vi.fn(),
  handleSystemResume: vi.fn(),
  cancelSystemResumeReload: vi.fn()
}))

vi.mock('electron', () => ({
  powerMonitor: {
    on: (event: string, handler: () => void) => {
      handlers[event] = handler
    }
  },
  net: { isOnline: () => true }
}))

vi.mock('../core/manager', () => ({
  hasCoreProcess: () => true,
  restartCore: mocks.restartCore,
  handleSystemResume: mocks.handleSystemResume,
  cancelSystemResumeReload: mocks.cancelSystemResumeReload
}))

vi.mock('../core/mihomoApi', () => ({
  mihomoVersion: vi.fn(),
  mihomoHotReloadConfig: mocks.mihomoHotReloadConfig,
  patchMihomoConfig: mocks.patchMihomoConfig
}))

vi.mock('../core/dns', () => ({
  recoverDNS: mocks.recoverDNS
}))

vi.mock('../utils/logger', () => ({
  createLogger: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn() })
}))

describe('lid sleep', () => {
  beforeEach(() => {
    for (const key of Object.keys(handlers)) delete handlers[key]
    mocks.restartCore.mockReset()
    mocks.patchMihomoConfig.mockReset()
    mocks.recoverDNS.mockReset()
    mocks.mihomoHotReloadConfig.mockReset()
    mocks.handleSystemResume.mockReset()
    mocks.cancelSystemResumeReload.mockReset()
  })

  it('does not drop TUN or restore DNS when the lid sleeps', () => {
    expect(recoverAfterResume()).toEqual({
      keepRunning: true,
      dropTun: false,
      restoreSystemDNS: false,
      restartCore: false
    })
    expect(mocks.restartCore).not.toHaveBeenCalled()
    expect(mocks.patchMihomoConfig).not.toHaveBeenCalled()
    expect(mocks.mihomoHotReloadConfig).not.toHaveBeenCalled()
    expect(mocks.recoverDNS).not.toHaveBeenCalled()
  })

  it('keeps TUN up across suspend and resume', async () => {
    initResumeRecovery()
    handlers.suspend()
    await vi.waitFor(() => expect(mocks.cancelSystemResumeReload).toHaveBeenCalledTimes(1))
    expect(mocks.handleSystemResume).not.toHaveBeenCalled()
    handlers.resume()
    await vi.waitFor(() => expect(mocks.handleSystemResume).toHaveBeenCalledTimes(1))
    expect(mocks.restartCore).not.toHaveBeenCalled()
    expect(mocks.patchMihomoConfig).not.toHaveBeenCalled()
    expect(mocks.mihomoHotReloadConfig).not.toHaveBeenCalled()
    expect(mocks.recoverDNS).not.toHaveBeenCalled()
  })
})
