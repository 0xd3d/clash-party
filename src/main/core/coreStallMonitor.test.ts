import { describe, expect, it, vi } from 'vitest'
import { sampleInstalledCore } from './coreStallMonitor'

const mocks = vi.hoisted(() => ({
  getAxios: vi.fn(),
  execFile: vi.fn(),
  hasCoreProcess: vi.fn(() => true),
  getCurrentCorePID: vi.fn(() => 4242)
}))

vi.mock('child_process', () => ({
  execFile: mocks.execFile
}))

vi.mock('../utils/logger', () => ({
  createLogger: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn() })
}))

vi.mock('./mihomoApi', () => ({
  getAxios: mocks.getAxios
}))

vi.mock('./manager', () => ({
  hasCoreProcess: mocks.hasCoreProcess,
  getCurrentCorePID: mocks.getCurrentCorePID,
  restartCore: vi.fn()
}))

describe('installed core stall sample', () => {
  it('does not probe or wait on Windows', async () => {
    mocks.getAxios.mockReturnValue(new Promise(() => {}))
    mocks.execFile.mockImplementation(() => new Promise(() => {}))
    await expect(sampleInstalledCore('win32')).resolves.toEqual({ running: false })
    expect(mocks.getAxios).not.toHaveBeenCalled()
    expect(mocks.execFile).not.toHaveBeenCalled()
    expect(mocks.hasCoreProcess).not.toHaveBeenCalled()
  })
})
