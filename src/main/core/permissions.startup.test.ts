import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
const mocks = vi.hoisted(() => ({ admin: vi.fn(), patch: vi.fn() }))
vi.mock('electron', () => ({ app: {}, dialog: {}, ipcMain: {} }))
vi.mock('../config', () => ({
  getAppConfig: vi.fn(),
  getControledMihomoConfig: vi.fn(),
  patchControledMihomoConfig: mocks.patch
}))
vi.mock('../utils/dirs', () => ({ mihomoCorePath: vi.fn(), mihomoCoreDir: vi.fn() }))
vi.mock('../utils/logger', () => ({
  managerLogger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() }
}))
vi.mock('../sys/autoRun', () => ({ checkAutoRun: vi.fn(), enableAutoRun: vi.fn() }))
vi.mock('../../shared/i18n', () => ({ default: { t: (key: string) => key } }))
vi.mock('./admin', () => ({
  checkAdminPrivileges: mocks.admin,
  getConfirmedAdminPrivileges: () => null
}))
import { requireWindowsTunPrivileges } from './permissions'
const descriptor = Object.getOwnPropertyDescriptor(process, 'platform') ?? {
  configurable: true,
  value: process.platform
}
beforeEach(() => {
  vi.clearAllMocks()
  Object.defineProperty(process, 'platform', { configurable: true, value: 'win32' })
})
afterEach(() => Object.defineProperty(process, 'platform', descriptor))
describe('protected Windows TUN startup', () => {
  it('rejects missing administrator rights without persisting a downgrade', async () => {
    mocks.admin.mockResolvedValue(false)
    await expect(requireWindowsTunPrivileges({ tun: { enable: true } })).rejects.toThrow(
      'tun.error.tunPermissionDenied'
    )
    expect(mocks.patch).not.toHaveBeenCalled()
  })
  it('allows a privileged protected configuration', async () => {
    mocks.admin.mockResolvedValue(true)
    await expect(requireWindowsTunPrivileges({ tun: { enable: true } })).resolves.toBeUndefined()
  })
  it('does not require elevation for intentional proxy-only mode', async () => {
    await requireWindowsTunPrivileges({ tun: { enable: false } })
    expect(mocks.admin).not.toHaveBeenCalled()
  })
  it('does not run a Windows privilege probe on macOS', async () => {
    Object.defineProperty(process, 'platform', { configurable: true, value: 'darwin' })
    await requireWindowsTunPrivileges({ tun: { enable: true } })
    expect(mocks.admin).not.toHaveBeenCalled()
  })
})
