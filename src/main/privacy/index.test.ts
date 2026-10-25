import path from 'path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { exportWebRTCGuard, inspectPrivacyProtection } from './index'

const mocks = vi.hoisted(() => ({
  access: vi.fn(),
  cp: vi.fn(),
  mkdir: vi.fn(),
  showOpenDialog: vi.fn(),
  getAppConfig: vi.fn(),
  getAppliedCoreConfig: vi.fn(),
  getCurrentCorePID: vi.fn(),
  getAppliedCoreRevision: vi.fn(),
  get: vi.fn(),
  auditPrivacyConfig: vi.fn(),
  app: { isPackaged: false, getAppPath: () => '/mock/repository' }
}))
vi.mock('fs/promises', () => ({ access: mocks.access, cp: mocks.cp, mkdir: mocks.mkdir }))
vi.mock('electron', () => ({ app: mocks.app, dialog: { showOpenDialog: mocks.showOpenDialog } }))
vi.mock('../config', () => ({ getAppConfig: mocks.getAppConfig }))
vi.mock('../core/manager', () => ({
  getAppliedCoreConfig: mocks.getAppliedCoreConfig,
  getCurrentCorePID: mocks.getCurrentCorePID,
  getAppliedCoreRevision: mocks.getAppliedCoreRevision
}))
vi.mock('../core/mihomoApi', () => ({ getAxios: async () => ({ get: mocks.get }) }))
vi.mock('../../shared/privacyAudit', () => ({ auditPrivacyConfig: mocks.auditPrivacyConfig }))

const resourcesPathDescriptor = Object.getOwnPropertyDescriptor(process, 'resourcesPath')
afterEach(() => {
  if (resourcesPathDescriptor)
    Object.defineProperty(process, 'resourcesPath', resourcesPathDescriptor)
  else Reflect.deleteProperty(process, 'resourcesPath')
})

beforeEach(() => {
  vi.resetAllMocks()
  Object.defineProperty(process, 'resourcesPath', {
    configurable: true,
    value: '/mock/bundle/resources'
  })
  mocks.app.isPackaged = false
  mocks.getCurrentCorePID.mockReturnValue(1234)
  mocks.getAppliedCoreRevision.mockReturnValue(1)
  mocks.getAppConfig.mockResolvedValue({ autoSetDNS: true })
  mocks.getAppliedCoreConfig.mockReturnValue({
    dns: { nameserver: ['https://dns.example.test#Proxy'] }
  })
  mocks.get.mockResolvedValue({ tun: { enable: true }, ipv6: true, 'allow-lan': false })
  mocks.auditPrivacyConfig.mockReturnValue([{ id: 'scope', level: 'info' }])
  mocks.access.mockResolvedValue(undefined)
  mocks.mkdir.mockResolvedValue(undefined)
  mocks.cp.mockResolvedValue(undefined)
})

describe('privacy inspection boundary', () => {
  it('uses confirmed DNS policy and live general/TUN state, and returns only findings', async () => {
    const result = await inspectPrivacyProtection()
    expect(mocks.auditPrivacyConfig).toHaveBeenCalledWith(
      expect.objectContaining({
        dns: { nameserver: ['https://dns.example.test#Proxy'] },
        tun: { enable: true },
        'allow-lan': false
      }),
      process.platform,
      { autoSetDNS: true }
    )
    expect(result.source).toBe('applied')
    expect(result).not.toHaveProperty('dns')
    expect(result).not.toHaveProperty('proxies')
  })

  it('does not inspect a candidate when there is no applied core', async () => {
    mocks.getAppliedCoreConfig.mockReturnValue(null)
    expect((await inspectPrivacyProtection()).source).toBe('unavailable')
    expect(mocks.get).not.toHaveBeenCalled()
    expect(mocks.auditPrivacyConfig).not.toHaveBeenCalled()
  })

  it('rejects a report spanning a core restart', async () => {
    mocks.getCurrentCorePID.mockReturnValueOnce(1234).mockReturnValue(5678)
    expect((await inspectPrivacyProtection()).source).toBe('unavailable')
    expect(mocks.auditPrivacyConfig).not.toHaveBeenCalled()
  })

  it('rejects a report spanning a hot reload with the same core PID', async () => {
    mocks.getAppliedCoreRevision.mockReturnValueOnce(1).mockReturnValue(2)
    expect((await inspectPrivacyProtection()).source).toBe('unavailable')
    expect(mocks.auditPrivacyConfig).not.toHaveBeenCalled()
  })

  it('does not call unavailable runtime checks a successful leak measurement', async () => {
    mocks.get.mockRejectedValue(new Error('core unavailable'))
    const result = await inspectPrivacyProtection()
    expect(result).toMatchObject({
      source: 'unavailable',
      findings: [{ id: 'runtimeUnavailable', level: 'warning' }]
    })
  })
})

describe('optional WebRTC tool export', () => {
  it('cancellation never writes a directory', async () => {
    mocks.showOpenDialog.mockResolvedValue({ canceled: true, filePaths: [] })
    expect(await exportWebRTCGuard()).toBeNull()
    expect(mocks.mkdir).not.toHaveBeenCalled()
    expect(mocks.cp).not.toHaveBeenCalled()
  })

  it('exports source assets without modifying a browser profile or policy', async () => {
    mocks.showOpenDialog.mockResolvedValue({ canceled: false, filePaths: ['/mock/selected'] })
    const destination = path.join('/mock/selected', 'ClashParty-WebRTC-Guard')
    expect(await exportWebRTCGuard()).toBe(destination)
    expect(mocks.cp).toHaveBeenCalledWith(
      path.join('/mock/repository', 'integrations', 'webrtc-guard'),
      destination,
      expect.objectContaining({ recursive: true, force: false, errorOnExist: true })
    )
    const filter = mocks.cp.mock.calls[0][2].filter as (file: string) => boolean
    expect(filter('controller.mjs')).toBe(true)
    expect(filter('controller.d.mts')).toBe(false)
    expect(filter('controller.d.ts')).toBe(false)
  })

  it('never overwrites an existing export directory', async () => {
    mocks.showOpenDialog.mockResolvedValue({ canceled: false, filePaths: ['/mock/selected'] })
    mocks.mkdir.mockRejectedValue(Object.assign(new Error('exists'), { code: 'EEXIST' }))
    await expect(exportWebRTCGuard()).rejects.toMatchObject({ code: 'EEXIST' })
    expect(mocks.cp).not.toHaveBeenCalled()
  })

  it('packaged builds read bundled resources instead of the source tree', async () => {
    mocks.app.isPackaged = true
    mocks.showOpenDialog.mockResolvedValue({ canceled: true, filePaths: [] })
    await exportWebRTCGuard()
    expect(mocks.access).toHaveBeenCalledWith(
      path.join(process.resourcesPath, 'integrations', 'webrtc-guard', 'manifest.json')
    )
  })
})
