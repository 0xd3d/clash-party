import { afterEach, describe, expect, it, vi } from 'vitest'
import { activateWindowsCoreProxy } from './startupProxy'
afterEach(() => vi.useRealTimers())

describe('Windows proxy activation after live core readiness', () => {
  it('activates on every successful start, including initial mode selection and retry', async () => {
    const read = vi.fn().mockResolvedValue({ tun: { enable: true } })
    const activate = vi.fn().mockResolvedValue(undefined)
    for (let attempt = 0; attempt < 2; attempt++)
      await activateWindowsCoreProxy('win32', { tun: { enable: true } }, read, () => true, activate)
    expect(read).toHaveBeenCalledTimes(2)
    expect(activate).toHaveBeenCalledTimes(2)
  })
  it('waits for Wintun after the controller is already ready', async () => {
    vi.useFakeTimers()
    const read = vi
      .fn()
      .mockResolvedValueOnce({ tun: { enable: false } })
      .mockResolvedValue({ tun: { enable: true } })
    const activate = vi.fn()
    const pending = activateWindowsCoreProxy(
      'win32',
      { tun: { enable: true } },
      read,
      () => true,
      activate
    )
    await vi.advanceTimersByTimeAsync(100)
    await pending
    expect(read).toHaveBeenCalledTimes(2)
    expect(activate).toHaveBeenCalledOnce()
  })
  it('does not activate a saved proxy after TUN remains disabled past the deadline', async () => {
    vi.useFakeTimers()
    const activate = vi.fn()
    const pending = expect(
      activateWindowsCoreProxy(
        'win32',
        { tun: { enable: true } },
        async () => ({ tun: { enable: false } }),
        () => true,
        activate
      )
    ).rejects.toThrow('not active')
    await vi.advanceTimersByTimeAsync(5100)
    await pending
    expect(activate).not.toHaveBeenCalled()
  })
  it('cancels a pending TUN readiness wait when the owning core changes', async () => {
    vi.useFakeTimers()
    const activate = vi.fn()
    let current = true
    const pending = expect(
      activateWindowsCoreProxy(
        'win32',
        { tun: { enable: true } },
        async () => ({ tun: { enable: false } }),
        () => current,
        activate
      )
    ).rejects.toThrow('changed')
    await vi.advanceTimersByTimeAsync(50)
    current = false
    await vi.advanceTimersByTimeAsync(100)
    await pending
    expect(activate).not.toHaveBeenCalled()
  })
  it('does not activate after an API failure or a replaced core', async () => {
    const activate = vi.fn()
    await expect(
      activateWindowsCoreProxy(
        'win32',
        {},
        async () => {
          throw new Error('timeout')
        },
        () => true,
        activate
      )
    ).rejects.toThrow('timeout')
    await expect(
      activateWindowsCoreProxy(
        'win32',
        {},
        async () => ({}),
        () => false,
        activate
      )
    ).rejects.toThrow('changed')
    expect(activate).not.toHaveBeenCalled()
  })
  it('leaves intentional proxy-only mode available', async () => {
    const activate = vi.fn()
    await activateWindowsCoreProxy(
      'win32',
      { tun: { enable: false } },
      async () => ({ tun: { enable: false } }),
      () => true,
      activate
    )
    expect(activate).toHaveBeenCalledOnce()
  })
  it('does not change the existing macOS startup path', async () => {
    const read = vi.fn()
    const activate = vi.fn()
    await activateWindowsCoreProxy('darwin', {}, read, () => true, activate)
    expect(read).not.toHaveBeenCalled()
    expect(activate).not.toHaveBeenCalled()
  })
})
