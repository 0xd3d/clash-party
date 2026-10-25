import { afterEach, describe, expect, it, vi } from 'vitest'
import { shutdownProtectedCore } from './protectedShutdown'
afterEach(() => vi.useRealTimers())
describe('protected shutdown scheduling', () => {
  it('starts core termination before waiting for a slow guard release', async () => {
    const order: string[] = []
    let done!: () => void
    const pending = shutdownProtectedCore({
      restoreDNS: async () => {
        order.push('restore')
      },
      stopCore: async () => {
        order.push('stop')
      },
      releaseGuard: async () => {
        order.push('release')
        await new Promise<void>((r) => {
          done = r
        })
      },
      onError: vi.fn()
    })
    await vi.waitFor(() => expect(order).toEqual(['restore', 'stop', 'release']))
    done()
    await pending
  })
  it('still terminates the core when DNS recovery never resolves, retaining protection', async () => {
    vi.useFakeTimers()
    const stop = vi.fn().mockResolvedValue(undefined)
    const release = vi.fn()
    const pending = shutdownProtectedCore({
      restoreDNS: () => new Promise(() => {}),
      stopCore: stop,
      releaseGuard: release,
      onError: vi.fn(),
      recoveryGraceMs: 2000
    })
    await vi.advanceTimersByTimeAsync(2001)
    await pending
    expect(stop).toHaveBeenCalledOnce()
    expect(release).not.toHaveBeenCalled()
  })
  it('does not release the guard when DNS restore fails', async () => {
    const release = vi.fn()
    const stop = vi.fn().mockResolvedValue(undefined)
    await shutdownProtectedCore({
      restoreDNS: async () => {
        throw new Error('helper unavailable')
      },
      stopCore: stop,
      releaseGuard: release,
      onError: vi.fn()
    })
    expect(stop).toHaveBeenCalledOnce()
    expect(release).not.toHaveBeenCalled()
  })
})
