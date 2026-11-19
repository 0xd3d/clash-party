import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  CORE_STALL_BACKOFF_MS,
  CORE_STALL_PROBE_INTERVAL_MS,
  CORE_STALL_THRESHOLD_MS,
  holdAcrossLidSleep,
  initialStallState,
  notifyLidSleep,
  parsePsCpuTime,
  performStuckCoreRestart,
  reduceCoreStall,
  shouldRecoverDNSBeforeCoreStart,
  shouldRestoreSystemDNS,
  startCoreStallMonitor,
  watchCoreStall,
  type StallSample
} from './coreStall'

afterEach(() => {
  vi.useRealTimers()
})

const frozen = (progress = 10): StallSample => ({
  running: true,
  apiAnswered: false,
  progress
})

describe('stalled mihomo core', () => {
  it('keeps the stall threshold safely under the 60s configd watchdog', () => {
    expect(CORE_STALL_THRESHOLD_MS).toBeGreaterThanOrEqual(5_000)
    expect(CORE_STALL_THRESHOLD_MS).toBeLessThan(60_000)
    expect(CORE_STALL_BACKOFF_MS).toBeGreaterThanOrEqual(CORE_STALL_THRESHOLD_MS * 10)
  })

  it('does not restore system DNS or drop TUN when restarting the core', async () => {
    const restoreSystemDNS = vi.fn()
    const disableTun = vi.fn()
    const restartCore = vi.fn().mockResolvedValue(undefined)
    await expect(
      performStuckCoreRestart({ restartCore, restoreSystemDNS, disableTun })
    ).resolves.toEqual({
      forceStop: true,
      restoreSystemDNS: false,
      dropTun: false,
      systemDNS: '127.0.0.1'
    })
    expect(restartCore).toHaveBeenCalledExactlyOnceWith(true)
    expect(restoreSystemDNS).not.toHaveBeenCalled()
    expect(disableTun).not.toHaveBeenCalled()
    expect(shouldRestoreSystemDNS(true, 'darwin')).toBe(false)
    expect(shouldRestoreSystemDNS(true, 'win32')).toBe(false)
    expect(
      shouldRecoverDNSBeforeCoreStart({ hasCore: true, skipStop: false, forceStop: true })
    ).toBe(false)
    expect(
      shouldRecoverDNSBeforeCoreStart({ hasCore: false, skipStop: false, forceStop: true })
    ).toBe(false)
  })

  it('restarts only after the API is silent and progress is frozen for the threshold', () => {
    let state = initialStallState()
    const started = reduceCoreStall(state, frozen(), 0)
    expect(started.restart).toBe(false)
    state = started.state
    const early = reduceCoreStall(state, frozen(), CORE_STALL_THRESHOLD_MS - 1)
    expect(early.restart).toBe(false)
    const due = reduceCoreStall(early.state, frozen(), CORE_STALL_THRESHOLD_MS)
    expect(due.restart).toBe(true)

    let moving = initialStallState()
    for (let step = 0; step <= 6; step += 1) {
      const decision = reduceCoreStall(moving, frozen(step), step * CORE_STALL_THRESHOLD_MS)
      expect(decision.restart).toBe(false)
      moving = decision.state
    }
    const answering = reduceCoreStall(
      early.state,
      { running: true, apiAnswered: true, progress: 10 },
      60_000
    )
    expect(answering.restart).toBe(false)
    const stopped = reduceCoreStall(early.state, { running: false }, 60_000)
    expect(stopped.restart).toBe(false)
    const unknown = reduceCoreStall(
      early.state,
      { running: true, apiAnswered: false, progress: null },
      60_000
    )
    expect(unknown.restart).toBe(false)
  })

  it('does not respawn a still-stuck core in a tight loop', () => {
    const first = reduceCoreStall(
      reduceCoreStall(initialStallState(), frozen(), 0).state,
      frozen(),
      CORE_STALL_THRESHOLD_MS
    )
    expect(first.restart).toBe(true)
    let state = first.state
    for (let step = 1; step <= 12; step += 1) {
      const decision = reduceCoreStall(state, frozen(), CORE_STALL_THRESHOLD_MS + step * 1_000)
      expect(decision.restart).toBe(false)
      state = decision.state
    }
    const stillInsideBackoff = reduceCoreStall(
      state,
      frozen(),
      CORE_STALL_THRESHOLD_MS + CORE_STALL_BACKOFF_MS - 1
    )
    expect(stillInsideBackoff.restart).toBe(false)
  })

  it('does not treat lid sleep as a stall or a reason to drop TUN', () => {
    const almost = reduceCoreStall(
      reduceCoreStall(initialStallState(), frozen(), 0).state,
      frozen(),
      CORE_STALL_THRESHOLD_MS - 1
    )
    expect(almost.restart).toBe(false)
    const slept = holdAcrossLidSleep(almost.state)
    expect(slept.hold).toEqual({
      keepRunning: true,
      dropTun: false,
      restoreSystemDNS: false,
      restartCore: false
    })
    const woke = reduceCoreStall(slept.state, frozen(), CORE_STALL_THRESHOLD_MS + 10 * 60_000)
    expect(woke.restart).toBe(false)
  })

  it('does not run or wait on Windows', async () => {
    let sampled = false
    let restarted = false
    const hanging = new Promise<StallSample>(() => {})
    const watched = watchCoreStall('win32', {
      now: () => 0,
      sample: () => {
        sampled = true
        return hanging
      },
      restart: () => {
        restarted = true
        return hanging.then(() => undefined)
      }
    })
    await expect(watched).resolves.toEqual(expect.any(Function))
    expect(sampled).toBe(false)
    expect(restarted).toBe(false)
    const stop = startCoreStallMonitor('win32', {
      now: () => 0,
      sample: () => {
        sampled = true
        return hanging
      },
      restart: () => {
        restarted = true
        return hanging.then(() => undefined)
      }
    })
    stop()
    expect(sampled).toBe(false)
    expect(restarted).toBe(false)
  })
})

describe('macOS stall monitor', () => {
  it('restarts once after the threshold and ignores a sleeping lid', async () => {
    vi.useFakeTimers()
    const restarts: number[] = []
    const origin = Date.now()
    const stop = startCoreStallMonitor('darwin', {
      now: () => Date.now(),
      sample: async () => frozen(),
      restart: async () => {
        restarts.push(Date.now() - origin)
      }
    })

    await vi.advanceTimersByTimeAsync(0)
    expect(restarts).toEqual([])
    await vi.advanceTimersByTimeAsync(CORE_STALL_THRESHOLD_MS - 1)
    expect(restarts).toEqual([])
    notifyLidSleep()
    await vi.advanceTimersByTimeAsync(CORE_STALL_PROBE_INTERVAL_MS)
    expect(restarts).toEqual([])
    await vi.advanceTimersByTimeAsync(CORE_STALL_THRESHOLD_MS)
    expect(restarts).toHaveLength(1)
    expect(restarts[0]).toBeGreaterThan(CORE_STALL_THRESHOLD_MS)
    expect(restarts[0]).toBeLessThan(60_000)
    await vi.advanceTimersByTimeAsync(CORE_STALL_THRESHOLD_MS * 3)
    expect(restarts).toHaveLength(1)
    stop()
  })
})

describe('parsePsCpuTime', () => {
  it('reads macOS ps CPU time', () => {
    expect(parsePsCpuTime('  0:00.03\n')).toBe(3)
    expect(parsePsCpuTime('48:28.59')).toBe((48 * 60 + 28) * 100 + 59)
    expect(parsePsCpuTime('1:02:03.04')).toBe(((1 * 60 + 2) * 60 + 3) * 100 + 4)
    expect(parsePsCpuTime('nope')).toBeNull()
    expect(parsePsCpuTime('1:02:60.00')).toBeNull()
  })
})
