/**
 * Userspace macOS detector for a mihomo core stuck in the kernel.
 *
 * On 2026-11-19 the core held a kernel mutex, configd's IPConfigurationAgentQueue
 * stopped checking in, and the watchdog panicked after 180s (the first missed
 * check-in was 60s). This watch restarts only that core once the control API is
 * silent and the process is not making progress, on a threshold safely under 60s.
 * It then backs off so a core that is still stuck is not respawned in a loop.
 * System DNS stays 127.0.0.1 for the whole restart, so lookups fail closed.
 * Closing the lid is not a stall and is not a reason to drop TUN.
 */

export const CORE_STALL_THRESHOLD_MS = 20_000
export const CORE_STALL_BACKOFF_MS = 300_000
export const CORE_STALL_PROBE_INTERVAL_MS = 5_000
export const FAIL_CLOSED_SYSTEM_DNS = '127.0.0.1'

export const STUCK_CORE_RESTART = {
  forceStop: true,
  restoreSystemDNS: false,
  dropTun: false,
  systemDNS: FAIL_CLOSED_SYSTEM_DNS
} as const

export type LidSleepHold = {
  keepRunning: true
  dropTun: false
  restoreSystemDNS: false
  restartCore: false
}

export function shouldRestoreSystemDNS(forceStop: boolean, platform: NodeJS.Platform): boolean {
  return !forceStop && platform === 'darwin'
}

export function shouldRecoverDNSBeforeCoreStart(input: {
  hasCore: boolean
  skipStop: boolean
  forceStop: boolean
}): boolean {
  return !input.hasCore && !input.skipStop && !input.forceStop
}

export async function performStuckCoreRestart(deps: {
  restartCore: (forceStop: boolean) => Promise<void>
  restoreSystemDNS: () => Promise<void>
  disableTun: () => Promise<void>
}): Promise<typeof STUCK_CORE_RESTART> {
  if (STUCK_CORE_RESTART.restoreSystemDNS) await deps.restoreSystemDNS()
  if (STUCK_CORE_RESTART.dropTun) await deps.disableTun()
  await deps.restartCore(STUCK_CORE_RESTART.forceStop)
  return STUCK_CORE_RESTART
}

export type StallState = {
  unhealthySince: number | null
  baselineProgress: number | null
  backoffUntil: number | null
}

export type StallSample =
  { running: false } | { running: true; apiAnswered: boolean; progress: number | null }

export type StallDecision = {
  state: StallState
  restart: boolean
}

export function initialStallState(): StallState {
  return { unhealthySince: null, baselineProgress: null, backoffUntil: null }
}

export function noteLidSleep(state: StallState): StallState {
  return { ...state, unhealthySince: null, baselineProgress: null }
}

export function holdAcrossLidSleep(state: StallState): { hold: LidSleepHold; state: StallState } {
  return {
    hold: {
      keepRunning: true,
      dropTun: false,
      restoreSystemDNS: false,
      restartCore: false
    },
    state: noteLidSleep(state)
  }
}

export function reduceCoreStall(
  state: StallState,
  sample: StallSample,
  now: number
): StallDecision {
  if (state.backoffUntil !== null && now < state.backoffUntil) {
    return {
      restart: false,
      state: { ...state, unhealthySince: null, baselineProgress: null }
    }
  }
  if (!sample.running || sample.apiAnswered || sample.progress === null) {
    return {
      restart: false,
      state: { ...state, unhealthySince: null, baselineProgress: null }
    }
  }
  if (sample.progress !== state.baselineProgress || state.unhealthySince === null) {
    return {
      restart: false,
      state: {
        ...state,
        unhealthySince: now,
        baselineProgress: sample.progress
      }
    }
  }
  if (now - state.unhealthySince < CORE_STALL_THRESHOLD_MS) {
    return { restart: false, state: { ...state, baselineProgress: sample.progress } }
  }
  return {
    restart: true,
    state: {
      unhealthySince: null,
      baselineProgress: null,
      backoffUntil: now + CORE_STALL_BACKOFF_MS
    }
  }
}

/** macOS `ps -o time=` (`[h:]m:ss.cc`, minutes may exceed 59). Centiseconds, or null. */
export function parsePsCpuTime(raw: string): number | null {
  const match = raw.trim().match(/^(?:(\d+):)?(\d+):(\d{2})(?:\.(\d+))?$/)
  if (!match) return null
  const hours = match[1] === undefined ? 0 : Number(match[1])
  const minutes = Number(match[2])
  const seconds = Number(match[3])
  if (seconds >= 60 || (match[1] !== undefined && minutes >= 60)) return null
  const fraction = match[4] ?? ''
  const centiseconds = fraction.length === 0 ? 0 : Number((fraction + '00').slice(0, 2))
  if (![hours, minutes, seconds, centiseconds].every((value) => Number.isInteger(value)))
    return null
  return ((hours * 60 + minutes) * 60 + seconds) * 100 + centiseconds
}

export type CoreStallDeps = {
  now: () => number
  sample: () => Promise<StallSample>
  restart: () => Promise<void>
}

let lidSleepNotice: (() => void) | null = null

export function attachLidSleepNotice(notice: (() => void) | null): void {
  lidSleepNotice = notice
}

export function notifyLidSleep(): void {
  lidSleepNotice?.()
}

export function startCoreStallMonitor(platform: NodeJS.Platform, deps: CoreStallDeps): () => void {
  if (platform !== 'darwin') return () => {}

  let state = initialStallState()
  let stopped = false
  let timer: ReturnType<typeof setTimeout> | null = null
  let delay = 0

  const onSleep = (): void => {
    state = noteLidSleep(state)
  }
  attachLidSleepNotice(onSleep)

  const tick = async (): Promise<void> => {
    if (stopped) return
    let sample: StallSample
    try {
      sample = await deps.sample()
    } catch {
      return
    }
    if (stopped) return
    const decision = reduceCoreStall(state, sample, deps.now())
    state = decision.state
    if (!decision.restart) return
    try {
      await deps.restart()
    } catch {
      // Backoff was stored before this attempt, so a failed restart cannot loop.
    }
  }

  const arm = (): void => {
    if (stopped) return
    timer = setTimeout(() => {
      void tick().finally(arm)
    }, delay)
    delay = CORE_STALL_PROBE_INTERVAL_MS
    timer.unref?.()
  }
  arm()

  return () => {
    stopped = true
    if (timer) clearTimeout(timer)
    if (lidSleepNotice === onSleep) attachLidSleepNotice(null)
  }
}

/** Startup hook. Non-macOS returns before any probe, so Windows does not run or wait. */
export async function watchCoreStall(
  platform: NodeJS.Platform,
  deps: CoreStallDeps
): Promise<() => void> {
  if (platform !== 'darwin') return () => {}
  return startCoreStallMonitor(platform, deps)
}
