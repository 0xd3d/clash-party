import { powerMonitor } from 'electron'
import {
  holdAcrossLidSleep,
  initialStallState,
  notifyLidSleep,
  type LidSleepHold
} from '../core/coreStall'
import { createLogger } from '../utils/logger'

const resumeLogger = createLogger('Resume')

/**
 * Lid close and system sleep keep the machine running. They do not drop TUN,
 * do not restart mihomo, and do not restore system DNS to the router.
 * A core that is actually stuck is handled by the macOS stall monitor.
 */
export function recoverAfterResume(): LidSleepHold {
  const { hold } = holdAcrossLidSleep(initialStallState())
  notifyLidSleep()
  return hold
}

export function initResumeRecovery(): void {
  powerMonitor.on('suspend', () => {
    resumeLogger.info('System sleep or lid close: keeping TUN up and leaving DNS fail-closed')
    recoverAfterResume()
  })
  powerMonitor.on('resume', () => {
    resumeLogger.info('System resumed: keeping TUN up and leaving DNS fail-closed')
    recoverAfterResume()
  })
}
