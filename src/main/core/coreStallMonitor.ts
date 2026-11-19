import { execFile } from 'child_process'
import { promisify } from 'util'
import { createLogger } from '../utils/logger'
import {
  parsePsCpuTime,
  performStuckCoreRestart,
  startCoreStallMonitor,
  type StallSample
} from './coreStall'
import { getAxios } from './mihomoApi'
import { getCurrentCorePID, hasCoreProcess, restartCore } from './manager'

const execFilePromise = promisify(execFile)
const stallLogger = createLogger('CoreStall')
const controlApiTimeoutMs = 1000
const progressTimeoutMs = 1000

async function controlApiAnswers(): Promise<boolean> {
  try {
    const api = await getAxios(false)
    await api.get('/version', { timeout: controlApiTimeoutMs })
    return true
  } catch {
    return false
  }
}

async function readCpuProgress(pid: number): Promise<number | null> {
  try {
    const { stdout } = await execFilePromise('/bin/ps', ['-p', String(pid), '-o', 'time='], {
      timeout: progressTimeoutMs
    })
    return parsePsCpuTime(stdout)
  } catch {
    return null
  }
}

export async function sampleInstalledCore(
  platform: NodeJS.Platform = process.platform
): Promise<StallSample> {
  if (platform !== 'darwin') return { running: false }
  if (!hasCoreProcess()) return { running: false }
  const pid = getCurrentCorePID()
  if (!pid) return { running: false }
  const [apiAnswered, progress] = await Promise.all([controlApiAnswers(), readCpuProgress(pid)])
  return { running: true, apiAnswered, progress }
}

export function startInstalledCoreStallMonitor(): void {
  startCoreStallMonitor(process.platform, {
    now: () => Date.now(),
    sample: () => sampleInstalledCore(process.platform),
    restart: async () => {
      const plan = await performStuckCoreRestart({
        restartCore,
        restoreSystemDNS: async () => {
          throw new Error('A stalled core restart must keep system DNS at 127.0.0.1')
        },
        disableTun: async () => {
          throw new Error('A stalled core restart must not drop TUN')
        }
      })
      stallLogger.warn(
        `Restarted a stalled mihomo core; system DNS stays ${plan.systemDNS} and TUN stays enabled`
      )
    }
  })
}
