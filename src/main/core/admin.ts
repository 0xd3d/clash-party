import { execFile, execFileSync } from 'child_process'
import { promisify } from 'util'
import i18next from 'i18next'
import { managerLogger } from '../utils/logger'
import {
  windowsTokenProbe,
  parseWindowsTokenElevation,
  WindowsElevationCache
} from './windowsTokenElevation'

const execute = promisify(execFile)
function probe(): { file: string; args: string[] } {
  return windowsTokenProbe(process.pid, process.env.SystemRoot || String.raw`C:\Windows`)
}
function probeReason(error: unknown): string {
  if (error && typeof error === 'object' && 'stdout' in error && typeof error.stdout === 'string') {
    try {
      parseWindowsTokenElevation(error.stdout, process.pid)
    } catch (parsed) {
      if (parsed instanceof Error && !(parsed instanceof SyntaxError)) return parsed.message
    }
  }
  return error instanceof Error ? error.message.slice(0, 512) : String(error).slice(0, 512)
}
const cache = new WindowsElevationCache(async () => {
  const command = probe()
  try {
    const { stdout } = await execute(command.file, command.args, {
      windowsHide: true,
      timeout: 10000,
      maxBuffer: 16 * 1024,
      encoding: 'utf8'
    })
    const elevated = parseWindowsTokenElevation(stdout, process.pid)
    managerLogger.info(`App process TokenElevation: pid=${process.pid}, elevated=${elevated}`)
    return elevated
  } catch (error) {
    const reason = probeReason(error)
    managerLogger.warn(
      'App token elevation check failed; result is unknown and will not be cached as non-admin',
      reason
    )
    throw new Error(
      i18next.t('tun.permissions.elevationUnconfirmed', {
        defaultValue:
          'Cannot read the Clash Party process token. Elevation is unconfirmed; retry and inspect the application log. Reason: {{reason}}',
        reason
      }),
      { cause: error }
    )
  }
})

export function primeAdminPrivilegesCache(value: boolean): void {
  cache.prime(value)
  managerLogger.info(`Admin privileges primed from process token: ${value}`)
}
export function getConfirmedAdminPrivileges(): boolean | null {
  return cache.confirmed
}

export function queryWindowsElevationSync(): boolean | null {
  if (process.platform !== 'win32') return false
  const command = probe()
  try {
    const stdout = execFileSync(command.file, command.args, {
      windowsHide: true,
      timeout: 2000,
      maxBuffer: 16 * 1024,
      encoding: 'utf8'
    })
    return parseWindowsTokenElevation(stdout, process.pid)
  } catch (error) {
    managerLogger.debug(
      'Early token check unconfirmed; deferring to asynchronous check',
      probeReason(error)
    )
    return null
  }
}
export async function checkAdminPrivileges(): Promise<boolean> {
  return process.platform === 'win32' ? cache.check() : true
}
