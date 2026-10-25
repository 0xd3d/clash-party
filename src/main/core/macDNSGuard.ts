import { execFile } from 'child_process'
import { promisify } from 'util'

const execute = promisify(execFile)
export const macDNSGuardPath = '/Library/PrivilegedHelperTools/party.mihomo.dns-guard'

export type MacDNSGuardStatus = {
  active: boolean
  ownerUid: number
  corePid: number | null
  reason?: string
  protection?: 'traffic' | 'dns' | 'none'
  dnsLease?: boolean
  trafficLease?: boolean
  tunDevice?: string | null
}

export function parseMacDNSGuardStatus(raw: string, expectedUid: number): MacDNSGuardStatus {
  const value: unknown = JSON.parse(raw)
  if (!value || typeof value !== 'object') throw new Error('Invalid DNS guard response')
  const state = value as Record<string, unknown>
  if (
    typeof state.active !== 'boolean' ||
    state.ownerUid !== expectedUid ||
    !(
      state.corePid === null ||
      (Number.isSafeInteger(state.corePid) && Number(state.corePid) > 0)
    ) ||
    (state.reason !== undefined && typeof state.reason !== 'string') ||
    (state.dnsLease !== undefined && typeof state.dnsLease !== 'boolean') ||
    (state.trafficLease !== undefined && typeof state.trafficLease !== 'boolean') ||
    (state.protection !== undefined &&
      !['traffic', 'dns', 'none'].includes(String(state.protection)))
  )
    throw new Error('Invalid DNS guard identity or state')
  return {
    active: state.active,
    ownerUid: expectedUid,
    corePid: state.corePid as number | null,
    ...(state.protection !== undefined
      ? { protection: state.protection as MacDNSGuardStatus['protection'] }
      : {}),
    ...(typeof state.dnsLease === 'boolean' ? { dnsLease: state.dnsLease } : {}),
    ...(typeof state.trafficLease === 'boolean' ? { trafficLease: state.trafficLease } : {}),
    ...(typeof state.reason === 'string' ? { reason: state.reason.slice(0, 160) } : {})
  }
}

async function executeCommand(args: string[]): Promise<MacDNSGuardStatus> {
  if (process.platform !== 'darwin' || !process.getuid)
    throw new Error('macOS DNS guard is unavailable on this platform')
  try {
    const { stdout } = await execute(macDNSGuardPath, args, {
      timeout: args[0] === 'repair-core' ? 12000 : 6000,
      maxBuffer: 16 * 1024,
      encoding: 'utf8',
      // The native helper also constructs its own clean environment for fixed PF commands.
      env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C' }
    })
    return parseMacDNSGuardStatus(stdout, process.getuid())
  } catch (error) {
    if (
      error &&
      typeof error === 'object' &&
      'stdout' in error &&
      typeof error.stdout === 'string'
    ) {
      let reason: string | undefined
      try {
        reason = parseMacDNSGuardStatus(error.stdout, process.getuid()).reason
      } catch {
        /* Reject unknown output without reflecting it. */
      }
      if (reason) throw new Error(`Native DNS protection unconfirmed: ${reason}`, { cause: error })
    }
    throw error
  }
}

// Serialize start/stop so an in-flight startup cannot re-enable protection after normal exit.
let commandTail: Promise<unknown> = Promise.resolve()
function command(args: string[]): Promise<MacDNSGuardStatus> {
  const result = commandTail.then(() => executeCommand(args))
  commandTail = result.catch(() => undefined)
  return result
}

export async function acquireMacDNSGuard(corePid: number): Promise<MacDNSGuardStatus> {
  if (!Number.isSafeInteger(corePid) || corePid <= 0) throw new Error('Invalid core PID')
  const state = await command(['start', String(corePid)])
  if (!state.active || state.corePid !== corePid)
    throw new Error('DNS guard did not confirm this core')
  return state
}

export async function inspectMacDNSGuard(): Promise<MacDNSGuardStatus> {
  return command(['status'])
}

export async function releaseMacDNSGuard(): Promise<void> {
  const state = await command(['stop'])
  if (state.dnsLease === true || (state.dnsLease === undefined && state.active))
    throw new Error('DNS guard restoration remains pending')
}

export async function repairMacTrafficCores(): Promise<void> {
  await command(['repair-core'])
}
