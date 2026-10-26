import { execFile } from 'child_process'
import { readFile } from 'fs/promises'
import { isIP } from 'net'
import path from 'path'
import { promisify } from 'util'
import axios from 'axios'
import { getAppConfig } from '../config'
import { dataDir } from '../utils/dirs'
import { createLogger } from '../utils/logger'
import { atomicWriteFile } from '../utils/safeFile'
import {
  SystemDNSController,
  type SystemDNSJournal,
  type SystemDNSService
} from './systemDNSController'
import { assertSystemDNSListener, getSystemDNSAddress, probeSystemDNS } from './systemDNSRuntime'
import { acquireMacDNSGuard, releaseMacDNSGuard } from './macDNSGuard'

const execFilePromise = promisify(execFile)
const logger = createLogger('SystemDNS')
const helperSocketPath = '/tmp/mihomo-party-helper.sock'
const journalPath = (): string => path.join(dataDir(), 'system-dns-state.json')
const emptyJournal = (): SystemDNSJournal => ({ version: 1, services: [] })

export async function getDefaultDevice(): Promise<string> {
  const { stdout } = await execFilePromise('/sbin/route', ['-n', 'get', 'default'])
  const device = stdout.match(/^\s*interface:\s*(\S+)/m)?.[1]
  if (!device) throw new Error('Get device failed')
  return device
}

export function parsePhysicalDNSServices(order: string): SystemDNSService[] {
  const services: SystemDNSService[] = []
  const blocks = order.matchAll(/^\(\d+\) (.+)\r?\n\(Hardware Port: .+?, Device: ([^)]+)\)/gm)
  for (const [, name, device] of blocks) {
    if (!name.startsWith('*') && /^(en\d+|bridge\d+)$/.test(device)) {
      services.push({ name, device })
    }
  }
  return services
}

async function listServices(): Promise<SystemDNSService[]> {
  const { stdout } = await execFilePromise('/usr/sbin/networksetup', ['-listnetworkserviceorder'], {
    timeout: 1000
  })
  return parsePhysicalDNSServices(stdout)
}

async function readDNS(service: SystemDNSService): Promise<string[]> {
  const { stdout } = await execFilePromise(
    '/usr/sbin/networksetup',
    ['-getdnsservers', service.name],
    { timeout: 500 }
  )
  if (stdout.startsWith("There aren't any DNS Servers set on")) return []
  const servers = stdout.trim().split(/\s+/)
  if (!servers.length || servers.some((server) => !isIP(server))) {
    throw new Error(`Cannot read original DNS for network service ${service.name}`)
  }
  return servers
}

async function writeDNS(
  service: SystemDNSService,
  servers: string[],
  options: { timeout?: number } = {}
): Promise<void> {
  if (servers.some((server) => !isIP(server))) throw new Error('Invalid system DNS address')
  await axios.post(
    'http://localhost/dns',
    { service: service.name, dns: servers.length ? servers.join(' ') : 'Empty' },
    { socketPath: helperSocketPath, timeout: options.timeout ?? 750 }
  )
}

async function readJournal(): Promise<SystemDNSJournal> {
  let value: unknown
  try {
    value = JSON.parse(await readFile(journalPath(), 'utf8'))
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return emptyJournal()
    throw error
  }
  const journal = value as SystemDNSJournal
  if (
    journal?.version !== 1 ||
    !Array.isArray(journal.services) ||
    journal.services.some(
      (entry) =>
        typeof entry.service?.name !== 'string' ||
        !/^(en\d+|bridge\d+)$/.test(entry.service.device) ||
        !Array.isArray(entry.original) ||
        !Array.isArray(entry.applied) ||
        entry.original.some((ip) => !isIP(ip)) ||
        entry.applied.some((ip) => !isIP(ip))
    )
  ) {
    throw new Error('System DNS recovery journal is invalid; retaining it for recovery')
  }
  return journal
}

const controller = new SystemDNSController({
  readJournal,
  writeJournal: (journal) =>
    atomicWriteFile(journalPath(), JSON.stringify(journal, null, 2), { mode: 0o600 }),
  listServices,
  readDNS,
  writeDNS
})

interface DNSSession {
  isCurrent: () => boolean
  runtime: IMihomoConfig
  corePid: number
  hasListenerProof: (address: string) => boolean
  generation: number
  signature: string | null
  busy: boolean
  lastError: string | null
  onReady: () => Promise<void>
  readyNotified: boolean
}

let session: DNSSession | null = null
let monitor: NodeJS.Timeout | null = null

export function stopSystemDNSMonitoring(): void {
  session = null
  if (monitor) clearInterval(monitor)
  monitor = null
  controller.cancel()
}

async function notifyReady(current: DNSSession): Promise<void> {
  if (current.readyNotified || session !== current || !current.isCurrent()) return
  await current.onReady()
  if (session === current && current.isCurrent()) current.readyNotified = true
}

async function synchronize(current: DNSSession): Promise<void> {
  if (current.busy || session !== current || !current.isCurrent()) return
  current.busy = true
  try {
    const config = await getAppConfig()
    if (session !== current || !current.isCurrent()) return
    const runtime = current.runtime
    if (config.autoSetDNS === false || !runtime.tun?.enable) {
      if (current.readyNotified && current.signature === null && current.lastError === null) return
      await controller.restore({ timeout: 750 })
      if (session !== current || !current.isCurrent() || current.runtime !== runtime) return
      await releaseMacDNSGuard()
      if (session !== current || !current.isCurrent() || current.runtime !== runtime) return
      current.generation = controller.beginSession()
      current.signature = null
      current.lastError = null
      await notifyReady(current)
      return
    }
    const address = getSystemDNSAddress(config)
    const restoreMode = config.systemDNSRestoreMode ?? 'original'
    const signature = JSON.stringify([address, restoreMode])
    assertSystemDNSListener(runtime, address)
    if (!current.hasListenerProof(address)) {
      throw new Error(`Core PID ${current.corePid} has not confirmed its local DNS listener`)
    }
    await probeSystemDNS(address)
    if (session !== current || !current.isCurrent() || current.runtime !== runtime) return
    if (!current.hasListenerProof(address)) return
    if (current.signature !== null && current.signature !== signature) {
      await controller.restore({ timeout: 750 })
      if (session !== current || !current.isCurrent() || current.runtime !== runtime) return
      current.generation = controller.beginSession()
    }
    if (!current.hasListenerProof(address)) return
    // Migrate regular system queries first so old external DNS states can expire.
    // If native filtering is unconfirmed, retain loopback DNS and its recovery journal.
    await controller.acquire(current.generation, [address], { restoreMode })
    if (session !== current || !current.isCurrent() || current.runtime !== runtime) return
    await acquireMacDNSGuard(current.corePid)
    if (session !== current || !current.isCurrent() || current.runtime !== runtime) return
    current.signature = signature
    current.lastError = null
    await notifyReady(current)
  } catch (error) {
    // A transient probe/network failure must never enable a router/public DNS fallback.
    const message = String(error)
    if (message !== current.lastError) logger.error('System DNS synchronization failed', error)
    current.lastError = message
  } finally {
    current.busy = false
  }
}

export function updateSystemDNSRuntime(runtime: IMihomoConfig, corePid: number | undefined): void {
  const current = session
  if (!current || current.corePid !== corePid || !current.isCurrent()) return
  current.runtime = structuredClone(runtime)
  // A confirmed application invalidates work that still uses an earlier runtime snapshot.
  current.generation = controller.beginSession()
}

export function patchSystemDNSRuntime(
  patch: Partial<IMihomoConfig>,
  corePid: number | undefined
): void {
  const current = session
  if (!current || !patch.tun) return
  // The caller supplies the complete applied TUN value; candidate DNS must never enter this snapshot.
  updateSystemDNSRuntime({ ...current.runtime, tun: patch.tun }, corePid)
}

export async function startSystemDNSMonitoring(
  isCurrent: () => boolean,
  appliedRuntime: IMihomoConfig,
  corePid: number,
  hasListenerProof: (address: string) => boolean,
  onReady: () => Promise<void> = async () => {}
): Promise<void> {
  if (process.platform !== 'darwin' || !isCurrent()) return
  stopSystemDNSMonitoring()
  const current: DNSSession = {
    isCurrent,
    runtime: structuredClone(appliedRuntime),
    corePid,
    hasListenerProof,
    generation: controller.beginSession(),
    signature: null,
    busy: false,
    lastError: null,
    onReady,
    readyNotified: false
  }
  session = current
  await synchronize(current)
  if (session !== current || !isCurrent()) return
  monitor = setInterval(() => void synchronize(current), 5000)
  monitor.unref()
}

/** Startup must not report protected readiness after a failed native guard or DNS takeover. */
export async function assertSystemDNSProtection(
  runtime: Partial<IMihomoConfig>,
  corePid: number,
  timeoutMs = 0
): Promise<void> {
  if (process.platform !== 'darwin' || runtime.tun?.enable !== true) return
  const config = await getAppConfig()
  if (config.autoSetDNS === false) return
  const deadline = Date.now() + Math.max(0, timeoutMs)
  while (true) {
    const current = session
    if (!current || current.corePid !== corePid || !current.isCurrent())
      throw new Error('Native DNS bypass protection or system DNS takeover is not ready')
    if (current.signature !== null && current.lastError === null && current.readyNotified) return
    if (Date.now() >= deadline)
      throw new Error('Native DNS bypass protection or system DNS takeover is not ready')
    // The existing monitor performs reconciliation. Only await its confirmation;
    // never declare success early or retry privileged operations in a tight loop.
    await new Promise<void>((resolve) => setTimeout(resolve, 100))
  }
}

export async function recoverDNS(
  options: { force?: boolean; timeout?: number; releaseGuard?: boolean } = {}
): Promise<void> {
  if (process.platform !== 'darwin') return
  stopSystemDNSMonitoring()
  await controller.restore({ timeout: options.timeout ?? 750 })
  if (options.releaseGuard) await releaseMacDNSGuard()
}
