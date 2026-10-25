import { execFile, spawn } from 'node:child_process'
import { promisify } from 'node:util'
import path from 'node:path'
import { app } from 'electron'
import { macDNSGuardPath } from './macDNSGuard'

const execute = promisify(execFile)
export type NetworkGuardStatus = {
  active: boolean
  corePid: number | null
  coreAlive?: boolean
  guardPid?: number | null
  corePath?: string | null
  protection?: string
  trafficLease?: boolean
  tunDevice?: string | null
  tunName?: string | null
  reason?: string
  filterCount?: number
}
export interface NetworkGuardAdapter {
  arm(corePath: string, device: string): Promise<NetworkGuardStatus>
  bind(corePath: string, corePid: number, device: string): Promise<NetworkGuardStatus>
  inspect(): Promise<NetworkGuardStatus>
  release(): Promise<NetworkGuardStatus>
}

function windowsHelperPath(): string {
  return app.isPackaged
    ? path.join(process.resourcesPath, 'files', 'party.mihomo.network-guard.exe')
    : path.join(
        app.getAppPath(),
        'build',
        'native',
        'windows',
        process.arch,
        'party.mihomo.network-guard.exe'
      )
}

export function parseTrafficGuardStatus(
  raw: string,
  platform: NodeJS.Platform
): NetworkGuardStatus {
  const data: unknown = JSON.parse(raw)
  if (!data || typeof data !== 'object') throw new Error('Invalid network guard response')
  const value = data as Record<string, unknown>
  if (typeof value.error === 'string')
    throw new Error(`Network protection: ${value.error.slice(0, 160)}`)
  if (
    typeof value.active !== 'boolean' ||
    !(value.corePid === null || (Number.isSafeInteger(value.corePid) && Number(value.corePid) > 0))
  )
    throw new Error('Unconfirmed network guard identity/state')
  if (platform === 'win32') {
    if (value.protocolVersion !== 1 || typeof value.coreAlive !== 'boolean')
      throw new Error('Unconfirmed Windows guard protocol')
    if (
      !(
        value.guardPid === null ||
        (Number.isSafeInteger(value.guardPid) && Number(value.guardPid) > 0)
      ) ||
      !(value.corePath === null || typeof value.corePath === 'string') ||
      !Number.isSafeInteger(value.filterCount) ||
      Number(value.filterCount) < 0 ||
      (value.active && (!value.guardPid || !value.corePath || Number(value.filterCount) === 0))
    )
      throw new Error('Unconfirmed Windows filter ownership')
  }
  if (
    platform === 'darwin' &&
    (value.ownerUid !== process.getuid?.() || typeof value.trafficLease !== 'boolean')
  )
    throw new Error('Unconfirmed macOS traffic guard ownership')
  return value as NetworkGuardStatus
}

async function invoke(args: string[]): Promise<NetworkGuardStatus> {
  const helper = process.platform === 'win32' ? windowsHelperPath() : macDNSGuardPath
  try {
    const { stdout } = await execute(helper, args, {
      timeout: 12000,
      maxBuffer: 32 * 1024,
      encoding: 'utf8',
      windowsHide: true,
      ...(process.platform === 'darwin'
        ? { env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C' } }
        : {})
    })
    return parseTrafficGuardStatus(stdout, process.platform)
  } catch (error) {
    if (
      error &&
      typeof error === 'object' &&
      'stdout' in error &&
      typeof error.stdout === 'string'
    ) {
      let reason: string | undefined
      try {
        reason = parseTrafficGuardStatus(error.stdout, process.platform).reason
      } catch (parsed) {
        // Only reflect the fixed, validated native error protocol, never arbitrary process output.
        if (parsed instanceof Error && parsed.message.startsWith('Network protection: '))
          throw parsed
      }
      if (reason) throw new Error(`Network protection unconfirmed: ${reason.slice(0, 160)}`)
    }
    throw error
  }
}

const nativeAdapter: NetworkGuardAdapter = {
  async arm(corePath, device) {
    if (process.platform === 'darwin') return invoke(['traffic-arm', device, '--close-old-public'])
    let status = await invoke(['status'])
    if (status.guardPid === null) {
      const server = spawn(windowsHelperPath(), ['serve'], {
        detached: true,
        stdio: 'ignore',
        windowsHide: true
      })
      await new Promise<void>((resolve, reject) => {
        server.once('spawn', resolve)
        server.once('error', reject)
      })
      server.unref()
      const deadline = Date.now() + 5000
      for (;;) {
        try {
          status = await invoke(['arm', '--core-path', corePath, '--tun-name', device])
          break
        } catch (error) {
          if (Date.now() >= deadline) throw error
          await new Promise((resolve) => setTimeout(resolve, 100))
        }
      }
      return status
    }
    return invoke(['arm', '--core-path', corePath, '--tun-name', device])
  },
  async bind(corePath, corePid, device) {
    return process.platform === 'darwin'
      ? invoke(['traffic-start', String(corePid), device])
      : invoke([
          'acquire',
          '--core-path',
          corePath,
          '--core-pid',
          String(corePid),
          '--tun-name',
          device
        ])
  },
  async inspect() {
    return invoke([process.platform === 'darwin' ? 'traffic-status' : 'status'])
  },
  async release() {
    return invoke([process.platform === 'darwin' ? 'traffic-stop' : 'release'])
  }
}

/** Commands are ordered; a failed start/reload never removes a previous guard. */
export class NetworkGuardSession {
  private tail: Promise<unknown> = Promise.resolve()
  private generation = 0
  private requested = false
  constructor(private readonly adapter: NetworkGuardAdapter) {}
  private queue<T>(operation: () => Promise<T>): Promise<T> {
    const next = this.tail.then(operation)
    this.tail = next.catch(() => undefined)
    return next
  }
  get enabled(): boolean {
    return this.requested
  }
  arm(corePath: string, device: string): Promise<void> {
    const generation = ++this.generation
    this.requested = true
    return this.queue(async () => {
      if (generation !== this.generation) throw new Error('Network guard start was cancelled')
      this.requested = true
      const state = await this.adapter.arm(corePath, device)
      if (!state.active || state.trafficLease === false)
        throw new Error(state.reason || 'Network guard could not establish a blocking lease')
      if (generation !== this.generation) throw new Error('Network guard start was cancelled')
    })
  }
  bind(corePath: string, corePid: number, device: string): Promise<void> {
    const generation = this.generation
    return this.queue(async () => {
      if (!this.requested || generation !== this.generation)
        throw new Error('Network guard session changed')
      const state = await this.adapter.bind(corePath, corePid, device)
      if (
        !state.active ||
        state.corePid !== corePid ||
        (state.corePath != null &&
          path.win32.normalize(state.corePath).toLowerCase() !==
            path.win32.normalize(corePath).toLowerCase()) ||
        state.coreAlive === false ||
        state.trafficLease === false ||
        (state.tunName ?? state.tunDevice) !== device
      )
        throw new Error(state.reason || 'Network guard did not confirm the actual core and TUN')
      if (generation !== this.generation) throw new Error('Network guard session changed')
    })
  }
  inspect(): Promise<NetworkGuardStatus> {
    return this.queue(() => this.adapter.inspect())
  }
  release(): Promise<void> {
    const generation = ++this.generation
    return this.queue(async () => {
      const state = await this.adapter.release()
      if (state.trafficLease === true || (state.trafficLease === undefined && state.active))
        throw new Error('Network protection recovery remains incomplete')
      if (generation === this.generation) this.requested = false
    })
  }
}

const session = new NetworkGuardSession(nativeAdapter)
export function armNetworkGuard(runtime: Partial<IMihomoConfig>, corePath: string): Promise<void> {
  if (!['darwin', 'win32'].includes(process.platform))
    return Promise.reject(new Error('Network guard requires macOS or Windows'))
  const device = runtime.tun?.device?.trim()
  if (!device || runtime.tun?.enable !== true)
    return Promise.reject(new Error('Network guard requires a named, enabled virtual TUN'))
  return session.arm(corePath, device)
}
export async function bindNetworkGuard(
  runtime: Partial<IMihomoConfig>,
  corePath: string,
  corePid: number
): Promise<void> {
  const deadline = Date.now() + 6000
  for (;;) {
    try {
      await session.bind(corePath, corePid, runtime.tun?.device ?? '')
      return
    } catch (error) {
      if (Date.now() >= deadline) throw error
      await new Promise((resolve) => setTimeout(resolve, 100))
    }
  }
}
export function inspectNetworkGuard(): Promise<NetworkGuardStatus> {
  return session.inspect()
}
export async function releaseNetworkGuard(force = false): Promise<void> {
  if (session.enabled || force) await session.release()
}
