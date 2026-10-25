import path from 'path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { SystemDNSJournal } from './systemDNSController'

const mocks = vi.hoisted(() => ({
  execFile: vi.fn(),
  acquireGuard: vi.fn(),
  releaseGuard: vi.fn(),
  readFile: vi.fn(),
  post: vi.fn(),
  getAppConfig: vi.fn(),
  getRuntimeConfig: vi.fn(),
  hasListenerProof: vi.fn(),
  atomicWriteFile: vi.fn(),
  assertSystemDNSListener: vi.fn(),
  probeSystemDNS: vi.fn(),
  logger: { error: vi.fn() }
}))

vi.mock('child_process', () => ({ execFile: mocks.execFile }))
vi.mock('fs/promises', () => ({ readFile: mocks.readFile }))
vi.mock('axios', () => ({ default: { post: mocks.post } }))
vi.mock('../config', () => ({ getAppConfig: mocks.getAppConfig }))
vi.mock('../utils/dirs', () => ({ dataDir: () => '/mock/system-dns' }))
vi.mock('../utils/logger', () => ({ createLogger: () => mocks.logger }))
vi.mock('../utils/safeFile', () => ({ atomicWriteFile: mocks.atomicWriteFile }))
vi.mock('./macDNSGuard', () => ({
  acquireMacDNSGuard: mocks.acquireGuard,
  releaseMacDNSGuard: mocks.releaseGuard
}))
vi.mock('./factory', () => ({ getRuntimeConfig: mocks.getRuntimeConfig }))
vi.mock('./systemDNSRuntime', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./systemDNSRuntime')>()
  return {
    ...actual,
    assertSystemDNSListener: mocks.assertSystemDNSListener,
    probeSystemDNS: mocks.probeSystemDNS
  }
})

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise
  })
  return { promise, resolve }
}

const platform = Object.getOwnPropertyDescriptor(process, 'platform') as PropertyDescriptor
const wifi = { name: 'Wi-Fi', device: 'en0' }
const ethernet = { name: 'USB Ethernet', device: 'en7' }
const serviceOrder = [
  'An asterisk (*) denotes that a network service is disabled.',
  '(1) Wi-Fi',
  '(Hardware Port: Wi-Fi, Device: en0)',
  '(2) USB Ethernet',
  '(Hardware Port: USB Ethernet, Device: en7)',
  '(3) VPN',
  '(Hardware Port: VPN, Device: utun3)'
].join('\n')
let dns: typeof import('./dns')
let config: Partial<IAppConfig>
let appliedRuntime: IMihomoConfig
const corePid = 4321
let journalText: string | undefined
let currentDNS: Map<string, string[]>
let events: string[]

function startMonitoring(isCurrent = () => true): Promise<void> {
  return dns.startSystemDNSMonitoring(isCurrent, appliedRuntime, corePid, mocks.hasListenerProof)
}

function journal(): SystemDNSJournal {
  return JSON.parse(journalText ?? '{"version":1,"services":[]}')
}

function applyHelper(body: { service: string; dns: string }): void {
  currentDNS.set(body.service, body.dns === 'Empty' ? [] : body.dns.split(' '))
  events.push(`dns:${body.service}:${body.dns}`)
}

beforeEach(async () => {
  vi.resetModules()
  vi.resetAllMocks()
  vi.useFakeTimers()
  Object.defineProperty(process, 'platform', { configurable: true, value: 'darwin' })
  config = { autoSetDNS: true }
  journalText = undefined
  currentDNS = new Map([
    [wifi.name, []],
    [ethernet.name, ['192.0.2.53', '2001:db8::53']]
  ])
  events = []
  mocks.getAppConfig.mockImplementation(async () => ({ ...config }))
  appliedRuntime = {
    tun: { enable: true },
    dns: { enable: true, listen: '127.0.0.1:53' }
  } as IMihomoConfig
  mocks.getRuntimeConfig.mockResolvedValue(appliedRuntime)
  const actualRuntime =
    await vi.importActual<typeof import('./systemDNSRuntime')>('./systemDNSRuntime')
  mocks.assertSystemDNSListener.mockImplementation(actualRuntime.assertSystemDNSListener)
  mocks.hasListenerProof.mockReturnValue(true)
  mocks.probeSystemDNS.mockResolvedValue(undefined)
  mocks.acquireGuard.mockResolvedValue({ active: true, ownerUid: 501, corePid })
  mocks.releaseGuard.mockResolvedValue(undefined)
  mocks.readFile.mockImplementation(async () => {
    if (journalText === undefined) throw Object.assign(new Error('missing'), { code: 'ENOENT' })
    return journalText
  })
  mocks.atomicWriteFile.mockImplementation(async (_file: string, value: string) => {
    journalText = value
    events.push(
      `journal:${journal()
        .services.map((entry) => entry.service.device)
        .join(',')}`
    )
  })
  mocks.execFile.mockImplementation(
    (
      file: string,
      args: string[],
      _options: unknown,
      callback: (error: Error | null, result?: { stdout: string; stderr: string }) => void
    ) => {
      if (file !== '/usr/sbin/networksetup') {
        callback(new Error(`Unexpected command: ${file}`))
        return
      }
      if (args[0] === '-listnetworkserviceorder') {
        callback(null, { stdout: serviceOrder, stderr: '' })
      } else if (args[0] === '-getdnsservers' && currentDNS.has(args[1])) {
        const servers = currentDNS.get(args[1]) ?? []
        callback(null, {
          stdout: servers.length
            ? servers.join('\n') + '\n'
            : `There aren't any DNS Servers set on ${args[1]}.\n`,
          stderr: ''
        })
      } else {
        callback(new Error(`Unexpected networksetup arguments: ${args.join(' ')}`))
      }
    }
  )
  mocks.post.mockImplementation(async (_url: string, body: { service: string; dns: string }) => {
    applyHelper(body)
  })
  dns = await import('./dns')
})

afterEach(() => {
  dns?.stopSystemDNSMonitoring()
  vi.useRealTimers()
  Object.defineProperty(process, 'platform', platform)
})

describe('system DNS integration', () => {
  it('selects enabled en and bridge services and excludes disabled services and VPN devices', () => {
    const order = [
      serviceOrder,
      '(4) Thunderbolt Bridge',
      '(Hardware Port: Thunderbolt Bridge, Device: bridge0)',
      '(*) Disabled Ethernet',
      '(Hardware Port: USB Ethernet, Device: en8)',
      '(5) *Disabled Wi-Fi',
      '(Hardware Port: Wi-Fi, Device: en9)',
      '(6) Loopback',
      '(Hardware Port: Loopback, Device: lo0)',
      '(7) VPN with physical-looking name',
      '(Hardware Port: VPN, Device: ppp0)'
    ].join('\r\n')

    expect(dns.parsePhysicalDNSServices(order)).toEqual([
      wifi,
      ethernet,
      { name: 'Thunderbolt Bridge', device: 'bridge0' }
    ])
  })

  it('does not acquire or start a timer after stopping while configuration is pending', async () => {
    const pendingConfig = deferred<Partial<IAppConfig>>()
    const requested = deferred<void>()
    mocks.getAppConfig.mockImplementationOnce(() => {
      requested.resolve()
      return pendingConfig.promise
    })
    const startup = startMonitoring()
    await requested.promise

    dns.stopSystemDNSMonitoring()
    pendingConfig.resolve({ autoSetDNS: true })
    await startup

    expect(mocks.probeSystemDNS).not.toHaveBeenCalled()
    expect(mocks.execFile).not.toHaveBeenCalled()
    expect(mocks.post).not.toHaveBeenCalled()
    expect(vi.getTimerCount()).toBe(0)
  })

  it('does not acquire or start a timer after stopping while readiness is pending', async () => {
    const pendingProbe = deferred<void>()
    const requested = deferred<void>()
    mocks.probeSystemDNS.mockImplementationOnce(() => {
      requested.resolve()
      return pendingProbe.promise
    })
    const startup = startMonitoring()
    await requested.promise

    dns.stopSystemDNSMonitoring()
    pendingProbe.resolve()
    await startup

    expect(mocks.execFile).not.toHaveBeenCalled()
    expect(mocks.atomicWriteFile).not.toHaveBeenCalled()
    expect(mocks.post).not.toHaveBeenCalled()
    expect(vi.getTimerCount()).toBe(0)
  })

  it('does not acquire when the owning core expires during readiness', async () => {
    const pendingProbe = deferred<void>()
    const requested = deferred<void>()
    let current = true
    mocks.probeSystemDNS.mockImplementationOnce(() => {
      requested.resolve()
      return pendingProbe.promise
    })
    const startup = startMonitoring(() => current)
    await requested.promise
    current = false
    pendingProbe.resolve()
    await startup

    expect(mocks.execFile).not.toHaveBeenCalled()
    expect(mocks.post).not.toHaveBeenCalled()
    expect(vi.getTimerCount()).toBe(0)
  })

  it.each(['listener', 'probe'])('never changes DNS when the %s is not ready', async (failure) => {
    if (failure === 'listener') {
      mocks.assertSystemDNSListener.mockImplementationOnce(() => {
        throw new Error('Wrong DNS listener')
      })
    } else {
      mocks.probeSystemDNS.mockRejectedValueOnce(new Error('Local TCP DNS readiness timed out'))
    }

    await startMonitoring()

    expect(mocks.execFile).not.toHaveBeenCalled()
    expect(mocks.atomicWriteFile).not.toHaveBeenCalled()
    expect(mocks.post).not.toHaveBeenCalled()
    expect(mocks.logger.error).toHaveBeenCalledOnce()
    await vi.advanceTimersByTimeAsync(5000)
    expect(mocks.post).toHaveBeenCalledTimes(2)
  })

  it('requires proof that the owning core bound its DNS listener before probing or acquiring', async () => {
    mocks.hasListenerProof.mockReturnValue(false)

    await startMonitoring()

    expect(mocks.hasListenerProof).toHaveBeenCalledWith('127.0.0.1')
    expect(mocks.probeSystemDNS).not.toHaveBeenCalled()
    expect(mocks.execFile).not.toHaveBeenCalled()
    expect(mocks.post).not.toHaveBeenCalled()
    mocks.hasListenerProof.mockReturnValue(true)
    await vi.advanceTimersByTimeAsync(5000)
    expect(mocks.post).toHaveBeenCalledTimes(2)
  })

  it('rechecks listener ownership after a pending readiness probe completes', async () => {
    const pendingProbe = deferred<void>()
    const requested = deferred<void>()
    mocks.probeSystemDNS.mockImplementationOnce(() => {
      requested.resolve()
      return pendingProbe.promise
    })
    const startup = startMonitoring()
    await requested.promise
    mocks.hasListenerProof.mockReturnValue(false)
    pendingProbe.resolve()
    await startup

    expect(mocks.execFile).not.toHaveBeenCalled()
    expect(mocks.post).not.toHaveBeenCalled()
  })

  it('ignores candidate factory runtime and mutations to the caller snapshot until a confirmed apply', async () => {
    await startMonitoring()
    appliedRuntime.tun.enable = false
    mocks.getRuntimeConfig.mockResolvedValue(appliedRuntime)

    await vi.advanceTimersByTimeAsync(5000)

    expect(mocks.getRuntimeConfig).not.toHaveBeenCalled()
    expect(mocks.post).toHaveBeenCalledTimes(2)
    expect(currentDNS.get(wifi.name)).toEqual(['127.0.0.1'])
    expect(journal().services).toHaveLength(2)
    expect(mocks.assertSystemDNSListener.mock.lastCall?.[0].tun.enable).toBe(true)
  })

  it('uses a cloned confirmed runtime update for the matching core PID', async () => {
    await startMonitoring()
    const confirmed = structuredClone(appliedRuntime)
    confirmed.tun.enable = false
    dns.updateSystemDNSRuntime(confirmed, corePid)
    confirmed.tun.enable = true

    await vi.advanceTimersByTimeAsync(5000)

    expect(currentDNS.get(wifi.name)).toEqual([])
    expect(currentDNS.get(ethernet.name)).toEqual(['192.0.2.53', '2001:db8::53'])
    expect(journal().services).toEqual([])
  })

  it.each([undefined, corePid - 1])(
    'ignores runtime updates from a nonmatching PID (%s)',
    async (pid) => {
      await startMonitoring()
      const staleRuntime = structuredClone(appliedRuntime)
      staleRuntime.tun.enable = false
      dns.updateSystemDNSRuntime(staleRuntime, pid)
      dns.patchSystemDNSRuntime({ tun: { enable: false } }, pid)

      await vi.advanceTimersByTimeAsync(5000)

      expect(mocks.post).toHaveBeenCalledTimes(2)
      expect(currentDNS.get(wifi.name)).toEqual(['127.0.0.1'])
      expect(journal().services).toHaveLength(2)
    }
  )

  it('patches only the complete applied TUN state and retains the confirmed DNS listener', async () => {
    appliedRuntime.tun.enable = false
    await startMonitoring()
    const patch = {
      tun: { enable: true },
      dns: { enable: false, listen: '192.0.2.53:53' }
    }
    dns.patchSystemDNSRuntime(patch, corePid)
    patch.tun.enable = false

    await vi.advanceTimersByTimeAsync(5000)

    expect(mocks.post).toHaveBeenCalledTimes(2)
    expect(mocks.assertSystemDNSListener.mock.lastCall?.[0].dns).toEqual({
      enable: true,
      listen: '127.0.0.1:53'
    })
    expect(mocks.assertSystemDNSListener.mock.lastCall?.[0].tun).toEqual({ enable: true })
  })

  it('does not create monitoring sessions from runtime update notifications', async () => {
    dns.updateSystemDNSRuntime(appliedRuntime, corePid)
    dns.patchSystemDNSRuntime({ tun: { enable: true } }, corePid)

    await vi.advanceTimersByTimeAsync(5000)

    expect(mocks.getAppConfig).not.toHaveBeenCalled()
    expect(mocks.post).not.toHaveBeenCalled()
    expect(vi.getTimerCount()).toBe(0)
  })

  it('ignores runtime notifications after the owning core has expired', async () => {
    let current = true
    await startMonitoring(() => current)
    current = false
    const staleRuntime = structuredClone(appliedRuntime)
    staleRuntime.tun.enable = false
    dns.updateSystemDNSRuntime(staleRuntime, corePid)
    dns.patchSystemDNSRuntime({ tun: { enable: false } }, corePid)
    current = true

    await vi.advanceTimersByTimeAsync(5000)

    expect(mocks.post).toHaveBeenCalledTimes(2)
    expect(currentDNS.get(wifi.name)).toEqual(['127.0.0.1'])
  })

  it('invalidates readiness work when a newer successful apply disables TUN', async () => {
    const pendingProbe = deferred<void>()
    const requested = deferred<void>()
    mocks.probeSystemDNS.mockImplementationOnce(() => {
      requested.resolve()
      return pendingProbe.promise
    })
    const startup = startMonitoring()
    await requested.promise

    dns.patchSystemDNSRuntime({ tun: { enable: false } }, corePid)
    pendingProbe.resolve()
    await startup
    await vi.advanceTimersByTimeAsync(5000)

    expect(mocks.post).not.toHaveBeenCalled()
    expect(mocks.atomicWriteFile).not.toHaveBeenCalled()
  })

  it('persists each original DNS before calling only the socket helper and restores both services', async () => {
    await startMonitoring()
    expect(mocks.logger.error.mock.calls).toEqual([])

    expect(events).toEqual([
      'journal:en0',
      'dns:Wi-Fi:127.0.0.1',
      'journal:en0,en7',
      'dns:USB Ethernet:127.0.0.1'
    ])
    expect(mocks.atomicWriteFile).toHaveBeenCalledWith(
      path.join('/mock/system-dns', 'system-dns-state.json'),
      expect.any(String),
      { mode: 0o600 }
    )
    expect(mocks.post).toHaveBeenCalledWith(
      'http://localhost/dns',
      { service: 'USB Ethernet', dns: '127.0.0.1' },
      { socketPath: '/tmp/mihomo-party-helper.sock', timeout: 750 }
    )
    expect(journal().services).toEqual([
      { service: wifi, original: [], applied: ['127.0.0.1'] },
      { service: ethernet, original: ['192.0.2.53', '2001:db8::53'], applied: ['127.0.0.1'] }
    ])

    await dns.recoverDNS({ force: true, timeout: 321 })

    expect(currentDNS.get(wifi.name)).toEqual([])
    expect(currentDNS.get(ethernet.name)).toEqual(['192.0.2.53', '2001:db8::53'])
    expect(journal().services).toEqual([])
    expect(mocks.post).toHaveBeenCalledWith(
      'http://localhost/dns',
      { service: 'USB Ethernet', dns: '192.0.2.53 2001:db8::53' },
      { socketPath: '/tmp/mihomo-party-helper.sock', timeout: 321 }
    )
    expect(mocks.execFile.mock.calls.every(([, args]) => args[0] !== '-setdnsservers')).toBe(true)
    expect(vi.getTimerCount()).toBe(0)
  })

  it('keeps the journal when the helper applies DNS but loses its response, then recovers it', async () => {
    mocks.post.mockImplementationOnce(
      async (_url: string, body: { service: string; dns: string }) => {
        applyHelper(body)
        throw new Error('Helper connection lost after apply')
      }
    )

    await startMonitoring()
    expect(currentDNS.get(wifi.name)).toEqual(['127.0.0.1'])
    expect(journal().services).toHaveLength(2)

    await dns.recoverDNS()
    expect(currentDNS.get(wifi.name)).toEqual([])
    expect(currentDNS.get(ethernet.name)).toEqual(['192.0.2.53', '2001:db8::53'])
    expect(journal().services).toEqual([])
  })

  it('makes recovery wait for an in-flight helper write and prevents later service takeover', async () => {
    const helperDone = deferred<void>()
    const helperStarted = deferred<void>()
    mocks.post.mockImplementationOnce((_url: string, body: { service: string; dns: string }) => {
      applyHelper(body)
      helperStarted.resolve()
      return helperDone.promise
    })
    const startup = startMonitoring()
    await helperStarted.promise

    const recovery = dns.recoverDNS()
    helperDone.resolve()
    await Promise.all([startup, recovery])

    expect(currentDNS.get(wifi.name)).toEqual([])
    expect(currentDNS.get(ethernet.name)).toEqual(['192.0.2.53', '2001:db8::53'])
    expect(events).toEqual(['journal:en0', 'dns:Wi-Fi:127.0.0.1', 'dns:Wi-Fi:Empty', 'journal:'])
    expect(journal().services).toEqual([])
    expect(vi.getTimerCount()).toBe(0)
  })

  it('restores DNS when takeover is disabled on the next synchronization', async () => {
    await startMonitoring()
    config.autoSetDNS = false

    await vi.advanceTimersByTimeAsync(5000)

    expect(currentDNS.get(wifi.name)).toEqual([])
    expect(currentDNS.get(ethernet.name)).toEqual(['192.0.2.53', '2001:db8::53'])
    expect(journal().services).toEqual([])
  })

  it('restores before applying a changed recovery mode and honors automatic restoration', async () => {
    await startMonitoring()
    config.systemDNSRestoreMode = 'automatic'

    await vi.advanceTimersByTimeAsync(5000)

    expect(journal().services.every((entry) => entry.original.length === 0)).toBe(true)
    expect(events.indexOf('dns:USB Ethernet:192.0.2.53 2001:db8::53')).toBeLessThan(
      events.lastIndexOf('dns:USB Ethernet:127.0.0.1')
    )
    await dns.recoverDNS()
    expect(currentDNS.get(ethernet.name)).toEqual([])
  })

  it('does not let a stopped disabled session invalidate its replacement after a delayed restore', async () => {
    config.autoSetDNS = false
    const pendingJournal = deferred<string>()
    const restoreStarted = deferred<void>()
    mocks.readFile.mockImplementationOnce(() => {
      restoreStarted.resolve()
      return pendingJournal.promise
    })
    const oldStartup = startMonitoring()
    await restoreStarted.promise
    dns.stopSystemDNSMonitoring()
    config.autoSetDNS = true
    const replacementProbed = deferred<void>()
    mocks.probeSystemDNS.mockImplementationOnce(async () => replacementProbed.resolve())
    const replacementStartup = startMonitoring()
    await replacementProbed.promise

    pendingJournal.resolve('{"version":1,"services":[]}')
    await Promise.all([oldStartup, replacementStartup])

    expect(mocks.post).toHaveBeenCalledTimes(2)
    expect(currentDNS.get(wifi.name)).toEqual(['127.0.0.1'])
    expect(vi.getTimerCount()).toBe(1)
  })

  it('retains invalid recovery journals and performs no DNS mutations', async () => {
    journalText = JSON.stringify({ version: 2, services: [] })

    await expect(dns.recoverDNS()).rejects.toThrow('recovery journal is invalid')

    expect(journalText).toBe('{"version":2,"services":[]}')
    expect(mocks.atomicWriteFile).not.toHaveBeenCalled()
    expect(mocks.post).not.toHaveBeenCalled()
  })
})

describe('system DNS platform boundary', () => {
  it.each(['win32', 'linux'] as const)('never invokes the macOS helper on %s', async (target) => {
    Object.defineProperty(process, 'platform', { configurable: true, value: target })
    await startMonitoring()
    await dns.recoverDNS({ force: true, timeout: 750 })
    expect(mocks.execFile).not.toHaveBeenCalled()
    expect(mocks.post).not.toHaveBeenCalled()
    expect(mocks.readFile).not.toHaveBeenCalled()
    expect(mocks.atomicWriteFile).not.toHaveBeenCalled()
    expect(vi.getTimerCount()).toBe(0)
  })
})

describe('native DNS bypass guard lifecycle', () => {
  it('retains loopback DNS while native filtering remains unconfirmed', async () => {
    mocks.acquireGuard.mockRejectedValue(new Error('helper unavailable'))
    await startMonitoring()
    expect(currentDNS.get(wifi.name)).toEqual(['127.0.0.1'])
    expect(journal().services).toHaveLength(2)
    expect(mocks.releaseGuard).not.toHaveBeenCalled()
  })
  it('retains protection through automatic recovery and releases only on explicit exit', async () => {
    await startMonitoring()
    await dns.recoverDNS()
    expect(mocks.releaseGuard).not.toHaveBeenCalled()
    await dns.recoverDNS({ releaseGuard: true })
    expect(mocks.releaseGuard).toHaveBeenCalledOnce()
  })
})

it('rejects protected startup when native guard activation failed', async () => {
  mocks.acquireGuard.mockRejectedValue(new Error('native tool unavailable'))
  await startMonitoring()
  await expect(dns.assertSystemDNSProtection(appliedRuntime, corePid)).rejects.toThrow('not ready')
})
it('confirms protected readiness only after both native guard and per-service DNS succeed', async () => {
  await startMonitoring()
  await expect(dns.assertSystemDNSProtection(appliedRuntime, corePid)).resolves.toBeUndefined()
  config.autoSetDNS = false
  await expect(dns.assertSystemDNSProtection(appliedRuntime, corePid)).resolves.toBeUndefined()
})

it('activates a deferred macOS proxy once after native protection eventually confirms', async () => {
  const ready = vi.fn().mockResolvedValue(undefined)
  mocks.acquireGuard.mockRejectedValueOnce(new Error('old external DNS state'))
  await dns.startSystemDNSMonitoring(
    () => true,
    appliedRuntime,
    corePid,
    mocks.hasListenerProof,
    ready
  )
  expect(ready).not.toHaveBeenCalled()
  await vi.advanceTimersByTimeAsync(5000)
  expect(ready).toHaveBeenCalledOnce()
  await vi.advanceTimersByTimeAsync(5000)
  expect(ready).toHaveBeenCalledOnce()
})

it('does not repeatedly invoke privileged recovery after an inactive session is reconciled', async () => {
  config.autoSetDNS = false
  await startMonitoring()
  expect(mocks.releaseGuard).toHaveBeenCalledOnce()
  await vi.advanceTimersByTimeAsync(15000)
  expect(mocks.releaseGuard).toHaveBeenCalledOnce()
})
