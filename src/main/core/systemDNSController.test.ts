import { describe, expect, it, vi } from 'vitest'
import {
  SystemDNSController,
  type SystemDNSJournal,
  type SystemDNSService
} from './systemDNSController'

const wifi: SystemDNSService = { name: 'Wi-Fi', device: 'en0' }
const ethernet: SystemDNSService = { name: 'USB Ethernet', device: 'en7' }
const target = ['127.0.0.1']

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void
  let reject!: (reason: unknown) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

function fixture(
  initial: Array<{ service: SystemDNSService; servers: string[] }> = [
    { service: wifi, servers: [] }
  ],
  saved: SystemDNSJournal = { version: 1, services: [] }
) {
  let journal = structuredClone(saved)
  let services = initial.map(({ service }) => structuredClone(service))
  const key = (service: SystemDNSService): string => `${service.name}/${service.device}`
  const dns = new Map(initial.map(({ service, servers }) => [key(service), [...servers]]))
  const events: string[] = []
  const deps = {
    readJournal: vi.fn(async () => structuredClone(journal)),
    writeJournal: vi.fn(async (next: SystemDNSJournal) => {
      journal = structuredClone(next)
      events.push(`journal:${journal.services.map(({ service }) => service.device).join(',')}`)
    }),
    listServices: vi.fn(async () => structuredClone(services)),
    readDNS: vi.fn(async (service: SystemDNSService) => {
      const servers = dns.get(key(service))
      if (!servers) throw new Error(`Service unavailable: ${service.name}`)
      return [...servers]
    }),
    writeDNS: vi.fn(
      async (service: SystemDNSService, servers: string[], _options?: { timeout?: number }) => {
        events.push(`dns:${service.device}:${servers.join(',')}`)
        dns.set(key(service), [...servers])
      }
    )
  }
  return {
    controller: new SystemDNSController(deps),
    deps,
    events,
    journal: () => structuredClone(journal),
    dns: (service: SystemDNSService) => dns.get(key(service)),
    setDNS: (service: SystemDNSService, servers: string[]) => dns.set(key(service), [...servers]),
    setServices: (next: SystemDNSService[]) => {
      services = structuredClone(next)
    }
  }
}

function ownedJournal(
  entries: Array<{ service: SystemDNSService; original: string[] }>
): SystemDNSJournal {
  return {
    version: 1,
    services: entries.map((entry) => ({ ...entry, applied: [...target] }))
  }
}

describe('SystemDNSController', () => {
  it('durably backs up and restores DHCP and multiple DNS addresses for each service', async () => {
    const original = ['192.0.2.53', '2001:db8::53']
    const state = fixture([
      { service: wifi, servers: [] },
      { service: ethernet, servers: original }
    ])

    await state.controller.acquire(state.controller.beginSession(), target)

    expect(state.events).toEqual([
      'journal:en0',
      'dns:en0:127.0.0.1',
      'journal:en0,en7',
      'dns:en7:127.0.0.1'
    ])
    expect(state.journal()).toEqual(
      ownedJournal([
        { service: wifi, original: [] },
        { service: ethernet, original }
      ])
    )

    await state.controller.restore()

    expect(state.dns(wifi)).toEqual([])
    expect(state.dns(ethernet)).toEqual(original)
    expect(state.journal()).toEqual({ version: 1, services: [] })
  })

  it('keeps the first backup while acquiring a newly discovered service', async () => {
    const state = fixture([{ service: wifi, servers: ['192.0.2.1'] }])
    const generation = state.controller.beginSession()
    await state.controller.acquire(generation, target)
    state.setServices([wifi, ethernet])
    state.setDNS(ethernet, ['192.0.2.2'])

    await state.controller.acquire(generation, target)

    expect(state.journal()).toEqual(
      ownedJournal([
        { service: wifi, original: ['192.0.2.1'] },
        { service: ethernet, original: ['192.0.2.2'] }
      ])
    )
    expect(state.deps.writeDNS).toHaveBeenCalledTimes(2)
    await state.controller.restore()
    expect(state.dns(wifi)).toEqual(['192.0.2.1'])
    expect(state.dns(ethernet)).toEqual(['192.0.2.2'])
  })

  it('does not modify system DNS when the backup cannot be persisted, and allows a retry', async () => {
    const state = fixture()
    const generation = state.controller.beginSession()
    state.deps.writeJournal.mockRejectedValueOnce(new Error('disk full'))

    await expect(state.controller.acquire(generation, target)).rejects.toThrow('disk full')
    expect(state.deps.writeDNS).not.toHaveBeenCalled()
    expect(state.journal().services).toEqual([])

    await state.controller.acquire(generation, target)
    expect(state.dns(wifi)).toEqual(target)
  })

  it('keeps durable backups after a partially successful apply and continues other services', async () => {
    const state = fixture([
      { service: wifi, servers: [] },
      { service: ethernet, servers: ['192.0.2.2'] }
    ])
    const writeDNS = state.deps.writeDNS.getMockImplementation()
    if (!writeDNS) throw new Error('Missing DNS write mock')
    state.deps.writeDNS.mockImplementationOnce(async (service, servers, options) => {
      await writeDNS(service, servers, options)
      throw new Error('helper disconnected after applying Wi-Fi DNS')
    })

    await expect(state.controller.acquire(state.controller.beginSession(), target)).rejects.toThrow(
      'helper disconnected'
    )
    expect(state.journal().services).toHaveLength(2)
    expect(state.dns(ethernet)).toEqual(target)

    await state.controller.restore()
    expect(state.dns(wifi)).toEqual([])
    expect(state.dns(ethernet)).toEqual(['192.0.2.2'])
    expect(state.journal().services).toEqual([])
  })

  it('retains failed restoration entries, durably clears successful ones, and retries', async () => {
    const state = fixture(
      [
        { service: wifi, servers: target },
        { service: ethernet, servers: target }
      ],
      ownedJournal([
        { service: wifi, original: [] },
        { service: ethernet, original: ['192.0.2.2'] }
      ])
    )
    state.deps.writeDNS.mockRejectedValueOnce(new Error('Wi-Fi restore failed'))

    await expect(state.controller.restore({ timeout: 750 })).rejects.toThrow('Wi-Fi restore failed')

    expect(state.journal()).toEqual(ownedJournal([{ service: wifi, original: [] }]))
    expect(state.dns(ethernet)).toEqual(['192.0.2.2'])
    expect(state.deps.writeDNS).toHaveBeenCalledWith(ethernet, ['192.0.2.2'], { timeout: 750 })

    await state.controller.restore()
    expect(state.dns(wifi)).toEqual([])
    expect(state.journal().services).toEqual([])
  })

  it('restores and persists other services while one restore is still pending and later rejects', async () => {
    const state = fixture(
      [
        { service: wifi, servers: target },
        { service: ethernet, servers: target }
      ],
      ownedJournal([
        { service: wifi, original: [] },
        { service: ethernet, original: ['192.0.2.2'] }
      ])
    )
    const pending = deferred<void>()
    const release = deferred<void>()
    const otherPersisted = deferred<void>()
    const writeJournal = state.deps.writeJournal.getMockImplementation()
    if (!writeJournal) throw new Error('Missing journal write mock')
    state.deps.writeDNS.mockImplementationOnce(async () => {
      pending.resolve()
      await release.promise
      throw new Error('delayed Wi-Fi failure')
    })
    state.deps.writeJournal.mockImplementation(async (journal) => {
      await writeJournal(journal)
      otherPersisted.resolve()
    })

    const restoration = state.controller.restore({ timeout: 750 })
    await pending.promise
    await otherPersisted.promise

    expect(state.dns(ethernet)).toEqual(['192.0.2.2'])
    expect(state.journal()).toEqual(ownedJournal([{ service: wifi, original: [] }]))
    release.resolve()
    await expect(restoration).rejects.toThrow('delayed Wi-Fi failure')
    expect(state.journal()).toEqual(ownedJournal([{ service: wifi, original: [] }]))
  })

  it('serializes durable removals when several parallel restores complete together', async () => {
    const thunderbolt: SystemDNSService = { name: 'Thunderbolt Ethernet', device: 'en8' }
    const state = fixture(
      [
        { service: wifi, servers: target },
        { service: ethernet, servers: target },
        { service: thunderbolt, servers: target }
      ],
      ownedJournal([
        { service: wifi, original: [] },
        { service: ethernet, original: ['192.0.2.2'] },
        { service: thunderbolt, original: ['192.0.2.3'] }
      ])
    )
    const persisting = deferred<void>()
    const release = deferred<void>()
    const writeJournal = state.deps.writeJournal.getMockImplementation()
    if (!writeJournal) throw new Error('Missing journal write mock')
    state.deps.writeJournal.mockImplementationOnce(async (journal) => {
      persisting.resolve()
      await release.promise
      await writeJournal(journal)
    })

    const restoration = state.controller.restore()
    await persisting.promise
    expect(state.deps.writeJournal).toHaveBeenCalledTimes(1)
    expect(state.deps.writeDNS).toHaveBeenCalledTimes(3)
    release.resolve()
    await restoration

    expect(state.deps.writeJournal.mock.calls.map(([journal]) => journal.services.length)).toEqual([
      2, 1, 0
    ])
    expect(state.journal().services).toEqual([])
    expect(state.dns(wifi)).toEqual([])
    expect(state.dns(ethernet)).toEqual(['192.0.2.2'])
    expect(state.dns(thunderbolt)).toEqual(['192.0.2.3'])
  })

  it('does not lose another service backup when persisting a successful restoration fails', async () => {
    const state = fixture(
      [
        { service: wifi, servers: target },
        { service: ethernet, servers: target }
      ],
      ownedJournal([
        { service: wifi, original: [] },
        { service: ethernet, original: ['192.0.2.2'] }
      ])
    )
    state.deps.writeJournal.mockRejectedValueOnce(new Error('journal write failed'))

    await expect(state.controller.restore()).rejects.toThrow('journal write failed')

    expect(state.journal()).toEqual(ownedJournal([{ service: wifi, original: [] }]))
    expect(state.dns(wifi)).toEqual([])
    expect(state.dns(ethernet)).toEqual(['192.0.2.2'])
    state.deps.writeDNS.mockClear()
    await state.controller.restore()
    expect(state.deps.writeDNS).not.toHaveBeenCalled()
    expect(state.journal().services).toEqual([])
  })

  it('retains a backup if the helper reports success but restoration cannot be verified', async () => {
    const saved = ownedJournal([{ service: wifi, original: [] }])
    const state = fixture([{ service: wifi, servers: target }], saved)
    state.deps.writeDNS.mockImplementationOnce(async () => {})

    await expect(state.controller.restore()).rejects.toThrow('could not be verified')

    expect(state.journal()).toEqual(saved)
  })

  it('verifies a successful helper response after takeover and retains an unverified backup', async () => {
    const state = fixture([
      { service: wifi, servers: [] },
      { service: ethernet, servers: ['192.0.2.2'] }
    ])
    state.deps.writeDNS.mockImplementationOnce(async () => {})

    await expect(state.controller.acquire(state.controller.beginSession(), target)).rejects.toThrow(
      'DNS takeover could not be verified for "Wi-Fi"'
    )

    expect(state.journal().services).toHaveLength(2)
    expect(state.dns(wifi)).toEqual([])
    expect(state.dns(ethernet)).toEqual(target)
    await state.controller.restore()
    expect(state.dns(ethernet)).toEqual(['192.0.2.2'])
    expect(state.journal().services).toEqual([])
  })

  it('retains unavailable services while still restoring the other services', async () => {
    const state = fixture(
      [{ service: ethernet, servers: target }],
      ownedJournal([
        { service: wifi, original: [] },
        { service: ethernet, original: ['192.0.2.2'] }
      ])
    )
    state.setServices([wifi, ethernet])

    await expect(state.controller.restore()).rejects.toThrow('Service unavailable: Wi-Fi')

    expect(state.journal()).toEqual(ownedJournal([{ service: wifi, original: [] }]))
    expect(state.dns(ethernet)).toEqual(['192.0.2.2'])
  })

  it.each([
    { change: 'deleted', replacement: null },
    { change: 'renamed', replacement: { name: 'Renamed Wi-Fi', device: 'en0' } },
    { change: 'same name with another device', replacement: { name: 'Wi-Fi', device: 'en9' } }
  ])(
    'retains the journal for a service that was $change without writing to it',
    async (testCase) => {
      const state = fixture(
        [
          { service: wifi, servers: target },
          { service: ethernet, servers: target }
        ],
        ownedJournal([
          { service: wifi, original: [] },
          { service: ethernet, original: ['192.0.2.2'] }
        ])
      )
      state.setServices(testCase.replacement ? [testCase.replacement, ethernet] : [ethernet])
      if (testCase.replacement) state.setDNS(testCase.replacement, target)

      await expect(state.controller.restore()).rejects.toThrow(
        'network service is missing or has changed identity'
      )

      expect(state.journal()).toEqual(ownedJournal([{ service: wifi, original: [] }]))
      expect(state.deps.readDNS.mock.calls.every(([service]) => service.name !== wifi.name)).toBe(
        true
      )
      expect(state.deps.writeDNS).toHaveBeenCalledTimes(1)
      expect(state.deps.writeDNS).toHaveBeenCalledWith(ethernet, ['192.0.2.2'], {})
      expect(state.dns(ethernet)).toEqual(['192.0.2.2'])
      if (testCase.replacement) expect(state.dns(testCase.replacement)).toEqual(target)
    }
  )

  it('preserves every backup and performs no DNS writes when service enumeration fails', async () => {
    const saved = ownedJournal([{ service: wifi, original: [] }])
    const state = fixture([{ service: wifi, servers: target }], saved)
    state.deps.listServices.mockRejectedValueOnce(new Error('Cannot enumerate network services'))

    await expect(state.controller.restore()).rejects.toThrow('Cannot enumerate network services')

    expect(state.journal()).toEqual(saved)
    expect(state.deps.readDNS).not.toHaveBeenCalled()
    expect(state.deps.writeDNS).not.toHaveBeenCalled()
    expect(state.deps.writeJournal).not.toHaveBeenCalled()
  })

  it('cancels after a delayed DNS read before backing up or applying anything', async () => {
    const state = fixture()
    const reading = deferred<void>()
    const result = deferred<string[]>()
    state.deps.readDNS.mockImplementationOnce(() => {
      reading.resolve()
      return result.promise
    })
    const acquisition = state.controller.acquire(state.controller.beginSession(), target)
    await reading.promise

    state.controller.cancel()
    result.resolve([])
    await acquisition

    expect(state.deps.writeJournal).not.toHaveBeenCalled()
    expect(state.deps.writeDNS).not.toHaveBeenCalled()
  })

  it('waits for a delayed durable backup, then restores without applying a cancelled generation', async () => {
    const state = fixture()
    const persisting = deferred<void>()
    const release = deferred<void>()
    const writeJournal = state.deps.writeJournal.getMockImplementation()
    if (!writeJournal) throw new Error('Missing journal write mock')
    state.deps.writeJournal.mockImplementationOnce(async (journal) => {
      persisting.resolve()
      await release.promise
      await writeJournal(journal)
    })
    const acquisition = state.controller.acquire(state.controller.beginSession(), target)
    await persisting.promise

    const restoration = state.controller.restore()
    release.resolve()
    await Promise.all([acquisition, restoration])

    expect(state.deps.writeDNS).not.toHaveBeenCalled()
    expect(state.journal().services).toEqual([])
  })

  it('makes restore a barrier for an in-flight apply and never applies later services after cancellation', async () => {
    const state = fixture([
      { service: wifi, servers: [] },
      { service: ethernet, servers: ['192.0.2.2'] }
    ])
    const applying = deferred<void>()
    const release = deferred<void>()
    const writeDNS = state.deps.writeDNS.getMockImplementation()
    if (!writeDNS) throw new Error('Missing DNS write mock')
    state.deps.writeDNS.mockImplementationOnce(async (service, servers, options) => {
      applying.resolve()
      await release.promise
      await writeDNS(service, servers, options)
    })
    const generation = state.controller.beginSession()
    const acquisition = state.controller.acquire(generation, target)
    await applying.promise

    const restoration = state.controller.restore()
    const staleAcquisition = state.controller.acquire(generation, target)
    expect(state.deps.readJournal).toHaveBeenCalledTimes(1)
    expect(state.deps.writeDNS).toHaveBeenCalledTimes(1)
    release.resolve()
    await Promise.all([acquisition, restoration, staleAcquisition])

    expect(
      state.deps.writeDNS.mock.calls.map(([service, servers]) => [service.device, servers])
    ).toEqual([
      ['en0', target],
      ['en0', []]
    ])
    expect(state.dns(wifi)).toEqual([])
    expect(state.dns(ethernet)).toEqual(['192.0.2.2'])
    expect(state.journal().services).toEqual([])
  })

  it('makes beginSession synchronously invalidate an earlier generation', async () => {
    const state = fixture()
    const first = state.controller.beginSession()
    const current = state.controller.beginSession()

    await state.controller.acquire(first, target)
    expect(state.deps.readJournal).not.toHaveBeenCalled()
    await state.controller.acquire(current, target)
    expect(state.dns(wifi)).toEqual(target)
  })

  it('respects a user DNS change during reconciliation and restoration', async () => {
    const state = fixture([{ service: wifi, servers: ['192.0.2.1'] }])
    const generation = state.controller.beginSession()
    await state.controller.acquire(generation, target)
    state.setDNS(wifi, ['198.51.100.53'])
    state.deps.writeDNS.mockClear()

    await state.controller.acquire(generation, target)
    await state.controller.restore()

    expect(state.deps.writeDNS).not.toHaveBeenCalled()
    expect(state.dns(wifi)).toEqual(['198.51.100.53'])
    expect(state.journal().services).toEqual([])
  })

  it.each([['127.0.0.1'], ['::1']])(
    'rejects original restoration when unjournaled DNS already uses loopback %s',
    async (server) => {
      const state = fixture([{ service: wifi, servers: [server] }])

      await expect(
        state.controller.acquire(state.controller.beginSession(), [server])
      ).rejects.toThrow('loopback DNS is already configured without an original DNS backup')

      expect(state.deps.writeJournal).not.toHaveBeenCalled()
      expect(state.deps.writeDNS).not.toHaveBeenCalled()
    }
  )

  it('explicitly records automatic restoration for existing loopback DNS', async () => {
    const state = fixture([{ service: wifi, servers: target }])

    await state.controller.acquire(state.controller.beginSession(), target, {
      restoreMode: 'automatic'
    })

    expect(state.journal()).toEqual(ownedJournal([{ service: wifi, original: [] }]))
    expect(state.deps.writeDNS).not.toHaveBeenCalled()
    await state.controller.restore()
    expect(state.dns(wifi)).toEqual([])
  })

  it('preserves an existing durable original even if a repeated acquire requests automatic mode', async () => {
    const saved = ownedJournal([{ service: wifi, original: ['192.0.2.1'] }])
    const state = fixture([{ service: wifi, servers: target }], saved)

    await state.controller.acquire(state.controller.beginSession(), target, {
      restoreMode: 'automatic'
    })

    expect(state.journal()).toEqual(saved)
    expect(state.deps.writeJournal).not.toHaveBeenCalled()
    await state.controller.restore()
    expect(state.dns(wifi)).toEqual(['192.0.2.1'])
  })

  it('requires restoring an existing session before changing its target', async () => {
    const saved = ownedJournal([{ service: wifi, original: [] }])
    const state = fixture([{ service: wifi, servers: target }], saved)

    await expect(
      state.controller.acquire(state.controller.beginSession(), ['::1'])
    ).rejects.toThrow('Restore the previous DNS session before changing the target')

    expect(state.journal()).toEqual(saved)
    expect(state.deps.writeDNS).not.toHaveBeenCalled()
  })
})
