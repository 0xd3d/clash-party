export interface SystemDNSService {
  name: string
  device: string
}

export interface SystemDNSJournal {
  version: 1
  services: Array<{
    service: SystemDNSService
    original: string[]
    applied: string[]
  }>
}

interface SystemDNSDependencies {
  readJournal(): Promise<SystemDNSJournal>
  writeJournal(journal: SystemDNSJournal): Promise<void>
  listServices(): Promise<SystemDNSService[]>
  readDNS(service: SystemDNSService): Promise<string[]>
  writeDNS(
    service: SystemDNSService,
    servers: string[],
    options?: { timeout?: number }
  ): Promise<void>
}

function sameService(left: SystemDNSService, right: SystemDNSService): boolean {
  return left.name === right.name && left.device === right.device
}

function sameDNS(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((server, index) => server === right[index])
}

function cloneJournal(journal: SystemDNSJournal): SystemDNSJournal {
  return {
    version: 1,
    services: journal.services.map((entry) => ({
      service: { ...entry.service },
      original: [...entry.original],
      applied: [...entry.applied]
    }))
  }
}

function isLoopbackTarget(servers: string[]): boolean {
  return (
    servers.length > 0 &&
    servers.every(
      (server) => server.startsWith('127.') || server === '::1' || server === '0:0:0:0:0:0:0:1'
    )
  )
}

function failureMessage(failures: unknown[]): string {
  return failures
    .map((error) => (error instanceof Error ? error.message : String(error)))
    .join('; ')
}

/** Owns DNS mutations, while the caller owns core readiness and service discovery. */
export class SystemDNSController {
  private generation = 0
  private queue: Promise<void> = Promise.resolve()

  constructor(private readonly deps: SystemDNSDependencies) {}

  beginSession(): number {
    return ++this.generation
  }

  cancel(): void {
    ++this.generation
  }

  private enqueue(operation: () => Promise<void>): Promise<void> {
    const current = this.queue.then(operation)
    this.queue = current.catch(() => {})
    return current
  }

  acquire(
    generation: number,
    target: string[],
    options: { restoreMode?: 'original' | 'automatic' } = {}
  ): Promise<void> {
    const applied = [...target]
    const restoreMode = options.restoreMode ?? 'original'
    const isCurrent = (): boolean => generation === this.generation

    return this.enqueue(async () => {
      if (!isCurrent()) return
      let journal = cloneJournal(await this.deps.readJournal())
      if (!isCurrent()) return
      const services = await this.deps.listServices()
      if (!isCurrent()) return
      const failures: unknown[] = []

      for (const discoveredService of services) {
        if (!isCurrent()) return
        const service = { ...discoveredService }
        let current: string[]
        try {
          current = await this.deps.readDNS(service)
        } catch (error) {
          if (!isCurrent()) return
          failures.push(error)
          continue
        }
        if (!isCurrent()) return

        const existing = journal.services.find((entry) => sameService(entry.service, service))
        if (existing && !sameDNS(existing.applied, applied)) {
          failures.push(
            new Error(
              `Restore the previous DNS session before changing the target for "${service.name}"`
            )
          )
          continue
        }
        if (
          existing &&
          !sameDNS(current, existing.applied) &&
          !sameDNS(current, existing.original)
        ) {
          // A later reconciliation must not overwrite a user's new DNS configuration.
          continue
        }
        if (!existing && restoreMode === 'original' && sameDNS(current, applied)) {
          if (isLoopbackTarget(applied)) {
            failures.push(
              new Error(
                `Cannot take over DNS for "${service.name}": loopback DNS is already configured ` +
                  'without an original DNS backup. Restore the previous DNS first, or explicitly ' +
                  'select automatic DNS restoration.'
              )
            )
            continue
          }
        }

        if (!existing) {
          const entry = {
            service,
            original: restoreMode === 'automatic' ? [] : [...current],
            applied: [...applied]
          }
          const next: SystemDNSJournal = {
            version: 1,
            services: [...journal.services, entry]
          }
          // A backup must be durable before the first system mutation, even if cancelled here.
          await this.deps.writeJournal(cloneJournal(next))
          if (!isCurrent()) return
          journal = next
        }

        if (sameDNS(current, applied)) continue
        try {
          await this.deps.writeDNS(service, [...applied])
          if (!isCurrent()) return
          const verified = await this.deps.readDNS(service)
          if (!isCurrent()) return
          if (!sameDNS(verified, applied)) {
            throw new Error(`DNS takeover could not be verified for "${service.name}"`)
          }
        } catch (error) {
          if (!isCurrent()) return
          failures.push(error)
        }
        if (!isCurrent()) return
      }

      if (failures.length > 0) {
        throw new AggregateError(
          failures,
          `Failed to take over system DNS: ${failureMessage(failures)}`
        )
      }
    })
  }

  restore(options: { timeout?: number } = {}): Promise<void> {
    // Invalidate synchronously; the queued barrier still waits for an in-flight write to finish.
    this.cancel()
    const restoreOptions = { ...options }
    return this.enqueue(async () => {
      let journal = cloneJournal(await this.deps.readJournal())
      if (journal.services.length === 0) return
      const services = await this.deps.listServices()
      let persistence: Promise<void> = Promise.resolve()
      const removeRestoredEntry = (entry: SystemDNSJournal['services'][number]): Promise<void> => {
        const operation = persistence.then(async () => {
          const next: SystemDNSJournal = {
            version: 1,
            services: journal.services.filter((saved) => saved !== entry)
          }
          // Always derive each durable result from the latest successful journal write.
          await this.deps.writeJournal(cloneJournal(next))
          journal = next
        })
        persistence = operation.catch(() => {})
        return operation
      }

      const results = await Promise.allSettled(
        [...journal.services].map(async (entry) => {
          if (!services.some((service) => sameService(service, entry.service))) {
            throw new Error(
              `Cannot restore DNS for "${entry.service.name}" (${entry.service.device}): ` +
                'network service is missing or has changed identity; retaining its recovery record'
            )
          }
          const current = await this.deps.readDNS(entry.service)
          if (sameDNS(current, entry.applied)) {
            await this.deps.writeDNS(entry.service, [...entry.original], restoreOptions)
            const restored = await this.deps.readDNS(entry.service)
            if (!sameDNS(restored, entry.original)) {
              throw new Error(`DNS restoration could not be verified for "${entry.service.name}"`)
            }
          }
          // Slow or failing services do not delay another service's restoration or persistence.
          await removeRestoredEntry(entry)
        })
      )
      const failures = results.flatMap((result) =>
        result.status === 'rejected' ? [result.reason] : []
      )

      if (failures.length > 0) {
        throw new AggregateError(
          failures,
          `Failed to restore system DNS: ${failureMessage(failures)}`
        )
      }
    })
  }
}
