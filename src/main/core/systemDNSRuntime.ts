import { randomBytes } from 'crypto'
import { createSocket } from 'dgram'
import { createConnection, isIP } from 'net'

export function getSystemDNSAddress(config: Pick<IAppConfig, 'systemDNSAddress'>): string {
  const address = config.systemDNSAddress?.trim() || '127.0.0.1'
  if (!(isIP(address) === 4 && address.startsWith('127.')) && address !== '::1') {
    throw new Error('System DNS must use a loopback address such as 127.0.0.1 or ::1')
  }
  return address
}

/** Only the local listener changes; upstreams and domain-specific policies stay intact. */
export function prepareSystemDNSListener(
  profile: IMihomoConfig,
  config: Pick<IAppConfig, 'autoSetDNS' | 'systemDNSAddress'>,
  platform: NodeJS.Platform = process.platform
): void {
  if (platform !== 'darwin' || config.autoSetDNS === false || !profile.tun?.enable) return
  if (!profile.dns?.enable) return
  const address = getSystemDNSAddress(config)
  profile.dns = { ...profile.dns, listen: address === '::1' ? '[::1]:53' : `${address}:53` }
}

export function assertSystemDNSListener(profile: IMihomoConfig, address: string): void {
  const expected = address === '::1' ? '[::1]:53' : `${address}:53`
  if (!profile.dns?.enable || profile.dns.listen !== expected) {
    throw new Error(`Core DNS must be enabled and listening on ${expected} before takeover`)
  }
}

/** Listener ownership evidence collected only from the current core process stdout. */
export class SystemDNSListenerProof {
  private readonly tcp = new Set<string>()
  private readonly udp = new Set<string>()
  private pending = ''
  private discardingLine = false

  record(chunk: string): void {
    const lines = (this.pending + chunk).split('\n')
    this.pending = lines.pop() ?? ''
    for (const line of lines) {
      if (this.discardingLine) {
        this.discardingLine = false
        continue
      }
      if (/Start DNS server(?:\([^)]*\))?.*error:/i.test(line)) {
        this.tcp.clear()
        this.udp.clear()
        continue
      }
      const listener = line.match(
        /DNS server\((TCP|UDP)\) listening at:\s+(\[[^\]]+\]|[\d.]+):53(?=$|[\s"'])/
      )
      if (!listener) continue
      const address = listener[2] === '[::1]' ? '::1' : listener[2]
      if (!(isIP(address) === 4 && address.startsWith('127.')) && address !== '::1') continue
      ;(listener[1] === 'TCP' ? this.tcp : this.udp).add(address)
    }
    // Discard an oversized incomplete line rather than treating its suffix as a new log line.
    if (Buffer.byteLength(this.pending, 'utf8') > 8 * 1024) {
      this.pending = ''
      this.discardingLine = true
    }
  }

  isReady(address: string): boolean {
    return this.tcp.has(address) && this.udp.has(address)
  }

  clear(): void {
    this.tcp.clear()
    this.udp.clear()
    this.pending = ''
    this.discardingLine = false
  }
}

/** Probe both transports using a random, non-user DNS name and no system resolver. */
export async function probeSystemDNS(address: string, port = 53, timeout = 750): Promise<void> {
  getSystemDNSAddress({ systemDNSAddress: address })
  const id = randomBytes(2)
  const labels = [`clash-party-${randomBytes(8).toString('hex')}`, 'invalid']
  const query = Buffer.concat([
    id,
    Buffer.from([1, 0, 0, 1, 0, 0, 0, 0, 0, 0]),
    ...labels.map((label) => Buffer.concat([Buffer.from([label.length]), Buffer.from(label)])),
    Buffer.from([0, 0, 1, 0, 1])
  ])
  const valid = (response: Buffer): boolean =>
    response.length >= 12 &&
    response.subarray(0, 2).equals(id) &&
    (response[2] & 0x80) !== 0 &&
    [0, 3].includes(response[3] & 0x0f)

  await Promise.all([
    new Promise<void>((resolve, reject) => {
      const socket = createSocket(address === '::1' ? 'udp6' : 'udp4')
      let settled = false
      const finish = (error?: Error): void => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        socket.close()
        if (error) reject(error)
        else resolve()
      }
      const timer = setTimeout(
        () => finish(new Error('Local UDP DNS readiness timed out')),
        timeout
      )
      socket.once('error', finish)
      socket.once('message', (response) =>
        finish(valid(response) ? undefined : new Error('Invalid local UDP DNS response'))
      )
      socket.connect(port, address, () => socket.send(query))
    }),
    new Promise<void>((resolve, reject) => {
      const socket = createConnection({ host: address, port })
      let data = Buffer.alloc(0)
      let settled = false
      const finish = (error?: Error): void => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        socket.destroy()
        if (error) reject(error)
        else resolve()
      }
      const timer = setTimeout(
        () => finish(new Error('Local TCP DNS readiness timed out')),
        timeout
      )
      socket.once('error', finish)
      socket.once('end', () => finish(new Error('Local TCP DNS closed before responding')))
      socket.once('connect', () => {
        const length = Buffer.alloc(2)
        length.writeUInt16BE(query.length)
        socket.write(Buffer.concat([length, query]))
      })
      socket.on('data', (chunk) => {
        data = Buffer.concat([data, typeof chunk === 'string' ? Buffer.from(chunk) : chunk])
        if (data.length < 2 || data.length < 2 + data.readUInt16BE(0)) return
        finish(valid(data.subarray(2)) ? undefined : new Error('Invalid local TCP DNS response'))
      })
    })
  ])
}
