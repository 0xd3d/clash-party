import { createSocket } from 'dgram'
import { EventEmitter } from 'events'
import { createConnection } from 'net'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  assertSystemDNSListener,
  getSystemDNSAddress,
  prepareSystemDNSListener,
  probeSystemDNS,
  SystemDNSListenerProof
} from './systemDNSRuntime'

vi.mock('dgram', () => ({ createSocket: vi.fn() }))
vi.mock('net', async (importOriginal) => ({
  ...(await importOriginal<typeof import('net')>()),
  createConnection: vi.fn()
}))

function profileFixture(): IMihomoConfig {
  const upstream = ['https://1.1.1.1/dns-query#🌐 海外出口']
  return {
    tun: { enable: true, 'dns-hijack': ['any:53'] },
    dns: {
      enable: true,
      listen: '0.0.0.0:1053',
      ipv6: true,
      'enhanced-mode': 'fake-ip',
      'fake-ip-range': '198.18.0.1/16',
      'respect-rules': true,
      nameserver: [...upstream],
      'default-nameserver': [...upstream],
      'proxy-server-nameserver': [...upstream],
      'nameserver-policy': {
        'aqqmusic.tc.qq.com': ['https://doh.pub/dns-query#DIRECT'],
        '+.stream.qqmusic.qq.com': ['https://doh.pub/dns-query#DIRECT']
      }
    },
    hosts: { 'example.invalid': '192.0.2.1' }
  } as unknown as IMihomoConfig
}

describe('getSystemDNSAddress', () => {
  it.each([undefined, '', '  '])('defaults an unset address (%j) to IPv4 loopback', (address) => {
    expect(getSystemDNSAddress({ systemDNSAddress: address })).toBe('127.0.0.1')
  })

  it.each(['127.0.0.1', '127.0.0.53', '127.1.2.3', '127.255.255.254', '::1'])(
    'accepts the loopback address %s and trims surrounding whitespace',
    (address) => {
      expect(getSystemDNSAddress({ systemDNSAddress: ` ${address} ` })).toBe(address)
    }
  )

  it.each([
    'localhost',
    '0.0.0.0',
    '126.255.255.255',
    '128.0.0.1',
    '192.0.2.53',
    '127.0.0.256',
    '127.1',
    '127.0.0.1:53',
    '::',
    '::2',
    '::ffff:127.0.0.1',
    '[::1]'
  ])('rejects addresses outside 127/8 and ::1: %s', (address) => {
    expect(() => getSystemDNSAddress({ systemDNSAddress: address })).toThrow('loopback address')
  })
})

describe('prepareSystemDNSListener', () => {
  it.each([
    { address: undefined, listen: '127.0.0.1:53', autoSetDNS: undefined },
    { address: '127.0.0.53', listen: '127.0.0.53:53', autoSetDNS: true },
    { address: ' ::1 ', listen: '[::1]:53', autoSetDNS: true }
  ])('changes only listen to $listen for macOS TUN DNS takeover', (testCase) => {
    const profile = profileFixture()
    const original = structuredClone(profile)

    prepareSystemDNSListener(
      profile,
      { autoSetDNS: testCase.autoSetDNS, systemDNSAddress: testCase.address },
      'darwin'
    )

    expect(profile).toEqual({
      ...original,
      dns: { ...original.dns, listen: testCase.listen }
    })
    expect(profile.dns?.nameserver).toEqual(['https://1.1.1.1/dns-query#🌐 海外出口'])
    expect(profile.dns?.['default-nameserver']).toEqual(profile.dns?.nameserver)
    expect(profile.dns?.['proxy-server-nameserver']).toEqual(profile.dns?.nameserver)
    expect(profile.dns?.['nameserver-policy']).toEqual({
      'aqqmusic.tc.qq.com': ['https://doh.pub/dns-query#DIRECT'],
      '+.stream.qqmusic.qq.com': ['https://doh.pub/dns-query#DIRECT']
    })
  })

  it.each(['linux', 'win32'] as const)(
    'leaves the complete profile unchanged on %s',
    (platform) => {
      const profile = profileFixture()
      const original = structuredClone(profile)
      prepareSystemDNSListener(profile, { autoSetDNS: true, systemDNSAddress: '::1' }, platform)
      expect(profile).toEqual(original)
    }
  )

  it.each(['automatic DNS disabled', 'TUN disabled', 'TUN absent', 'DNS disabled', 'DNS absent'])(
    'leaves the complete profile unchanged when %s',
    (condition) => {
      const profile = profileFixture()
      if (condition === 'TUN disabled') profile.tun = { enable: false }
      if (condition === 'TUN absent') Reflect.deleteProperty(profile, 'tun')
      if (condition === 'DNS disabled') profile.dns = { ...profile.dns, enable: false }
      if (condition === 'DNS absent') Reflect.deleteProperty(profile, 'dns')
      const original = structuredClone(profile)

      prepareSystemDNSListener(
        profile,
        { autoSetDNS: condition !== 'automatic DNS disabled', systemDNSAddress: '192.0.2.53' },
        'darwin'
      )

      expect(profile).toEqual(original)
    }
  )

  it('rejects a non-loopback listener before changing an enabled macOS profile', () => {
    const profile = profileFixture()
    const original = structuredClone(profile)
    expect(() =>
      prepareSystemDNSListener(profile, { autoSetDNS: true, systemDNSAddress: '0.0.0.0' }, 'darwin')
    ).toThrow('loopback address')
    expect(profile).toEqual(original)
  })
})

describe('assertSystemDNSListener', () => {
  it.each([
    ['127.0.0.1', '127.0.0.1:53'],
    ['127.0.0.53', '127.0.0.53:53'],
    ['::1', '[::1]:53']
  ])('accepts enabled DNS at %s port 53', (address, listen) => {
    const profile = profileFixture()
    profile.dns = { enable: true, listen }
    expect(() => assertSystemDNSListener(profile, address)).not.toThrow()
  })

  it.each([
    { address: '127.0.0.1', dns: undefined },
    { address: '127.0.0.1', dns: { enable: false, listen: '127.0.0.1:53' } },
    { address: '127.0.0.1', dns: { enable: true, listen: '127.0.0.1:1053' } },
    { address: '127.0.0.1', dns: { enable: true, listen: '0.0.0.0:53' } },
    { address: '127.0.0.53', dns: { enable: true, listen: '127.0.0.1:53' } },
    { address: '::1', dns: { enable: true, listen: '[::1]:1053' } },
    { address: '::1', dns: { enable: true, listen: '::1:53' } }
  ])('rejects a disabled, absent, or mismatched listener: %j', ({ address, dns }) => {
    const profile = profileFixture()
    if (dns) profile.dns = dns
    else Reflect.deleteProperty(profile, 'dns')
    expect(() => assertSystemDNSListener(profile, address)).toThrow('before takeover')
  })
})

describe('SystemDNSListenerProof', () => {
  const listener = (transport: 'TCP' | 'UDP', endpoint = '127.0.0.1:53'): string =>
    `time="2026-10-25T12:00:00Z" level=info msg="DNS server(${transport}) listening at: ${endpoint}"\n`

  it.each(['TCP', 'UDP'] as const)('waits for both protocols when %s is logged first', (first) => {
    const proof = new SystemDNSListenerProof()
    expect(proof.isReady('127.0.0.1')).toBe(false)
    proof.record(listener(first))
    expect(proof.isReady('127.0.0.1')).toBe(false)
    proof.record(listener(first === 'TCP' ? 'UDP' : 'TCP'))
    expect(proof.isReady('127.0.0.1')).toBe(true)
  })

  it('collects complete DNS listener lines from fragmented fake stdout events', () => {
    const proof = new SystemDNSListenerProof()
    const stdout = new EventEmitter()
    stdout.on('data', (chunk: string) => proof.record(chunk))
    const tcp = listener('TCP')
    const udp = listener('UDP')
    for (const chunk of [tcp.slice(0, 20), tcp.slice(20, -1), tcp.slice(-1), udp.slice(0, -1)]) {
      stdout.emit('data', chunk)
      expect(proof.isReady('127.0.0.1')).toBe(false)
    }
    stdout.emit('data', udp.slice(-1))
    expect(proof.isReady('127.0.0.1')).toBe(true)
  })

  it('handles multiple log lines and unrelated output in one chunk', () => {
    const proof = new SystemDNSListenerProof()
    proof.record(`startup complete\n${listener('TCP')}other listener started\n${listener('UDP')}`)
    expect(proof.isReady('127.0.0.1')).toBe(true)
  })

  it('requires the TCP and UDP listeners to use the same address', () => {
    const proof = new SystemDNSListenerProof()
    proof.record(listener('TCP') + listener('UDP', '127.0.0.53:53'))
    expect(proof.isReady('127.0.0.1')).toBe(false)
    expect(proof.isReady('127.0.0.53')).toBe(false)
    proof.record(listener('TCP', '127.0.0.53:53'))
    expect(proof.isReady('127.0.0.53')).toBe(true)
    expect(proof.isReady('127.0.0.1')).toBe(false)
  })

  it.each([
    '127.0.0.1:1053',
    '127.0.0.1:53053',
    '127.0.0.1:53suffix',
    '127.0.0.1:53.1',
    '0.0.0.0:53',
    '192.0.2.1:53',
    '127.256.0.1:53',
    '[::]:53',
    '[::1]:1053'
  ])('rejects a listener at a different port or invalid local endpoint: %s', (endpoint) => {
    const proof = new SystemDNSListenerProof()
    proof.record(listener('TCP', endpoint) + listener('UDP', endpoint))
    expect(proof.isReady('127.0.0.1')).toBe(false)
    expect(proof.isReady('::1')).toBe(false)
    expect(proof.isReady(endpoint.slice(0, endpoint.lastIndexOf(':')))).toBe(false)
  })

  it('recognizes bracketed IPv6 loopback listeners across CRLF chunks', () => {
    const proof = new SystemDNSListenerProof()
    proof.record('DNS server(TCP) listening at: [::1]:53\r')
    expect(proof.isReady('::1')).toBe(false)
    proof.record('\nDNS server(UDP) listening at: [::1]:53\r\n')
    expect(proof.isReady('::1')).toBe(true)
    expect(proof.isReady('127.0.0.1')).toBe(false)
  })

  it.each([
    'Start DNS server error: address already in use',
    'Start DNS server(TCP) error: bind failed',
    'Start DNS server(UDP) error: permission denied'
  ])('clears both protocol proofs after %s', (error) => {
    const proof = new SystemDNSListenerProof()
    proof.record(listener('TCP') + listener('UDP'))
    expect(proof.isReady('127.0.0.1')).toBe(true)
    proof.record(`level=error msg="${error}"\n`)
    expect(proof.isReady('127.0.0.1')).toBe(false)
    proof.record(listener('TCP'))
    expect(proof.isReady('127.0.0.1')).toBe(false)
    proof.record(listener('UDP'))
    expect(proof.isReady('127.0.0.1')).toBe(true)
  })

  it('handles a fragmented startup error and new listener lines in the same final chunk', () => {
    const proof = new SystemDNSListenerProof()
    proof.record(listener('TCP') + listener('UDP'))
    proof.record('Start DNS server(UD')
    proof.record(`P) error: bind failed\n${listener('TCP', '[::1]:53')}`)
    expect(proof.isReady('127.0.0.1')).toBe(false)
    expect(proof.isReady('::1')).toBe(false)
    proof.record(listener('UDP', '[::1]:53'))
    expect(proof.isReady('::1')).toBe(true)
  })

  it('clear discards protocol records and an unfinished line before a listener change', () => {
    const proof = new SystemDNSListenerProof()
    proof.record(listener('TCP') + listener('UDP') + 'DNS server(TCP) listening at: ')
    proof.clear()
    expect(proof.isReady('127.0.0.1')).toBe(false)
    proof.record(`127.0.0.53:53\n${listener('UDP', '127.0.0.53:53')}`)
    expect(proof.isReady('127.0.0.53')).toBe(false)
    proof.record(listener('TCP', '127.0.0.53:53'))
    expect(proof.isReady('127.0.0.53')).toBe(true)
  })

  it('discards oversized unfinished UTF-8 lines and resumes at the next newline', () => {
    const proof = new SystemDNSListenerProof()
    proof.record('界'.repeat(2800))
    proof.record(listener('TCP') + listener('UDP'))
    expect(proof.isReady('127.0.0.1')).toBe(false)
    proof.record(listener('TCP'))
    expect(proof.isReady('127.0.0.1')).toBe(true)
  })

  it('clear also resets oversized-line discard state', () => {
    const proof = new SystemDNSListenerProof()
    proof.record('x'.repeat(8193))
    proof.clear()
    proof.record(listener('TCP') + listener('UDP'))
    expect(proof.isReady('127.0.0.1')).toBe(true)
  })
})

class FakeDatagramSocket extends EventEmitter {
  connect = vi.fn((_port: number, _address: string, connected: () => void) => connected())
  send = vi.fn((_query: Buffer) => {})
  close = vi.fn()
}

class FakeTCPSocket extends EventEmitter {
  write = vi.fn((_query: Buffer) => {})
  destroy = vi.fn()
}

function startProbe(address = '127.0.0.1', port = 53053, timeout = 75) {
  const udp = new FakeDatagramSocket()
  const tcp = new FakeTCPSocket()
  vi.mocked(createSocket).mockReturnValue(udp as unknown as ReturnType<typeof createSocket>)
  vi.mocked(createConnection).mockReturnValue(tcp as unknown as ReturnType<typeof createConnection>)
  const ready = probeSystemDNS(address, port, timeout)
  tcp.emit('connect')
  const query = udp.send.mock.calls[0]?.[0]
  if (!query) throw new Error('Expected a local DNS query')
  return { udp, tcp, ready, query }
}

function responseFor(query: Buffer, rcode = 0): Buffer {
  const response = Buffer.from(query)
  response[2] = 0x81
  response[3] = 0x80 | rcode
  return response
}

function tcpFrame(response: Buffer): Buffer {
  const size = Buffer.alloc(2)
  size.writeUInt16BE(response.length)
  return Buffer.concat([size, response])
}

describe('probeSystemDNS', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.clearAllTimers()
    vi.useRealTimers()
  })

  it.each(['UDP', 'TCP'])('requires both transports after %s succeeds first', async (first) => {
    const { udp, tcp, ready, query } = startProbe()
    const resolved = vi.fn()
    void ready.then(resolved)
    const response = responseFor(query)

    if (first === 'UDP') udp.emit('message', response)
    else tcp.emit('data', tcpFrame(response))
    await Promise.resolve()
    expect(resolved).not.toHaveBeenCalled()

    if (first === 'UDP') tcp.emit('data', tcpFrame(response))
    else udp.emit('message', response)
    await expect(ready).resolves.toBeUndefined()
    expect(udp.close).toHaveBeenCalledOnce()
    expect(tcp.destroy).toHaveBeenCalledOnce()
    expect(vi.getTimerCount()).toBe(0)
  })

  it.each([
    { address: '127.0.0.1', family: 'udp4' },
    { address: '::1', family: 'udp6' }
  ])(
    'uses only the requested local $family endpoint and sends a framed TCP query',
    async (entry) => {
      const { udp, tcp, ready, query } = startProbe(entry.address)
      expect(createSocket).toHaveBeenCalledWith(entry.family)
      expect(udp.connect).toHaveBeenCalledWith(53053, entry.address, expect.any(Function))
      expect(createConnection).toHaveBeenCalledWith({ host: entry.address, port: 53053 })
      expect(tcp.write).toHaveBeenCalledWith(tcpFrame(query))
      expect(query.subarray(2, 12)).toEqual(Buffer.from([1, 0, 0, 1, 0, 0, 0, 0, 0, 0]))
      const labelLength = query[12]
      expect(query.subarray(13, 13 + labelLength).toString()).toMatch(/^clash-party-[a-f0-9]{16}$/)
      expect(query.subarray(13 + labelLength)).toEqual(
        Buffer.from([7, ...Buffer.from('invalid'), 0, 0, 1, 0, 1])
      )
      udp.emit('message', responseFor(query))
      tcp.emit('data', tcpFrame(responseFor(query)))
      await expect(ready).resolves.toBeUndefined()
    }
  )

  it('accepts NXDOMAIN from both transports as a valid DNS response', async () => {
    const { udp, tcp, ready, query } = startProbe()
    udp.emit('message', responseFor(query, 3))
    tcp.emit('data', tcpFrame(responseFor(query, 3)))
    await expect(ready).resolves.toBeUndefined()
  })

  it('buffers a split TCP length prefix and response until the complete frame arrives', async () => {
    const { udp, tcp, ready, query } = startProbe()
    const resolved = vi.fn()
    void ready.then(resolved)
    udp.emit('message', responseFor(query))
    const frame = tcpFrame(responseFor(query))
    for (const chunk of [frame.subarray(0, 1), frame.subarray(1, 7), frame.subarray(7, -1)]) {
      tcp.emit('data', chunk)
      await Promise.resolve()
      expect(resolved).not.toHaveBeenCalled()
    }
    tcp.emit('data', frame.subarray(-1))
    await expect(ready).resolves.toBeUndefined()
  })

  it.each(['UDP', 'TCP'])('rejects if only %s times out', async (transport) => {
    const { udp, tcp, ready, query } = startProbe()
    const rejected = expect(ready).rejects.toThrow(`Local ${transport} DNS readiness timed out`)
    if (transport === 'UDP') tcp.emit('data', tcpFrame(responseFor(query)))
    else udp.emit('message', responseFor(query))
    await vi.advanceTimersByTimeAsync(75)
    await rejected
    expect(udp.close).toHaveBeenCalledOnce()
    expect(tcp.destroy).toHaveBeenCalledOnce()
  })

  it.each(['UDP', 'TCP'])('rejects an incorrect %s transaction ID', async (transport) => {
    const { udp, tcp, ready, query } = startProbe()
    const rejected = expect(ready).rejects.toThrow(`Invalid local ${transport} DNS response`)
    const invalid = responseFor(query)
    invalid[0] ^= 0xff
    udp.emit('message', transport === 'UDP' ? invalid : responseFor(query))
    tcp.emit('data', tcpFrame(transport === 'TCP' ? invalid : responseFor(query)))
    await rejected
  })

  it.each(['UDP', 'TCP'])(
    'rejects a %s socket failure even if the other transport succeeds',
    async (transport) => {
      const { udp, tcp, ready, query } = startProbe()
      const rejected = expect(ready).rejects.toThrow('socket failed')
      if (transport === 'UDP') {
        tcp.emit('data', tcpFrame(responseFor(query)))
        udp.emit('error', new Error('socket failed'))
      } else {
        udp.emit('message', responseFor(query))
        tcp.emit('error', new Error('socket failed'))
      }
      await rejected
      expect(udp.close).toHaveBeenCalledOnce()
      expect(tcp.destroy).toHaveBeenCalledOnce()
    }
  )

  it('rejects a TCP connection that ends before a complete response', async () => {
    const { udp, tcp, ready, query } = startProbe()
    const rejected = expect(ready).rejects.toThrow('closed before responding')
    udp.emit('message', responseFor(query))
    tcp.emit('data', tcpFrame(responseFor(query)).subarray(0, 4))
    tcp.emit('end')
    await rejected
  })

  it('rejects non-loopback targets before opening either transport', async () => {
    await expect(probeSystemDNS('192.0.2.53', 53053)).rejects.toThrow('loopback address')
    expect(createSocket).not.toHaveBeenCalled()
    expect(createConnection).not.toHaveBeenCalled()
  })
})
