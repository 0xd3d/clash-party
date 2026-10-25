import { createServer, createConnection, type Socket, type Server } from 'node:net'
import { createSocket, type Socket as Datagram } from 'node:dgram'
import { mkdir, mkdtemp, writeFile, rm, stat } from 'node:fs/promises'
import { spawn, type ChildProcess } from 'node:child_process'
import { once } from 'node:events'
import path from 'node:path'
import os from 'node:os'
import { stringify } from 'yaml'
import { applyNetworkProtectionPolicy } from '../src/main/core/networkProtectionPolicy'

// Unprivileged, isolated loopback protocol fixtures. Never changes the running app,
// system DNS/routes/firewall or TUN. Only these prepared sidecars may be selected.
const allowedCores = ['mihomo', 'mihomo-alpha', 'mihomo-smart']
const args = process.argv.slice(2)
if (args.length !== 0 && (args.length !== 2 || args[0] !== '--core')) {
  throw new Error(
    'Usage: tsx scripts/check-desktop-protection.ts [--core mihomo|mihomo-alpha|mihomo-smart]'
  )
}
const coreName = args[1] ?? 'mihomo'
if (!allowedCores.includes(coreName)) throw new Error('Unsupported fixture core')
const binary = path.resolve(
  'extra/sidecar',
  coreName + (process.platform === 'win32' ? '.exe' : '')
)
if ((await stat(binary)).mode & 0o6000) throw new Error('Refuse to run a privileged fixture binary')
const delay = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms))
const folder = await mkdtemp(path.join(os.tmpdir(), 'clash-desktop-protection-'))
const servers: Server[] = []
const datagrams: Datagram[] = []
const fixtureSockets = new Set<Socket>()
const cores = new Set<ChildProcess>()
const coreLogs = new Map<string, string>()
let directDNS = 0
let proxyDNS = 0
let directUDP = 0

type FixtureCore = { port: number; queryPort: number; process: ChildProcess; name: string }
function assert(value: unknown, message: string): asserts value {
  if (!value) throw new Error(message)
}
async function waitFor(check: () => boolean, message: string, timeout = 2500): Promise<void> {
  const deadline = Date.now() + timeout
  while (!check()) {
    if (Date.now() >= deadline) throw new Error(message)
    await delay(20)
  }
}
async function tcp(handler: (socket: Socket) => void): Promise<number> {
  const server = createServer((socket) => {
    fixtureSockets.add(socket)
    socket.once('close', () => fixtureSockets.delete(socket))
    socket.on('error', () => {})
    handler(socket)
  })
  servers.push(server)
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  assert(address && typeof address !== 'string', 'TCP fixture address')
  return address.port
}
async function udp(
  handler: (data: Buffer, remote: { port: number; address: string }, socket: Datagram) => void
): Promise<{ port: number; socket: Datagram }> {
  const socket = createSocket('udp4')
  datagrams.push(socket)
  socket.on('message', (data, remote) => handler(data, remote, socket))
  socket.bind(0, '127.0.0.1')
  await once(socket, 'listening')
  return { port: socket.address().port, socket }
}
async function unusedTCP(): Promise<number> {
  const server = createServer()
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  assert(address && typeof address !== 'string', 'Fixture port')
  await new Promise<void>((resolve) => server.close(() => resolve()))
  return address.port
}
// TCP chunks are not SOCKS frames: retain partial replies until the expected length arrives.
function readExactly(socket: Socket, length: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => finish(new Error('SOCKS fixture timed out')), 1200)
    const onError = (error: Error): void => finish(error)
    const onClose = (): void => finish(new Error('SOCKS fixture closed before its reply'))
    const onReadable = (): void => {
      const data: Buffer | null = socket.read(length)
      if (data !== null) finish(undefined, data)
    }
    function finish(error?: Error, data?: Buffer): void {
      clearTimeout(timer)
      socket.removeListener('readable', onReadable)
      socket.removeListener('error', onError)
      socket.removeListener('close', onClose)
      if (error) reject(error)
      else if (data) resolve(data)
      else reject(new Error('SOCKS fixture returned no bytes'))
    }
    socket.on('readable', onReadable)
    socket.once('error', onError)
    socket.once('close', onClose)
    onReadable()
  })
}
function endpoint(port: number): Buffer {
  const result = Buffer.from([1, 127, 0, 0, 1, 0, 0])
  result.writeUInt16BE(port, 5)
  return result
}
async function socksConnection(port: number): Promise<Socket> {
  const socket = createConnection(port, '127.0.0.1')
  socket.on('error', () => {})
  const timer = setTimeout(() => socket.destroy(new Error('Fixture TCP connect timeout')), 1200)
  try {
    await once(socket, 'connect')
    socket.write(Buffer.from([5, 1, 0]))
    const hello = await readExactly(socket, 2)
    assert(hello.equals(Buffer.from([5, 0])), 'SOCKS auth reply')
    return socket
  } catch (error) {
    socket.destroy()
    throw error
  } finally {
    clearTimeout(timer)
  }
}
async function socksReply(socket: Socket): Promise<number> {
  const header = await readExactly(socket, 4)
  assert(header[0] === 5 && header[1] === 0 && header[2] === 0, 'SOCKS command reply')
  // Every fixture listener and request is IPv4 loopback; reject unexpected relay addresses.
  assert(header[3] === 1, 'SOCKS fixture relay must be IPv4')
  const address = await readExactly(socket, 6)
  assert(address.subarray(0, 4).equals(Buffer.from([127, 0, 0, 1])), 'Non-loopback fixture relay')
  return address.readUInt16BE(4)
}
async function stopCore(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) {
    cores.delete(child)
    return
  }
  const exited = once(child, 'exit')
  child.kill('SIGTERM')
  await Promise.race([exited, delay(1200)])
  if (child.exitCode === null && child.signalCode === null) {
    child.kill('SIGKILL')
    await Promise.race([exited, delay(1200)])
  }
  assert(child.exitCode !== null || child.signalCode !== null, 'Fixture core did not stop')
  cores.delete(child)
}
let readinessPort: number
async function launch(profile: Record<string, unknown>, name: string): Promise<FixtureCore> {
  const port = await unusedTCP()
  const queryPort = await unusedTCP()
  // A shared cache.db locks later processes in InnerLoading even though their listeners
  // are open. Give every case its own directory and also stop it before the next case.
  const workDir = path.join(folder, name)
  await mkdir(workDir)
  const target = path.join(workDir, 'config.yaml')
  const rules = [
    `AND,((NETWORK,TCP),(DST-PORT,${readinessPort})),DIRECT`,
    ...(profile.rules as string[])
  ]
  await writeFile(
    target,
    stringify({
      ...profile,
      rules,
      'mixed-port': port,
      'bind-address': '127.0.0.1',
      'allow-lan': false,
      tun: { enable: false },
      dns: { ...(profile.dns as object), listen: `127.0.0.1:${queryPort}` },
      'external-controller': '',
      'external-ui': '',
      'geo-auto-update': false,
      'find-process-mode': 'off',
      ntp: { enable: false },
      sniffer: { enable: false },
      'log-level': 'debug'
    })
  )
  const child = spawn(binary, ['-d', workDir, '-f', target], { stdio: ['ignore', 'pipe', 'pipe'] })
  cores.add(child)
  let logs = ''
  for (const stream of [child.stdout, child.stderr]) {
    stream?.on('data', (value) => {
      logs = (logs + String(value)).slice(-16384)
      coreLogs.set(name, logs)
    })
  }
  let spawnError: Error | undefined
  child.on('error', (error) => {
    spawnError = error
  })
  const deadline = Date.now() + 6000
  for (;;) {
    if (spawnError) throw spawnError
    assert(child.exitCode === null && child.signalCode === null, 'Isolated core exited: ' + logs)
    let socket: Socket | undefined
    try {
      socket = await socksConnection(port)
      socket.write(Buffer.concat([Buffer.from([5, 1, 0]), endpoint(readinessPort)]))
      await socksReply(socket)
      // A SOCKS success reply alone precedes routing in mihomo. Require the local
      // destination's bytes to prove the tunnel has transitioned to Running.
      assert((await readExactly(socket, 5)).equals(Buffer.from('ready')), 'Fixture route readiness')
      break
    } catch {
      if (Date.now() >= deadline) throw new Error('Isolated core route readiness failed: ' + logs)
      await delay(30)
    } finally {
      socket?.destroy()
    }
  }
  return { port, queryPort, process: child, name }
}
async function withCore(
  profile: Record<string, unknown>,
  name: string,
  run: (core: FixtureCore) => Promise<void>
): Promise<void> {
  const core = await launch(profile, name)
  try {
    await run(core)
  } finally {
    await stopCore(core.process)
  }
}
async function query(port: number): Promise<void> {
  const socket = createSocket('udp4')
  try {
    await new Promise<void>((resolve) => socket.bind(0, '127.0.0.1', resolve))
    const packet = Buffer.concat([
      Buffer.from([0x42, 0x42, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 5]),
      Buffer.from('probe'),
      Buffer.from([4]),
      Buffer.from('test'),
      Buffer.from([0, 0, 1, 0, 1])
    ])
    await new Promise<void>((resolve, reject) => {
      socket.send(packet, port, '127.0.0.1', (error) => (error ? reject(error) : resolve()))
    })
    await delay(350)
  } finally {
    socket.close()
  }
}
async function sendUDP(core: FixtureCore, targetPort: number): Promise<void> {
  const socket = createSocket('udp4')
  let control: Socket | undefined
  try {
    await new Promise<void>((resolve) => socket.bind(0, '127.0.0.1', resolve))
    control = await socksConnection(core.port)
    control.write(Buffer.concat([Buffer.from([5, 3, 0]), endpoint(socket.address().port)]))
    const relayPort = await socksReply(control)
    // Numeric loopback removes DNS from the UDP policy control entirely.
    const frame = Buffer.concat([
      Buffer.from([0, 0, 0]),
      endpoint(targetPort),
      Buffer.from('probe')
    ])
    await new Promise<void>((resolve, reject) => {
      socket.send(frame, relayPort, '127.0.0.1', (error) => (error ? reject(error) : resolve()))
    })
    await waitFor(
      () => (coreLogs.get(core.name) ?? '').includes('Node UDP is not supported'),
      'Unsupported UDP rule was not actually exercised: ' + coreLogs.get(core.name)
    )
    await delay(350)
  } finally {
    control?.destroy()
    socket.close()
  }
}
try {
  readinessPort = await tcp((socket) => socket.end('ready'))
  const dnsTrap = await tcp((socket) => {
    directDNS++
    socket.destroy()
  })
  const proxy = await tcp((socket) => {
    proxyDNS++
    socket.once('data', () => {
      socket.write(Buffer.from([5, 0]))
      socket.once('data', () => socket.end(Buffer.from([5, 5, 0, 1, 0, 0, 0, 0, 0, 0])))
    })
  })
  const udpTrap = await udp((data) => {
    if (data.equals(Buffer.from('probe'))) directUDP++
  })
  const base = (): Record<string, unknown> => ({
    mode: 'rule',
    ipv6: true,
    proxies: [{ name: 'Node', type: 'socks5', server: '127.0.0.1', port: proxy, udp: false }],
    'proxy-groups': [{ name: 'Protected', type: 'select', proxies: ['Node'] }],
    rules: ['MATCH,Protected'],
    dns: {
      enable: true,
      'default-nameserver': ['https://127.0.0.1:1/dns-query'],
      nameserver: [`https://127.0.0.1:${dnsTrap}/dns-query#h3=false&DIRECT`]
    }
  })
  await withCore(base(), 'direct-control', async (core) => {
    const before = directDNS
    await query(core.queryPort)
    assert(directDNS > before, 'Direct DNS positive-control trap did not run')
  })
  const safe = base()
  safe.tun = { enable: true, device: 'fixture' }
  applyNetworkProtectionPolicy(safe as unknown as IMihomoConfig, {
    networkProtection: true,
    networkProtectionPublicUDP: true,
    autoSetDNS: true
  })
  await withCore(safe, 'dns-protected', async (core) => {
    const before = directDNS,
      proxyBefore = proxyDNS
    await query(core.queryPort)
    assert(directDNS === before, 'DNS escaped to the direct trap')
    assert(proxyDNS > proxyBefore, 'Protected DNS did not enter the selected proxy')
  })
  const empty = base()
  empty['proxy-groups'] = [
    { name: 'Protected', type: 'select', proxies: ['Node'], 'exclude-filter': '.*' }
  ]
  ;(empty.dns as Record<string, unknown>).nameserver = [
    `https://127.0.0.1:${dnsTrap}/dns-query#Protected`
  ]
  await withCore(empty, 'empty-control', async (core) => {
    const before = directDNS
    await query(core.queryPort)
    assert(directDNS > before, 'Empty-group DIRECT positive-control did not reproduce')
  })
  empty.tun = { enable: true, device: 'fixture' }
  applyNetworkProtectionPolicy(empty as unknown as IMihomoConfig, {
    networkProtection: true,
    autoSetDNS: true
  })
  await withCore(empty, 'empty-protected', async (core) => {
    const before = directDNS
    await query(core.queryPort)
    assert(directDNS === before, 'Filtered group fell back to DIRECT')
  })
  // Isolate the generated public-UDP pair from LAN exemptions: the local trap
  // models a public destination without sending a single packet outside loopback.
  const unsafeUDP = base()
  unsafeUDP.rules = ['NETWORK,UDP,Node', 'MATCH,DIRECT']
  await withCore(unsafeUDP, 'udp-control', async (core) => {
    const before = directUDP
    await sendUDP(core, udpTrap.port)
    assert(
      directUDP > before,
      'Unsupported-UDP DIRECT positive-control did not reproduce: ' + coreLogs.get(core.name)
    )
  })
  const protectedUDP = base()
  protectedUDP.rules = ['NETWORK,UDP,Node', 'NETWORK,UDP,REJECT', 'MATCH,DIRECT']
  await withCore(protectedUDP, 'udp-protected', async (core) => {
    const before = directUDP
    await sendUDP(core, udpTrap.port)
    assert(
      (coreLogs.get(core.name) ?? '').includes('REJECT'),
      'UDP rejection was not actually exercised'
    )
    assert(directUDP === before, 'Unsupported UDP skipped the proxy into DIRECT')
  })
  process.stdout.write(
    JSON.stringify({
      desktopCoreFixture: 'passed',
      core: coreName,
      tests: [
        'direct DNS positive control',
        'bound DNS enters proxy and never direct',
        'empty group DIRECT positive control',
        'empty group fail closed',
        'unsupported UDP DIRECT positive control',
        'unsupported UDP REJECT fallback'
      ],
      osFirewallExercised: false,
      currentAppModified: false
    }) + '\n'
  )
} finally {
  for (const child of cores) await stopCore(child)
  for (const socket of fixtureSockets) socket.destroy()
  for (const socket of datagrams) socket.close()
  for (const server of servers) await new Promise<void>((resolve) => server.close(() => resolve()))
  await rm(folder, { recursive: true, force: true })
}
