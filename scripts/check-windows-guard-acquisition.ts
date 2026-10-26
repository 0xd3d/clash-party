// Isolated Windows CI only. Exercises real WFP transactions with bounded owned-process cleanup.
import { execFileSync, spawn, spawnSync } from 'node:child_process'
import path from 'node:path'
import {
  windowsGuardBrokerCommand,
  parseWindowsGuardBrokerResult
} from '../src/main/core/windowsGuardBroker.ts'
if (
  process.platform !== 'win32' ||
  process.env.GITHUB_ACTIONS !== 'true' ||
  !process.env.RUNNER_TEMP
)
  throw new Error('Privileged acquisition fixture requires an isolated Windows CI runner')
const [directory, pidText, alias, physicalAlias] = process.argv.slice(2)
if (!directory || !pidText || !alias || !physicalAlias)
  throw new Error('Missing CI fixture arguments')
const relative = path.relative(process.env.RUNNER_TEMP, directory)
if (
  relative.startsWith('..') ||
  path.isAbsolute(relative) ||
  !path.basename(directory).startsWith('clash-wintun-')
)
  throw new Error('Fixture must use its isolated runner temporary directory')
const corePid = Number(pidText)
if (!Number.isSafeInteger(corePid) || corePid <= 0) throw new Error('Invalid owned core PID')
const helper = path.join(directory, 'resources/files/party.mihomo.network-guard.exe')
const core = path.join(directory, 'resources/sidecar/mihomo.exe')
function call(args: string[]) {
  return JSON.parse(execFileSync(helper, args, { encoding: 'utf8', timeout: 8000 }))
}
function requireState(value: boolean, message: string): void {
  if (!value) throw new Error(message)
}
const before = call(['status'])
requireState(before.guardPid === null && !before.active, 'Refusing to replace an existing guard')
let guardPid: number | undefined
let watchdog: ReturnType<typeof spawn> | undefined
try {
  const broker = windowsGuardBrokerCommand(helper, process.env.SystemRoot)
  guardPid = parseWindowsGuardBrokerResult(
    execFileSync(broker.file, broker.args, { encoding: 'utf8', timeout: 15000 })
  )
  // Hold the exact helper process before arming. A stalled test cannot leave its runner offline.
  // This does not look up a possibly reused PID at cleanup time or touch any unrelated process.
  const script = `
$ErrorActionPreference='Stop'
$p=[Diagnostics.Process]::GetProcessById(${guardPid})
$null=$p.Handle
$expected=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${Buffer.from(helper).toString('base64')}'))
if ($p.MainModule.FileName -ine $expected) { throw 'Unexpected watchdog process identity' }
[Console]::WriteLine('READY')
if (!$p.WaitForExit(45000)) { $p.Kill(); $p.WaitForExit(5000) | Out-Null }
$p.Dispose()
`
  watchdog = spawn(
    broker.file,
    [
      '-NoLogo',
      '-NoProfile',
      '-NonInteractive',
      '-EncodedCommand',
      Buffer.from(script, 'utf16le').toString('base64')
    ],
    { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] }
  )
  const monitor = watchdog
  const output = monitor.stdout
  if (!output) throw new Error('Watchdog output unavailable')
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error('Owned guard watchdog did not become ready')),
      8000
    )
    output.once('data', (data) => {
      clearTimeout(timer)
      String(data).includes('READY') ? resolve() : reject(new Error('Unexpected watchdog response'))
    })
    monitor.once('error', (error) => {
      clearTimeout(timer)
      reject(error)
    })
    monitor.once('exit', (code) => {
      clearTimeout(timer)
      reject(new Error(`Watchdog exited before readiness: ${code}`))
    })
  })
  const physical = call(['arm', '--core-path', core, '--tun-name', physicalAlias])
  requireState(
    physical.active &&
      physical.guardPid === guardPid &&
      physical.corePid === null &&
      physical.tunLuid === null &&
      physical.filterCount > 0,
    'Arm did not create a closed barrier with a pre-existing non-Wintun alias'
  )
  const invalid = spawnSync(
    helper,
    ['acquire', '--core-path', core, '--core-pid', String(corePid), '--tun-name', physicalAlias],
    { encoding: 'utf8', timeout: 8000 }
  )
  requireState(
    invalid.status === 1 && Boolean(JSON.parse(invalid.stdout).error),
    'Physical adapter acquisition was not rejected'
  )
  const preserved = call(['status'])
  requireState(
    preserved.active &&
      preserved.guardPid === guardPid &&
      preserved.corePid === null &&
      preserved.tunLuid === null &&
      preserved.filterCount === physical.filterCount,
    'Failed acquisition changed the closed barrier'
  )
  const acquired = call([
    'acquire',
    '--core-path',
    core,
    '--core-pid',
    String(corePid),
    '--tun-name',
    alias
  ])
  requireState(
    acquired.active &&
      acquired.guardPid === guardPid &&
      acquired.corePid === corePid &&
      acquired.coreAlive &&
      acquired.tunName === alias &&
      Boolean(acquired.tunLuid) &&
      acquired.tunIndex > 0 &&
      acquired.filterCount > physical.filterCount,
    'Actual Mihomo TUN was not acquired through WMI-owned production guard'
  )
  const rearmed = call(['arm', '--core-path', core, '--tun-name', alias])
  requireState(
    rearmed.active &&
      rearmed.corePid === null &&
      rearmed.tunLuid === null &&
      rearmed.filterCount === physical.filterCount,
    'Rearming kept an unowned interface permit'
  )
  process.stdout.write(
    JSON.stringify({
      acquisitionIntegration: 'passed',
      closedArmIgnoresUnownedAlias: true,
      physicalAcquireRejected: true,
      failedAcquireRetainsBarrier: true,
      actualCoreAndTunAcquired: true,
      rearmClosesTunPermit: true,
      closedFilterCount: physical.filterCount,
      acquiredFilterCount: acquired.filterCount
    }) + '\n'
  )
} finally {
  const state = call(['status'])
  if (guardPid && state.guardPid === guardPid) call(['recover'])
  const after = call(['status'])
  requireState(
    after.guardPid === null && !after.active && after.filterCount === 0,
    'Owned CI protection was not recovered'
  )
  if (watchdog && watchdog.exitCode === null) watchdog.kill()
}
