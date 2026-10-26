// Windows CI only. Starts UNARMED helpers: no WFP, DNS, firewall or core changes.
import { execFileSync, spawnSync } from 'node:child_process'
import { copyFileSync, mkdirSync, rmSync } from 'node:fs'
import path from 'node:path'
import {
  windowsGuardBrokerCommand,
  parseWindowsGuardBrokerResult
} from '../src/main/core/windowsGuardBroker.ts'
if (process.platform !== 'win32') throw new Error('This integration requires Windows')
const directory = path.resolve('build/native/windows', process.arch)
const helper = path.join(directory, 'party.mihomo.network-guard.exe')
const fixture = path.join(directory, 'broker-lifetime-selftest.exe')
const status = () =>
  JSON.parse(execFileSync(helper, ['status'], { encoding: 'utf8', timeout: 8000 }))
if (status().guardPid !== null) throw new Error('Refusing to test with an existing guard')
// A matching basename must not authenticate an ordinary process as the Windows broker.
const fakeDirectory = path.join(directory, 'untrusted broker')
mkdirSync(fakeDirectory, { recursive: true })
const fakeProvider = path.join(fakeDirectory, 'WmiPrvSE.exe')
copyFileSync(fixture, fakeProvider)
try {
  const denied = JSON.parse(
    execFileSync(fakeProvider, ['--reject-origin', helper], { encoding: 'utf8', timeout: 40000 })
  )
  if (!denied.untrustedOriginRejected || denied.cases !== 2)
    throw new Error('Ordinary or forged broker inherited-Job launch was not rejected')
} finally {
  rmSync(fakeDirectory, { recursive: true })
}
for (const providerJob of [false, true]) {
  let fixturePid: number | undefined
  try {
    const command = windowsGuardBrokerCommand(helper, process.env.SystemRoot)
    const encoded = command.args.at(-1)
    if (!encoded) throw new Error('Missing fixed broker script')
    let script = Buffer.from(encoded, 'base64').toString('utf16le')
    // Keep the calling launcher alive until its private kill-on-close Job is destroyed.
    script = script.replace('      exit 0', '      Start-Sleep -Seconds 60; exit 0')
    // Reproduce a WMI-managed Job independently of CI host policy. Production still asks
    // for breakaway, but trusts only verified WMI provenance if Windows retains a Job.
    if (providerJob) script = script.replace('16777216 -bor 134217728', '134217728')
    const run = spawnSync(
      fixture,
      ['--run-launcher', command.file, Buffer.from(script, 'utf16le').toString('base64')],
      { encoding: 'utf8', timeout: 45000 }
    )
    if (run.error || run.status !== 0)
      throw new Error(run.stderr || run.error?.message || 'Broker lifetime fixture failed')
    const result = JSON.parse(run.stdout)
    fixturePid = parseWindowsGuardBrokerResult(JSON.stringify(result.broker))
    const state = status()
    if (
      !result.launcherJobTerminated ||
      state.guardPid !== fixturePid ||
      state.launchOrigin !== 'local-wmi' ||
      state.active ||
      state.filterCount !== 0 ||
      (providerJob && !state.jobMember)
    )
      throw new Error('Guard did not survive forced app-Job termination with expected WMI origin')
    process.stdout.write(
      JSON.stringify({
        brokerLaunchIntegration: 'passed',
        launcherJobTerminated: true,
        providerJobRequested: providerJob,
        jobMember: state.jobMember,
        creatorPid: state.creatorPid,
        active: state.active,
        filterCount: state.filterCount
      }) + '\n'
    )
  } finally {
    const state = status()
    if (
      state.guardPid &&
      !state.active &&
      state.filterCount === 0 &&
      (fixturePid === undefined || state.guardPid === fixturePid)
    )
      execFileSync(helper, ['recover'], { encoding: 'utf8', timeout: 8000 })
  }
}
