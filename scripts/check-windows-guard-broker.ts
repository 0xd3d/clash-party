// Windows CI only. Starts an UNARMED helper: no WFP, DNS, firewall or core changes.
// The native serve command rejects every inherited Job before creating its authenticated pipe.
import { execFileSync } from 'node:child_process'
import path from 'node:path'
import {
  windowsGuardBrokerCommand,
  parseWindowsGuardBrokerResult
} from '../src/main/core/windowsGuardBroker.ts'
if (process.platform !== 'win32') throw new Error('This integration requires Windows')
const helper = path.resolve('build/native/windows', process.arch, 'party.mihomo.network-guard.exe')
const status = () =>
  JSON.parse(execFileSync(helper, ['status'], { encoding: 'utf8', timeout: 8000 }))
if (process.argv.includes('--launch')) {
  const command = windowsGuardBrokerCommand(helper, process.env.SystemRoot)
  let raw: string
  try {
    raw = execFileSync(command.file, command.args, { encoding: 'utf8', timeout: 25000 })
  } catch (error) {
    const output = (error as { stdout?: string }).stdout
    if (output) parseWindowsGuardBrokerResult(output)
    throw error
  }
  const pid = parseWindowsGuardBrokerResult(raw),
    state = status()
  if (state.guardPid !== pid || state.active || state.filterCount !== 0)
    throw new Error('Unarmed guard readiness failed')
  process.stdout.write(JSON.stringify(state) + '\n')
} else {
  if (status().guardPid !== null) throw new Error('Refusing to test with an existing guard')
  let fixturePid: number | undefined
  try {
    const output = execFileSync(
      process.execPath,
      ['--experimental-transform-types', process.argv[1], '--launch'],
      { encoding: 'utf8', timeout: 40000 }
    )
    fixturePid = JSON.parse(output).guardPid
    const state = status()
    if (!fixturePid || state.guardPid !== fixturePid || state.active || state.filterCount !== 0)
      throw new Error('Independent guard did not survive launcher exit')
    process.stdout.write(
      JSON.stringify({
        brokerLaunchIntegration: 'passed',
        launcherExited: true,
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
