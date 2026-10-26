// Windows CI only: a temporary same-user task starts an UNARMED helper. Never opens WFP,
// changes DNS, modifies firewall rules or starts a core. Owns and cleans up only this fixture.
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import path from 'node:path'
import {
  windowsGuardTaskCommand,
  parseWindowsGuardTaskResult
} from '../src/main/core/windowsGuardTask.ts'

if (process.platform !== 'win32') throw new Error('This integration requires Windows')
const helper = path.resolve('build/native/windows', process.arch, 'party.mihomo.network-guard.exe')
function status() {
  return JSON.parse(execFileSync(helper, ['status'], { encoding: 'utf8', timeout: 8000 }))
}
if (process.argv.includes('--launch')) {
  const command = windowsGuardTaskCommand(helper, randomUUID(), process.env.SystemRoot)
  let stdout: string
  try {
    stdout = execFileSync(command.file, command.args, { encoding: 'utf8', timeout: 25000 })
  } catch (error) {
    const output = (error as { stdout?: string }).stdout
    if (output) parseWindowsGuardTaskResult(output)
    throw error
  }
  parseWindowsGuardTaskResult(stdout)
  const state = status()
  if (!state.guardPid || state.active || state.filterCount !== 0)
    throw new Error('Unarmed guard readiness failed')
  process.stdout.write(JSON.stringify(state) + '\n')
} else {
  if (status().guardPid !== null)
    throw new Error('Refusing to test while an existing guard is running')
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
        scheduledLaunchIntegration: 'passed',
        launcherExited: true,
        active: state.active,
        filterCount: state.filterCount
      }) + '\n'
    )
  } finally {
    const state = status()
    // Never recover another owner or an armed guard, even on a failed fixture.
    if (
      state.guardPid &&
      !state.active &&
      state.filterCount === 0 &&
      (fixturePid === undefined || state.guardPid === fixturePid)
    )
      execFileSync(helper, ['recover'], { encoding: 'utf8', timeout: 8000 })
  }
}
