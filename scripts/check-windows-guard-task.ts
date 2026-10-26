// Windows CI only: a temporary same-user task starts an UNARMED helper. Never opens WFP,
// changes DNS, modifies firewall rules or starts a core. Owns and cleans up only this fixture.
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import path from 'node:path'
import { writeFileSync, readFileSync, unlinkSync } from 'node:fs'
import os from 'node:os'
import {
  windowsGuardTaskCommand,
  parseWindowsGuardTaskResult
} from '../src/main/core/windowsGuardTask.ts'

if (process.platform !== 'win32') throw new Error('This integration requires Windows')
const helper = path.resolve('build/native/windows', process.arch, 'party.mihomo.network-guard.exe')
function status() {
  return JSON.parse(execFileSync(helper, ['status'], { encoding: 'utf8', timeout: 8000 }))
}

// CI-only bounded diagnostics. The action starts an unarmed helper; no arm/acquire command.
// Preserve native output from the scheduled context, then test the documented local WMI
// provider with explicit job breakaway. Neither path touches machine network settings.
function diagnoseLaunch() {
  const outputPath = path.join(os.tmpdir(), `clash-guard-diagnostic-${randomUUID()}.json`)
  const payload = Buffer.from(helper, 'utf8').toString('base64')
  const encodedOutput = Buffer.from(outputPath, 'utf8').toString('base64')
  const wrapper = `
$ErrorActionPreference='Stop'
$exe=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${payload}'))
$file=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encodedOutput}'))
$out=(& $exe start | Out-String)
[IO.File]::WriteAllText($file,$out)
exit $LASTEXITCODE
`
  const wrapperArgs =
    '-NoLogo -NoProfile -NonInteractive -EncodedCommand ' +
    Buffer.from(wrapper, 'utf16le').toString('base64')
  const task = windowsGuardTaskCommand(helper, randomUUID(), process.env.SystemRoot)
  let script = Buffer.from(task.args.at(-1)!, 'base64').toString('utf16le')
  script = script.replace(
    "$action.Arguments = 'start'",
    `$action.Path = '${task.file.replaceAll("'", "''")}'\n  $action.Arguments = '${wrapperArgs}'`
  )
  writeFileSync(outputPath, '')
  try {
    try {
      execFileSync(
        task.file,
        [...task.args.slice(0, -1), Buffer.from(script, 'utf16le').toString('base64')],
        { encoding: 'utf8', timeout: 25000 }
      )
    } catch (error) {
      console.error('scheduler diagnostic:', (error as { stdout?: string }).stdout)
    }
    console.error('native scheduled launch:', readFileSync(outputPath, 'utf8'))
    if (status().guardPid) throw new Error('Unexpected existing guard after scheduler diagnostics')
    const wmi = `
$ErrorActionPreference='Stop'
$exe=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${payload}'))
$startup=([wmiclass]'\\\\.\\root\\cimv2:Win32_ProcessStartup').CreateInstance()
$startup.CreateFlags=16777216 -bor 134217728
$startup.ShowWindow=0
$result=([wmiclass]'\\\\.\\root\\cimv2:Win32_Process').Create(('"'+$exe+'" serve'),[IO.Path]::GetDirectoryName($exe),$startup)
if($result.ReturnValue -ne 0){throw ('WMI local creation failed: '+$result.ReturnValue)}
Start-Sleep -Milliseconds 500
$state=(& $exe status | Out-String)|ConvertFrom-Json
@{wmiReturn=$result.ReturnValue;pid=$result.ProcessId;callerSession=[Diagnostics.Process]::GetCurrentProcess().SessionId;state=$state}|ConvertTo-Json -Compress -Depth 8
`
    console.error(
      'local WMI diagnostic:',
      execFileSync(
        task.file,
        [...task.args.slice(0, -1), Buffer.from(wmi, 'utf16le').toString('base64')],
        { encoding: 'utf8', timeout: 12000 }
      )
    )
  } finally {
    unlinkSync(outputPath)
  }
}

if (process.argv.includes('--launch')) {
  const command = windowsGuardTaskCommand(helper, randomUUID(), process.env.SystemRoot)
  let stdout: string
  try {
    stdout = execFileSync(command.file, command.args, { encoding: 'utf8', timeout: 25000 })
  } catch (error) {
    const output = (error as { stdout?: string }).stdout
    diagnoseLaunch()
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
