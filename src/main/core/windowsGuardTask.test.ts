import { describe, expect, it } from 'vitest'
import {
  windowsGuardTaskCommand,
  parseWindowsGuardTaskResult,
  isWindowsGuardJobFailure
} from './windowsGuardTask'

const taskId = '0f338f28-fef5-41c3-bf9a-fd77b661a5ec'
describe('temporary Windows guard task', () => {
  it('uses a fixed native start action and encodes paths as data, including shell punctuation', () => {
    const helper = String.raw`C:\Users\It's $(example) & files\resources\files\party.mihomo.network-guard.exe`
    const command = windowsGuardTaskCommand(helper, taskId)
    const script = Buffer.from(command.args.at(-1) ?? '', 'base64').toString('utf16le')
    expect(command.file).toBe(String.raw`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`)
    expect(script).not.toContain(helper)
    expect(script).toContain(Buffer.from(helper, 'utf8').toString('base64'))
    expect(script).toContain("$action.Arguments = 'start'")
    expect(script).toContain('RegisterTaskDefinition($name, $definition, 18,')
    expect(script).toContain('$definition.Principal.LogonType = 3')
    expect(script).toContain('$task.RunEx($null, 4, $session, $null)')
    expect(script).toContain('$folder.DeleteTask($name, 0)')
    expect(script).not.toMatch(
      /Triggers.Create|\.Stop\(|Stop-Process|ExecutionPolicy|netsh|recover|\bSYSTEM identity\b/
    )
  })
  it('rejects nonlocal, unexpected executable and injected task identities', () => {
    for (const helper of [
      'relative.exe',
      String.raw`\\server\guard.exe`,
      String.raw`C:\App\other.exe`,
      'C:\\bad\n\\party.mihomo.network-guard.exe'
    ])
      expect(() => windowsGuardTaskCommand(helper, taskId)).toThrow('path')
    expect(() =>
      windowsGuardTaskCommand(String.raw`C:\App\party.mihomo.network-guard.exe`, "name'; calc")
    ).toThrow('identity')
  })
  it('requires confirmed success and registration cleanup rather than a task registration receipt', () => {
    expect(() =>
      parseWindowsGuardTaskResult('\ufeff{"protocolVersion":1,"taskResult":0,"taskRemoved":true}')
    ).not.toThrow()
    for (const value of [
      {},
      { protocolVersion: 1, taskResult: 0 },
      { protocolVersion: 1, taskResult: 1, taskRemoved: true },
      { protocolVersion: 1, taskResult: 0, taskRemoved: false }
    ])
      expect(() => parseWindowsGuardTaskResult(JSON.stringify(value))).toThrow()
    expect(() =>
      parseWindowsGuardTaskResult('{"protocolVersion":1,"error":"Scheduler service unavailable"}')
    ).toThrow('Scheduler service unavailable')
  })
  it('only retries the native pre-execution job refusal, never arbitrary access or WFP failures', () => {
    expect(
      isWindowsGuardJobFailure(
        new Error(
          'Network protection: Windows retained the guard in a parent job; protection was not started'
        )
      )
    ).toBe(true)
    expect(
      isWindowsGuardJobFailure(
        new Error(
          'Network protection: Start independent guard; parent Windows job must permit breakaway failed (5)'
        )
      )
    ).toBe(true)
    for (const message of [
      'access denied (5)',
      'Network protection: Add owned WFP filter failed (5)',
      'Network protection: Start independent guard; parent Windows job must permit breakaway failed (2)',
      'Guard exited before confirming startup'
    ])
      expect(isWindowsGuardJobFailure(new Error(message))).toBe(false)
  })
})
