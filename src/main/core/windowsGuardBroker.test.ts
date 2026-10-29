import { describe, expect, it } from 'vitest'
import {
  windowsGuardBrokerCommand,
  parseWindowsGuardBrokerResult,
  isWindowsGuardJobFailure
} from './windowsGuardBroker'

describe('local Windows guard broker', () => {
  it('uses local WMI with explicit breakaway and only the fixed native broker command', () => {
    const helper = String.raw`C:\Users\It's $(example) & files\resources\files\party.mihomo.network-guard.exe`
    const command = windowsGuardBrokerCommand(helper)
    const script = Buffer.from(command.args.at(-1) ?? '', 'base64').toString('utf16le')
    expect(command.file).toBe(String.raw`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`)
    expect(script).not.toContain(helper)
    expect(script).toContain(Buffer.from(helper, 'utf8').toString('base64'))
    expect(script).toContain(String.raw`[wmiclass]'\\.\root\cimv2:Win32_Process'`)
    expect(script).toContain('16777216 -bor 134217728')
    expect(script).toContain(`.Create(('"' + $exe + '" serve-wmi')`)
    expect(script).toContain('$state.guardPid -ne $result.ProcessId')
    expect(script).toContain("$state.launchOrigin -ne 'local-wmi'")
    expect(script).toContain('$process.HasExited')
    expect(script).toContain('$process.Kill()')
    expect(script).toContain('$process.WaitForExit(3000)')
    expect(script).toContain('$failure = $_')
    expect(script).toContain('reused PID cannot be terminated')
    expect(script).not.toMatch(
      /Schedule.Service|RegisterTask|Stop-Process|ExecutionPolicy|netsh|recover|Invoke-Expression/
    )
  })
  it('rejects nonlocal or command-injected helper paths and unexpected executables', () => {
    for (const helper of [
      'relative.exe',
      String.raw`\\server\guard.exe`,
      String.raw`C:\App\other.exe`,
      'C:\\bad\n\\party.mihomo.network-guard.exe',
      'C:\\bad"\\party.mihomo.network-guard.exe'
    ])
      expect(() => windowsGuardBrokerCommand(helper)).toThrow('path')
    expect(() =>
      windowsGuardBrokerCommand(String.raw`C:\App\party.mihomo.network-guard.exe`, 'relative')
    ).toThrow('system directory')
  })
  it('requires matching positive process identity, not just successful process creation', () => {
    const good = { protocolVersion: 1, launchMethod: 'local-wmi', processId: 101, guardPid: 101 }
    expect(parseWindowsGuardBrokerResult('\ufeff' + JSON.stringify(good))).toBe(101)
    for (const value of [
      {},
      { ...good, guardPid: null },
      { ...good, guardPid: 102 },
      { ...good, processId: 0, guardPid: 0 },
      { ...good, processId: 1.2, guardPid: 1.2 },
      { ...good, processId: 0x100000000, guardPid: 0x100000000 },
      { ...good, launchMethod: 'remote' },
      { ...good, processId: '101' }
    ])
      expect(() => parseWindowsGuardBrokerResult(JSON.stringify(value))).toThrow()
    expect(() =>
      parseWindowsGuardBrokerResult(
        '{"protocolVersion":1,"error":"Local WMI guard creation failed: 2"}'
      )
    ).toThrow('creation failed: 2')
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
