import { execFileSync } from 'node:child_process'
import { readFileSync, mkdtempSync, rmSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { describe, expect, it } from 'vitest'
import { parse } from 'yaml'
import {
  parseDeveloperEnvironment,
  windowsGuardCompilerArguments
} from './build-windows-network-guard.mjs'

describe('Windows guard native build and boundary', () => {
  it('builds the native target with SDK libraries and no kernel driver or persistent installer', () => {
    for (const arch of ['x64', 'arm64']) {
      const args = windowsGuardCompilerArguments(arch, path.join('build', 'native guard.exe'))
      expect(args).toContain(arch === 'x64' ? '/MACHINE:X64' : '/MACHINE:ARM64')
      expect(args).toContain('Fwpuclnt.lib')
      expect(args).toContain('/WX')
      expect(args.some((arg) => arg.endsWith('.sys'))).toBe(false)
    }
    expect(() => windowsGuardCompilerArguments('ia32', 'out.exe')).toThrow('Unsupported')
  })

  it('preserves environment values without printing or evaluating them', () => {
    expect(
      parseDeveloperEnvironment('Path=C:\\Tools\r\nINCLUDE=C:\\SDK\r\nLIB=C:\\Lib\r\nVALUE=x=y')
    ).toEqual({
      PATH: 'C:\\Tools',
      INCLUDE: 'C:\\SDK',
      LIB: 'C:\\Lib',
      VALUE: 'x=y'
    })
    expect(() => parseDeveloperEnvironment('PATH=C:\\Tools')).toThrow('incomplete')
  })

  it('packages the helper only as a Windows resource at the fixed client path', () => {
    const builder = parse(readFileSync(new URL('../electron-builder.yml', import.meta.url), 'utf8'))
    expect(builder.win.extraResources).toContainEqual({
      from: './build/native/windows/${arch}/party.mihomo.network-guard.exe',
      to: 'files/party.mihomo.network-guard.exe'
    })
    expect(JSON.stringify(builder.mac)).not.toContain('windows-network-guard')
  })

  it('keeps the self-test path separate from privileged runtime operations', () => {
    const source = readFileSync(
      new URL('../integrations/windows-network-guard/main.cpp', import.meta.url),
      'utf8'
    )
    const main = source.slice(source.lastIndexOf('int wmain('))
    expect(main.indexOf('L"--self-test"')).toBeLessThan(main.indexOf('elevatedUser('))
    expect(source).toContain('FWPM_SESSION_FLAG_DYNAMIC')
    expect(source).not.toContain('FWPM_FILTER_FLAG_PERSISTENT')
    expect(source).not.toContain('FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT')
    expect(source).not.toMatch(/netsh|MpsSvc|Set-NetFirewallProfile/)
    expect(source).toContain('PIPE_REJECT_REMOTE_CLIENTS')
    expect(source).toContain('FILE_FLAG_FIRST_PIPE_INSTANCE')
    expect(source).toContain(
      'ng::allowTun(candidate.corePid, candidate.process.valid(), candidate.tun.has_value())'
    )
    expect(source).toContain('candidate.tun.reset()')
  })

  it.skipIf(process.platform === 'win32')(
    'runs the portable protocol/policy fixtures without WFP',
    () => {
      const directory = mkdtempSync(path.join(os.tmpdir(), 'clash-network-guard-fixtures-'))
      try {
        const output = path.join(directory, 'policy-selftest')
        execFileSync('c++', [
          '-std=c++17',
          '-Wall',
          '-Wextra',
          '-Werror',
          'integrations/windows-network-guard/policy-selftest.cpp',
          '-o',
          output
        ])
        expect(JSON.parse(execFileSync(output, { encoding: 'utf8' }))).toMatchObject({
          protocolVersion: 1,
          selfTest: 'passed'
        })
      } finally {
        rmSync(directory, { recursive: true, force: true })
      }
    }
  )
})
