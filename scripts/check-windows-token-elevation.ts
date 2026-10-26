// Read-only Windows integration check: no proxy, firewall, BFE, TUN or DNS changes.
import { execFileSync } from 'node:child_process'
import {
  parseWindowsTokenElevation,
  windowsTokenProbe
} from '../src/main/core/windowsTokenElevation.ts'
if (process.platform !== 'win32') throw new Error('Run this check on Windows')
const probe = windowsTokenProbe(process.pid, process.env.SystemRoot || String.raw`C:\Windows`)
const output = execFileSync(probe.file, probe.args, {
  encoding: 'utf8',
  windowsHide: true,
  timeout: 15000
})
const elevated = parseWindowsTokenElevation(output, process.pid)
const reference = execFileSync(
  probe.file,
  [
    '-NoProfile',
    '-NonInteractive',
    '-Command',
    '([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)'
  ],
  { encoding: 'utf8', windowsHide: true, timeout: 15000 }
).trim()
if (reference !== String(elevated).replace(/^./, (x) => x.toUpperCase()))
  throw new Error('Independent Windows principal check disagrees with process TokenElevation')
const missing = windowsTokenProbe(0x7fffffff, process.env.SystemRoot || String.raw`C:\Windows`)
let failed = false
try {
  execFileSync(missing.file, missing.args, { encoding: 'utf8', windowsHide: true, timeout: 15000 })
} catch (error) {
  const stdout = (error as { stdout?: string }).stdout
  try {
    parseWindowsTokenElevation(stdout || '', 0x7fffffff)
  } catch (error) {
    failed =
      error instanceof Error && error.message.includes('Open app process token target failed')
  }
}
if (!failed) throw new Error('Missing process was not reported as a query error')
process.stdout.write(
  JSON.stringify({ tokenElevationIntegration: 'passed', elevated, pid: process.pid, cases: 2 })
)
