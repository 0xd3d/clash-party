import { describe, expect, it, vi } from 'vitest'
import {
  WindowsElevationCache,
  parseWindowsTokenElevation,
  windowsTokenProbe
} from './windowsTokenElevation'
const response = (elevated: boolean, processId = 42) =>
  JSON.stringify({ protocolVersion: 1, processId, elevated })
describe('Windows actual app token elevation', () => {
  it('recognizes elevated and non-elevated tokens without service or driver probes', () => {
    expect(parseWindowsTokenElevation(response(true), 42)).toBe(true)
    expect(parseWindowsTokenElevation(response(false), 42)).toBe(false)
    const probe = windowsTokenProbe(42, String.raw`C:\Windows`)
    expect(probe.file).toBe(String.raw`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`)
    const code = Buffer.from(probe.args.at(-1) ?? '', 'base64').toString('utf16le')
    expect(code).toContain('GetTokenInformation(token, 20')
    expect(code).toContain('IsElevated(42)')
    expect(code).not.toMatch(/fltmc|net session|ExecutionPolicy|Set-ExecutionPolicy/)
  })
  it('rejects another process, malformed data and an unconfirmed result', () => {
    expect(() => parseWindowsTokenElevation(response(true, 43), 42)).toThrow('this app process')
    expect(() => parseWindowsTokenElevation('not json', 42)).toThrow()
    expect(() => parseWindowsTokenElevation('{"protocolVersion":1,"processId":42}', 42)).toThrow(
      'unconfirmed'
    )
    expect(() =>
      parseWindowsTokenElevation('{"protocolVersion":1,"processId":42,"elevated":"true"}', 42)
    ).toThrow('unconfirmed')
    for (const pid of [0, -1, 1.2, Infinity, 0x100000000])
      expect(() => windowsTokenProbe(pid, 'C:\\Windows')).toThrow('Invalid process ID')
  })
  it('propagates policy/token errors instead of reporting non-admin', () => {
    expect(() =>
      parseWindowsTokenElevation(
        '{"protocolVersion":1,"processId":42,"error":"Token query denied (5)"}',
        42
      )
    ).toThrow('Token query denied (5)')
  })
  it('does not permanently cache a timeout or command failure as false', async () => {
    const read = vi.fn().mockRejectedValueOnce(new Error('timeout')).mockResolvedValueOnce(true)
    const cache = new WindowsElevationCache(read)
    await expect(cache.check()).rejects.toThrow('timeout')
    expect(cache.confirmed).toBe(null)
    await expect(cache.check()).resolves.toBe(true)
    expect(read).toHaveBeenCalledTimes(2)
  })
  it('shares concurrent probes and caches only confirmed values', async () => {
    const read = vi.fn().mockResolvedValue(false)
    const cache = new WindowsElevationCache(read)
    expect(await Promise.all([cache.check(), cache.check()])).toEqual([false, false])
    expect(read).toHaveBeenCalledOnce()
    expect(cache.confirmed).toBe(false)
    await expect(cache.check()).resolves.toBe(false)
    expect(read).toHaveBeenCalledOnce()
  })
  it('uses a confirmed synchronous token result without a second command', async () => {
    const read = vi.fn()
    const cache = new WindowsElevationCache(read)
    cache.prime(true)
    await expect(cache.check()).resolves.toBe(true)
    expect(cache.confirmed).toBe(true)
    expect(read).not.toHaveBeenCalled()
  })
})
