import { describe, expect, it } from 'vitest'
import { getWindowsLoginTaskXml } from './windowsTask'
describe('Windows login task paths', () => {
  it('escapes portable paths as XML text while preserving the requested elevation', () => {
    const xml = getWindowsLoginTaskXml(`D:\\R&D\\O'Brien\\Clash Party.exe`, true)
    expect(xml).toContain('D:\\R&amp;D\\O&apos;Brien\\Clash Party.exe')
    expect(xml).not.toContain('R&D')
    expect(xml).toContain('<RunLevel>HighestAvailable</RunLevel>')
  })
  it('keeps an ordinary login task at least privilege', () => {
    expect(getWindowsLoginTaskXml('C:\\Clash Party.exe', false)).toContain(
      '<RunLevel>LeastPrivilege</RunLevel>'
    )
  })
})
