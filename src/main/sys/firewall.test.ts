import { describe, expect, it, vi } from 'vitest'
import { configureFirewallRules } from './firewall'
const rules = [
  { name: 'mihomo', program: 'C:\\Program Files\\Clash Party\\resources\\sidecar\\mihomo.exe' }
]
const actions = () => ({
  isAdministrator: vi.fn().mockResolvedValue(true),
  execute: vi.fn().mockResolvedValue({ stdout: 'Ok.' }),
  adminRequired: 'Run as administrator',
  commandFailed: 'Inbound rule failed'
})
describe('Windows firewall permission and diagnostic handling', () => {
  it('refuses before any deletion or addition when not elevated', async () => {
    const a = actions()
    a.isAdministrator.mockResolvedValue(false)
    await expect(configureFirewallRules(rules, a)).rejects.toThrow('Run as administrator')
    expect(a.execute).not.toHaveBeenCalled()
  })
  it('passes spaced executable paths as one argument, without a shell or global reset', async () => {
    const a = actions()
    await configureFirewallRules(rules, a)
    expect(a.execute).toHaveBeenNthCalledWith(1, [
      'advfirewall',
      'firewall',
      'delete',
      'rule',
      'name=mihomo',
      `program=${rules[0].program}`
    ])
    expect(a.execute).toHaveBeenNthCalledWith(2, [
      'advfirewall',
      'firewall',
      'add',
      'rule',
      'name=mihomo',
      'dir=in',
      'action=allow',
      `program=${rules[0].program}`,
      'enable=yes',
      'profile=any'
    ])
    expect(a.execute.mock.calls.flat(2)).not.toContain('reset')
  })
  it('retains stdout-only netsh failure text and exit code instead of showing just Command failed', async () => {
    const a = actions()
    const failure = Object.assign(new Error('Command failed: netsh'), {
      code: 1,
      stdout: 'The Windows Defender Firewall service is not running.',
      stderr: ''
    })
    a.execute.mockResolvedValueOnce({ stdout: 'No rules match' }).mockRejectedValueOnce(failure)
    await expect(configureFirewallRules(rules, a)).rejects.toThrow(
      'The Windows Defender Firewall service is not running.'
    )
    expect(a.execute).toHaveBeenCalledTimes(2)
  })
  it('keeps a failed addition a failure and does not attempt subsequent programs', async () => {
    const a = actions()
    a.execute
      .mockResolvedValueOnce({})
      .mockRejectedValueOnce(
        Object.assign(new Error('failed'), { stderr: 'Access denied', code: 5 })
      )
    await expect(
      configureFirewallRules([...rules, { name: 'app', program: 'C:\\App.exe' }], a)
    ).rejects.toThrow('Exit: 5')
    expect(a.execute).toHaveBeenCalledTimes(2)
  })
})
