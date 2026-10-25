import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { cleanupWindowsNamedPipes } from './process'

const mocks = vi.hoisted(() => ({
  execFile: vi.fn()
}))

vi.mock('child_process', () => ({
  execFile: mocks.execFile
}))

vi.mock('../utils/dirs', () => ({
  mihomoCoreDir: () => 'C:\\Program Files\\Clash Party\\resources\\sidecar'
}))

vi.mock('../utils/logger', () => ({
  managerLogger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() }
}))

vi.mock('./mihomoApi', () => ({
  getAxios: vi.fn()
}))

const tasklistOutput = [
  '"MihomoTray.exe","1001","Console","1","10,000 K"',
  '"mihomo.exe","1002","Console","1","20,000 K"',
  '"mihomo.exe","1003","Console","1","20,000 K"',
  '"Mihomo-Smart.exe","1004","Console","1","20,000 K"',
  '"mihomo-helper.exe","1005","Console","1","20,000 K"',
  '"mihomo.exe","1006","Services","0","20,000 K"'
].join('\r\n')

function mockExecFile(processInfo: unknown, powershellError?: Error): void {
  mocks.execFile.mockImplementation(
    (file: string, _args: string[], _options: unknown, callback) => {
      if (file === 'tasklist') {
        callback(null, { stdout: tasklistOutput, stderr: '' })
      } else if (powershellError) {
        callback(powershellError)
      } else {
        callback(null, { stdout: JSON.stringify(processInfo), stderr: '' })
      }
    }
  )
}

describe('cleanupWindowsNamedPipes', () => {
  let killSpy: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    vi.clearAllMocks()
    killSpy = vi.spyOn(process, 'kill').mockImplementation(() => true)
  })

  afterEach(() => {
    killSpy.mockRestore()
  })

  function terminatedPids(): number[] {
    return killSpy.mock.calls
      .filter(([, signal]) => signal === 'SIGTERM')
      .map(([pid]) => pid as number)
  }

  it('only terminates bundled core executables', async () => {
    mockExecFile([
      {
        ProcessId: 1002,
        ParentProcessId: process.pid,
        ExecutablePath: 'C:\\Program Files\\Clash Party\\resources\\sidecar\\mihomo.exe'
      },
      {
        ProcessId: 1003,
        ParentProcessId: process.pid,
        ExecutablePath: 'D:\\tools\\mihomo\\mihomo.exe'
      },
      {
        ProcessId: 1004,
        ParentProcessId: process.pid,
        ExecutablePath: 'c:\\program files\\clash party\\resources\\sidecar\\MIHOMO-SMART.EXE'
      },
      { ProcessId: 1006, ParentProcessId: process.pid, ExecutablePath: null }
    ])

    await cleanupWindowsNamedPipes()

    expect(terminatedPids()).toEqual([1002, 1004])
    const powershellArgs = mocks.execFile.mock.calls.find(([file]) => file === 'powershell')?.[1]
    expect(powershellArgs?.join(' ')).toContain('Get-CimInstance Win32_Process')
  })

  it('does not terminate another instance using the same installed core', async () => {
    mockExecFile([
      {
        ProcessId: 1002,
        ParentProcessId: process.pid + 1,
        ExecutablePath: 'C:\\Program Files\\Clash Party\\resources\\sidecar\\mihomo.exe'
      }
    ])
    await cleanupWindowsNamedPipes()
    expect(terminatedPids()).toEqual([])
  })

  it('does not terminate a process on malformed inspection output', async () => {
    mockExecFile(null)
    mocks.execFile.mockImplementation((file, _args, _options, callback) =>
      callback(null, { stdout: file === 'tasklist' ? tasklistOutput : '{invalid', stderr: '' })
    )
    await cleanupWindowsNamedPipes()
    expect(terminatedPids()).toEqual([])
  })

  it('skips process inspection when no core executable is running', async () => {
    mocks.execFile.mockImplementation(
      (_file: string, _args: string[], _options: unknown, callback) =>
        callback(null, { stdout: '"MihomoTray.exe","1001","Console","1","10,000 K"', stderr: '' })
    )

    await cleanupWindowsNamedPipes(true)

    expect(mocks.execFile).toHaveBeenCalledTimes(1)
    expect(terminatedPids()).toEqual([])
  })

  it('leaves all unknown processes running when path inspection fails', async () => {
    mockExecFile(null, new Error('powershell unavailable'))

    await cleanupWindowsNamedPipes()

    expect(terminatedPids()).toEqual([])
  })
})
