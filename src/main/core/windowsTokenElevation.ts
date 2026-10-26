import path from 'node:path'

/** Read only this app's actual process token. No group/service/driver command heuristics. */
export function windowsTokenProbe(
  pid: number,
  systemRoot: string
): { file: string; args: string[] } {
  if (!Number.isSafeInteger(pid) || pid <= 0 || pid > 0xffffffff)
    throw new Error('Invalid process ID for Windows elevation check')
  const script = String.raw`
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
try {
  Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class ClashPartyTokenProbe {
  [DllImport("kernel32.dll", SetLastError=true)]
  private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
  [DllImport("advapi32.dll", SetLastError=true)]
  private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
  [DllImport("advapi32.dll", SetLastError=true)]
  private static extern bool GetTokenInformation(IntPtr token, int kind, out uint elevated, uint size, out uint returned);
  [DllImport("kernel32.dll")]
  private static extern bool CloseHandle(IntPtr handle);
  private static Win32Exception Failure(string operation) {
    int code = Marshal.GetLastWin32Error();
    return new Win32Exception(code, operation + " failed (" + code + ")");
  }
  public static bool IsElevated(uint pid) {
    IntPtr process = OpenProcess(0x1000, false, pid);
    if (process == IntPtr.Zero) throw Failure("Open app process token target");
    IntPtr token = IntPtr.Zero;
    try {
      if (!OpenProcessToken(process, 0x0008, out token))
        throw Failure("Open app access token");
      uint elevated, returned;
      if (!GetTokenInformation(token, 20, out elevated, 4, out returned))
        throw Failure("Read app TokenElevation");
      if (returned != 4) throw new InvalidOperationException("Invalid TokenElevation size");
      return elevated != 0;
    } finally {
      if (token != IntPtr.Zero) CloseHandle(token);
      CloseHandle(process);
    }
  }
}
'@
  $elevated = [ClashPartyTokenProbe]::IsElevated(${pid})
  @{ protocolVersion = 1; processId = ${pid}; elevated = $elevated } | ConvertTo-Json -Compress
} catch {
  @{ protocolVersion = 1; processId = ${pid}; error = $_.Exception.Message } | ConvertTo-Json -Compress
  exit 1
}
`
  return {
    file: path.win32.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
    args: [
      '-NoLogo',
      '-NoProfile',
      '-NonInteractive',
      '-EncodedCommand',
      Buffer.from(script, 'utf16le').toString('base64')
    ]
  }
}

export function parseWindowsTokenElevation(raw: string, expectedPid: number): boolean {
  const data: unknown = JSON.parse(raw.replace(/^\uFEFF/, '').trim())
  if (!data || typeof data !== 'object') throw new Error('Invalid Windows elevation response')
  const value = data as Record<string, unknown>
  if (value.protocolVersion !== 1 || value.processId !== expectedPid)
    throw new Error('Windows elevation response does not match this app process')
  if (typeof value.error === 'string') throw new Error(value.error.slice(0, 512))
  if (typeof value.elevated !== 'boolean') throw new Error('Windows elevation is unconfirmed')
  return value.elevated
}

/** Cache confirmed token results, including false; never turn a probe failure into false. */
export class WindowsElevationCache {
  private pending: Promise<boolean> | null = null
  confirmed: boolean | null = null
  constructor(private readonly read: () => Promise<boolean>) {}
  prime(value: boolean): void {
    if (this.pending) return
    this.confirmed = value
    this.pending = Promise.resolve(value)
  }
  check(): Promise<boolean> {
    if (!this.pending) {
      const pending = Promise.resolve().then(this.read)
      this.pending = pending
      void pending.then(
        (value) => {
          this.confirmed = value
        },
        () => {
          if (this.pending === pending) this.pending = null
        }
      )
    }
    return this.pending
  }
}
