import path from 'node:path'

/** Local WMI starts only the installed helper; no tasks, services, shell or profile arguments. */
export function windowsGuardBrokerCommand(
  helper: string,
  systemRoot = 'C:\\Windows'
): { file: string; args: string[] } {
  if (
    !/^[A-Za-z]:\\/.test(helper) ||
    helper.includes('"') ||
    [...helper].some((character) => character.charCodeAt(0) < 32) ||
    path.win32.basename(helper) !== 'party.mihomo.network-guard.exe'
  )
    throw new Error('Invalid installed Windows guard path')
  if (!/^[A-Za-z]:\\/.test(systemRoot) || /["\r\n]/.test(systemRoot))
    throw new Error('Invalid Windows system directory')
  const encodedPath = Buffer.from(helper, 'utf8').toString('base64')
  // WMI separates the server from Electron's Job. Windows may retain a service quota Job;
  // serve-wmi independently verifies its actual system WMI creator before opening IPC.
  // Native status still authenticates the exact helper path, elevated SID and session.
  const script = String.raw`
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$process = $null
try {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The guard launcher requires the current elevated user'
  }
  $session = [Diagnostics.Process]::GetCurrentProcess().SessionId
  if ($session -le 0) { throw 'The guard launcher requires an interactive Windows session' }
  $exe = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encodedPath}'))
  $startup = ([wmiclass]'\\.\root\cimv2:Win32_ProcessStartup').CreateInstance()
  $startup.CreateFlags = 16777216 -bor 134217728
  $startup.ShowWindow = 0
  $result = ([wmiclass]'\\.\root\cimv2:Win32_Process').Create(('"' + $exe + '" serve-wmi'), [IO.Path]::GetDirectoryName($exe), $startup)
  if ($result.ReturnValue -ne 0 -or !$result.ProcessId) { throw ('Local WMI guard creation failed: ' + $result.ReturnValue) }
  $process = [Diagnostics.Process]::GetProcessById($result.ProcessId)
  $null = $process.Handle # Keep the newly created process identity, including its exit code.
  $deadline = [DateTime]::UtcNow.AddSeconds(8)
  do {
    $raw = (& $exe status | Out-String)
    if ($LASTEXITCODE -ne 0) {
      $failure = $raw | ConvertFrom-Json
      throw ('Native guard authentication failed: ' + $failure.error)
    }
    $state = $raw | ConvertFrom-Json
    if ($state.protocolVersion -ne 1) { throw 'Native guard protocol is unconfirmed' }
    if ($state.guardPid) {
      if ($state.launchOrigin -ne 'local-wmi') { throw 'Native guard did not verify its system WMI creator; check that the application and helper versions match' }
      if ($state.guardPid -ne $result.ProcessId) { throw 'Another guard owns the session; recheck existing protection before retrying' }
      [Console]::WriteLine((@{ protocolVersion = 1; launchMethod = 'local-wmi'; processId = $result.ProcessId; guardPid = $state.guardPid } | ConvertTo-Json -Compress))
      exit 0
    }
    if ($process.HasExited) { throw ('Local WMI guard exited before readiness (code ' + $process.ExitCode + '); no protection was started') }
    if ([DateTime]::UtcNow -ge $deadline) { throw 'Local WMI guard did not confirm readiness; recheck status before retrying' }
    Start-Sleep -Milliseconds 100
  } while ($true)
} catch {
  $failure = $_
  # The WMI call creates a new helper before readiness is authenticated.  Never leave
  # that unarmed process behind after a timeout, protocol mismatch, or identity error.
  # Keep the Process handle from GetProcessById so a reused PID cannot be terminated.
  if ($null -ne $process) {
    try {
      if (!$process.HasExited) {
        $process.Kill()
        $null = $process.WaitForExit(3000)
      }
    } catch {
      # Preserve the original readiness error; the next status call will still expose
      # any helper that could not be terminated.
    }
  }
  [Console]::WriteLine((@{ protocolVersion = 1; error = $failure.Exception.Message } | ConvertTo-Json -Compress))
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

export function parseWindowsGuardBrokerResult(raw: string): number {
  const value: unknown = JSON.parse(raw.replace(/^\uFEFF/, '').trim())
  if (
    !value ||
    typeof value !== 'object' ||
    !('protocolVersion' in value) ||
    value.protocolVersion !== 1
  )
    throw new Error('Unconfirmed Windows guard broker response')
  if ('error' in value && typeof value.error === 'string')
    throw new Error(`Windows guard launch: ${value.error.slice(0, 512)}`)
  if (
    !('launchMethod' in value) ||
    value.launchMethod !== 'local-wmi' ||
    !('processId' in value) ||
    typeof value.processId !== 'number' ||
    !Number.isSafeInteger(value.processId) ||
    value.processId <= 0 ||
    value.processId > 0xffffffff ||
    !('guardPid' in value) ||
    value.guardPid !== value.processId
  )
    throw new Error('Windows guard broker did not confirm the launched helper identity')
  return value.processId
}

export function isWindowsGuardJobFailure(error: unknown): boolean {
  return (
    error instanceof Error &&
    (error.message ===
      'Network protection: Windows retained the guard in a parent job; protection was not started' ||
      error.message ===
        'Network protection: Start independent guard; parent Windows job must permit breakaway failed (5)')
  )
}
