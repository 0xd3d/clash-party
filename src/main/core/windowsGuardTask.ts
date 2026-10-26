import path from 'node:path'

/** This task runs only the packaged helper's fixed `start` command, without profile data. */
export function windowsGuardTaskCommand(
  helper: string,
  taskId: string,
  systemRoot = 'C:\\Windows'
): { file: string; args: string[] } {
  if (
    !/^[A-Za-z]:\\/.test(helper) ||
    helper.includes('"') ||
    [...helper].some((character) => character.charCodeAt(0) < 32) ||
    path.win32.basename(helper) !== 'party.mihomo.network-guard.exe'
  )
    throw new Error('Invalid installed Windows guard path')
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(taskId))
    throw new Error('Invalid guard launch task identity')
  const encodedPath = Buffer.from(helper, 'utf8').toString('base64')
  // The Scheduler owns this short-lived launcher, not Electron's inherited Job. The native
  // `start` command still checks that the actual guard escaped EVERY Job before resuming it.
  // No triggers, saved password, SYSTEM identity, permanent service, WFP changes or recovery.
  const script = String.raw`
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$name = 'ClashParty-NetworkGuard-${taskId}'
$created = $false
$removed = $false
$reason = $null
$taskResult = $null
try {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The guard launcher requires the current elevated user'
  }
  $session = [Diagnostics.Process]::GetCurrentProcess().SessionId
  if ($session -le 0) { throw 'The guard launcher requires an interactive Windows session' }
  $scheduler = New-Object -ComObject 'Schedule.Service'
  $scheduler.Connect()
  $folder = $scheduler.GetFolder('\')
  $definition = $scheduler.NewTask(0)
  $definition.RegistrationInfo.Description = 'Clash Party temporary network guard launcher; no automatic triggers.'
  $definition.Principal.UserId = $identity.User.Value
  $definition.Principal.LogonType = 3
  $definition.Principal.RunLevel = 1
  $settings = $definition.Settings
  $settings.Enabled = $true
  $settings.AllowDemandStart = $true
  $settings.DisallowStartIfOnBatteries = $false
  $settings.StopIfGoingOnBatteries = $false
  $settings.AllowHardTerminate = $false
  $settings.RunOnlyIfNetworkAvailable = $false
  $settings.RunOnlyIfIdle = $false
  $settings.ExecutionTimeLimit = 'PT30S'
  $settings.MultipleInstances = 2
  $action = $definition.Actions.Create(0)
  $action.Path = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encodedPath}'))
  $action.Arguments = 'start'
  $action.WorkingDirectory = [IO.Path]::GetDirectoryName($action.Path)
  # TASK_CREATE | TASK_DONT_ADD_PRINCIPAL_ACE. Never replace an existing task, and restrict
  # running/modifying this elevated launcher to administrators and SYSTEM.
  $task = $folder.RegisterTaskDefinition($name, $definition, 18, $identity.User.Value, $null, 3, 'D:P(A;;GA;;;SY)(A;;GA;;;BA)')
  $created = $true
  $running = $task.RunEx($null, 4, $session, $null)
  $deadline = [DateTime]::UtcNow.AddSeconds(12)
  do {
    Start-Sleep -Milliseconds 100
    $running.Refresh()
    if ([DateTime]::UtcNow -gt $deadline) { throw 'Task Scheduler guard launch timed out; retry status before starting again' }
  } while ($running.State -eq 2 -or $running.State -eq 4)
  $taskResult = [long]$task.LastTaskResult
  if ($taskResult -ne 0) { throw ('Task Scheduler guard launcher exited with code ' + $taskResult) }
} catch {
  $reason = $_.Exception.Message
} finally {
  if ($created) {
    try { $folder.DeleteTask($name, 0); $removed = $true }
    catch { $reason = (($reason + '; temporary task cleanup failed: ' + $_.Exception.Message).TrimStart(';', ' ')) }
  }
}
if ($reason) {
  [Console]::WriteLine((@{ protocolVersion = 1; error = $reason; taskRemoved = $removed } | ConvertTo-Json -Compress))
  exit 1
}
[Console]::WriteLine((@{ protocolVersion = 1; taskResult = $taskResult; taskRemoved = $removed } | ConvertTo-Json -Compress))
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

export function parseWindowsGuardTaskResult(raw: string): void {
  const value: unknown = JSON.parse(raw.replace(/^\uFEFF/, '').trim())
  if (
    !value ||
    typeof value !== 'object' ||
    !('protocolVersion' in value) ||
    value.protocolVersion !== 1
  )
    throw new Error('Unconfirmed Windows guard launch task response')
  if ('error' in value && typeof value.error === 'string')
    throw new Error(`Windows guard launch: ${value.error.slice(0, 512)}`)
  if (
    !('taskResult' in value) ||
    value.taskResult !== 0 ||
    !('taskRemoved' in value) ||
    value.taskRemoved !== true
  )
    throw new Error('Windows guard launch task did not confirm completion and cleanup')
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
