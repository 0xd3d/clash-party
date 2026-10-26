param([ValidateSet('x64', 'arm64')][string]$Arch)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or !$env:RUNNER_TEMP) {
  throw 'This integration test creates a temporary adapter and is restricted to isolated CI runners.'
}
$coreProcess = $null
$directory = Join-Path $env:RUNNER_TEMP ('clash-wintun-' + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $directory | Out-Null
try {
  $archive = Join-Path $directory 'wintun.zip'
  Invoke-WebRequest -Uri 'https://www.wintun.net/builds/wintun-0.14.1.zip' -OutFile $archive
  $expected = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'
  if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) {
    throw 'Official Wintun archive hash mismatch.'
  }
  Expand-Archive -LiteralPath $archive -DestinationPath $directory
  $dllArch = if ($Arch -eq 'x64') { 'amd64' } else { 'arm64' }
  $dll = Join-Path $directory "wintun/bin/$dllArch/wintun.dll"
  if ((Get-AuthenticodeSignature -LiteralPath $dll).Status -ne 'Valid') {
    throw 'Pinned Wintun DLL signature did not validate.'
  }
  # Exercise the shipped stable core as well as the standalone official driver.
  $coreName = if ($Arch -eq 'x64') { 'amd64-compatible' } else { 'arm64' }
  $coreHash = if ($Arch -eq 'x64') {
    '7aaf636a4f2172dcd8ec34ac4f52797b059195e5afd6409508c963e545f8864d'
  } else { 'a2a26869a14634c49f3fbcecc593b498ed8591fbdd7616b24475b3d60b148da3' }
  $coreZip = Join-Path $directory 'mihomo.zip'
  Invoke-WebRequest -Uri "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.33/mihomo-windows-$coreName-v1.19.33.zip" -OutFile $coreZip
  if ((Get-FileHash -LiteralPath $coreZip -Algorithm SHA256).Hash.ToLowerInvariant() -ne $coreHash) {
    throw 'Pinned Mihomo archive hash mismatch.'
  }
  $coreDirectory = Join-Path $directory 'resources/sidecar'
  Expand-Archive -LiteralPath $coreZip -DestinationPath $coreDirectory
  $core = @(Get-ChildItem -LiteralPath $coreDirectory -Filter '*.exe' -File)
  if ($core.Count -ne 1) { throw 'Expected one pinned core executable.' }
  $corePath = Join-Path $coreDirectory 'mihomo.exe'
  Move-Item -LiteralPath $core[0].FullName -Destination $corePath
  $helperDirectory = Join-Path $directory 'resources/files'
  New-Item -ItemType Directory -Path $helperDirectory | Out-Null
  Copy-Item -LiteralPath "./build/native/windows/$Arch/party.mihomo.network-guard.exe" -Destination $helperDirectory
  $alias = 'ufw' # Reproduce the reported custom alias on a disposable runner.
  if (Get-NetAdapter -IncludeHidden -Name $alias -ErrorAction SilentlyContinue) {
    throw 'Refusing to reuse a pre-existing CI interface.'
  }
  $config = Join-Path $directory 'test.yaml'
  @"
mode: rule
log-level: info
ipv6: false
mixed-port: 0
dns:
  enable: false
tun:
  enable: true
  device: '$alias'
  stack: mixed
  auto-route: false
  strict-route: false
  auto-detect-interface: true
  dns-hijack: []
rules:
  - MATCH,REJECT
"@ | Set-Content -LiteralPath $config -Encoding utf8NoBOM
  $start = [Diagnostics.ProcessStartInfo]::new($corePath)
  $start.UseShellExecute = $false
  $start.CreateNoWindow = $true
  $start.RedirectStandardOutput = $true
  $start.RedirectStandardError = $true
  foreach ($argument in @('-d', $directory, '-f', $config)) { $start.ArgumentList.Add($argument) }
  $coreProcess = [Diagnostics.Process]::Start($start)
  $stdout = $coreProcess.StandardOutput.ReadToEndAsync()
  $stderr = $coreProcess.StandardError.ReadToEndAsync()
  $deadline = [DateTime]::UtcNow.AddSeconds(20)
  $ready = $false
  while ([DateTime]::UtcNow -lt $deadline -and !$coreProcess.HasExited) {
    if (Get-NetAdapter -IncludeHidden -Name $alias -ErrorAction SilentlyContinue) { $ready = $true; break }
    Start-Sleep -Milliseconds 200
  }
  if (!$ready) { throw 'Pinned Mihomo did not create its isolated TUN.' }
  & "./build/native/windows/$Arch/adapter-selftest.exe" '--inspect-created-adapter' $alias
  if ($LASTEXITCODE -ne 0) { throw 'Production identity check rejected the actual pinned Mihomo TUN.' }
  Write-Output 'Actual pinned Mihomo TUN identity passed; no default routes, DNS or proxy access enabled.'
  $physical = @(Get-NetAdapter -IncludeHidden | Where-Object HardwareInterface | Select-Object -First 1)
  if ($physical.Count -ne 1) { throw 'Physical rejection fixture requires one real hardware adapter.' }
  & node --experimental-transform-types ./scripts/check-windows-guard-acquisition.ts $directory $coreProcess.Id $alias $physical[0].Name
  if ($LASTEXITCODE -ne 0) { throw 'Production guard acquisition fixture failed.' }
  & "./build/native/windows/$Arch/adapter-selftest.exe" $dll
  if ($LASTEXITCODE -ne 0) { throw "Actual Wintun identity test failed: $LASTEXITCODE" }
} finally {
  if ($coreProcess) {
    if (!$coreProcess.HasExited) { $coreProcess.Kill(); $coreProcess.WaitForExit(10000) | Out-Null }
    if ($stdout) { Write-Output $stdout.GetAwaiter().GetResult() }
    if ($stderr) { Write-Output $stderr.GetAwaiter().GetResult() }
    $coreProcess.Dispose()
  }
  Remove-Item -LiteralPath $directory -Recurse -Force
}
