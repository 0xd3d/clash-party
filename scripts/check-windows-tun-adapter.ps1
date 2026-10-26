param([ValidateSet('x64', 'arm64')][string]$Arch)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or !$env:RUNNER_TEMP) {
  throw 'This integration test creates a temporary adapter and is restricted to isolated CI runners.'
}
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
  & "./build/native/windows/$Arch/adapter-selftest.exe" $dll
  if ($LASTEXITCODE -ne 0) { throw "Actual Wintun identity test failed: $LASTEXITCODE" }
} finally {
  Remove-Item -LiteralPath $directory -Recurse -Force
}
