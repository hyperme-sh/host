$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'Disposable Windows CI only' }
$fixture = Join-Path $env:RUNNER_TEMP ('hypermesh-crash-unit-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null
$exe = Join-Path $fixture 'machineidentity.test.exe'
go test -c -o $exe ./internal/machineidentity
if ($LASTEXITCODE -ne 0) { throw 'Unit contract compilation failed' }
$script = Join-Path $fixture 'run.ps1'
@'
param([string]$Fixture)
$env:HYPERMESH_WINDOWS_UNIT_CONTRACT = '1'
& (Join-Path $Fixture 'machineidentity.test.exe') '-test.v' '-test.timeout=2m' *> (Join-Path $Fixture 'output.txt')
$code = $LASTEXITCODE
[IO.File]::WriteAllText((Join-Path $Fixture 'exit.txt'), [string]$code)
exit $code
'@ | Set-Content -LiteralPath $script
$name = 'HypermeshCrashUnit-' + [guid]::NewGuid().ToString('N')
# Occupy the former public name to prove it cannot block the private lock.
$oldLock = New-Object Threading.Mutex($false, 'Global\HypermeshCrashServiceStoreV1')
try {
  $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$script`" -Fixture `"$fixture`""
  $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 3)
  Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $settings | Out-Null
  Start-ScheduledTask -TaskName $name
  $deadline = (Get-Date).AddMinutes(3)
  while (!(Test-Path (Join-Path $fixture 'exit.txt')) -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 1 }
  if (Test-Path (Join-Path $fixture 'output.txt')) { Get-Content (Join-Path $fixture 'output.txt') }
  if (!(Test-Path (Join-Path $fixture 'exit.txt')) -or (Get-Content (Join-Path $fixture 'exit.txt')) -ne '0') { throw 'LocalSystem unit contract failed' }
} finally {
  Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
  $oldLock.Dispose()
  Remove-Item -LiteralPath $fixture -Recurse -Force
}
