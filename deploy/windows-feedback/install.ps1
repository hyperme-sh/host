param([Parameter(Mandatory=$true)][string]$Executable, [Parameter(Mandatory=$true)][string]$Config)
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Elevated administrator required' }
$root = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'HypermeshFeedbackService'
if ((Test-Path -LiteralPath $root) -or (Get-Service -Name HypermeshFeedbackGrant -ErrorAction SilentlyContinue)) { throw 'Existing installation must be reviewed explicitly' }
$sourceExe = (Resolve-Path -LiteralPath $Executable).Path
$sourceConfig = (Resolve-Path -LiteralPath $Config).Path
$configuration = Get-Content -LiteralPath $sourceConfig -Raw | ConvertFrom-Json
if ($configuration.version -ne 1 -or $configuration.enabled -ne $false) { throw 'Version 1 disabled configuration required' }
function Protect-InstalledPath([string]$Path, [bool]$Directory) {
  if ($Directory) { $acl = New-Object Security.AccessControl.DirectorySecurity } else { $acl = New-Object Security.AccessControl.FileSecurity }
  $admins = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
  $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
  $acl.SetOwner($admins)
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($sid in @($system, $admins)) {
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'Allow')))
  }
  Set-Acl -LiteralPath $Path -AclObject $acl
}
New-Item -ItemType Directory -Path $root | Out-Null
Protect-InstalledPath $root $true
$targetExe = Join-Path $root 'hypermesh-feedback-service.exe'
$targetConfig = Join-Path $root 'config.json'
Copy-Item -LiteralPath $sourceExe -Destination $targetExe
Copy-Item -LiteralPath $sourceConfig -Destination $targetConfig
Protect-InstalledPath $targetExe $false
Protect-InstalledPath $targetConfig $false
# Installation never starts the service or enables feedback.
New-Service -Name HypermeshFeedbackGrant -DisplayName 'Hypermesh feedback grant' -BinaryPathName ('"' + $targetExe + '"') -StartupType Disabled | Out-Null
