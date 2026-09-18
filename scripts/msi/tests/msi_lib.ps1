# msi_lib.ps1 - assertions about a pmg MSI install, shared by the MSI E2E
# and the tests of the packages that wrap the MSI. Set $TestRoot before you
# dot-source this file. It loads the MDM E2E library too.
. "$PSScriptRoot\..\..\mdm\tests\e2e_lib_windows.ps1"

$GlobalConfigDir = Split-Path $GlobalConfig

function Get-ProductEntry {
  $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
  return @(Get-ChildItem -Path $keys -ErrorAction SilentlyContinue | Get-ItemProperty |
    Where-Object { $_.Publisher -eq 'SafeDep' -and $_.DisplayName -like 'pmg*' })
}

function Get-Backup {
  return @(Get-ChildItem -Path "$ProductDir\pmg.exe.old*" -ErrorAction SilentlyContinue)
}

function Assert-Version {
  param([string]$Expected)
  $result = Invoke-Pmg -ArgumentList @('version')
  Assert-Equal 0 $result.ExitCode 'pmg version exit code'
  $line = $result.Output | Where-Object { $_ -like 'Version:*' } | Select-Object -First 1
  Assert-Equal "Version: $Expected" $line 'installed pmg version'
}

function Assert-SystemInstall {
  param([string]$Version)
  Assert-PathPresent $PmgExe
  Assert-PathPresent "$ProductDir\bin\npm.cmd"
  Assert-PathPresent $GlobalConfig
  $entries = Get-MachinePathEntry
  if ($entries[0] -ine "$ProductDir\bin") { Stop-OnFailure "the shim directory is not first on the machine PATH: $($entries[0])" }
  Assert-Equal 1 @($entries | Where-Object { $_ -ieq $ProductDir }).Count 'product directory entries on the machine PATH'
  foreach ($object in $ProductDir, $PmgExe, "$ProductDir\bin\npm.cmd", $GlobalConfig) { Assert-PmgDescriptor $object }
  Assert-Version $Version
}

function Assert-MsiInstalled {
  param([string]$Version, [int]$Backups)
  Assert-SystemInstall -Version $Version
  Assert-Equal 1 @(Get-ProductEntry).Count 'pmg entries in Apps & Features'
  Assert-Equal $Backups @(Get-Backup).Count 'pmg.exe backups next to the binary'
}

# `pmg setup remove --system` keeps the product directory on the machine PATH
# by design, so that entry is not checked here.
function Assert-NoShims {
  Assert-PathAbsent "$ProductDir\bin"
  if (Get-MachinePathEntry | Where-Object { $_ -ieq "$ProductDir\bin" }) { Stop-OnFailure 'the shim directory is still on the machine PATH' }
}

# Everything the uninstall removes even while a pmg.exe process holds its
# image. Windows deletes the locked binary at the next restart.
function Assert-MsiUnregistered {
  Assert-PathAbsent $GlobalConfig
  Assert-Equal 0 @(Get-ChildItem -Path "$GlobalConfigDir\config.yml.rollback*" -ErrorAction SilentlyContinue).Count 'managed config copies after the uninstall'
  Assert-NoShims
  Assert-Equal 0 @(Get-ProductEntry).Count 'pmg entries in Apps & Features'
}

function Assert-MsiUninstalled {
  Assert-MsiUnregistered
  Assert-PathAbsent $ProductDir
  Assert-PathAbsent "$env:ProgramFiles\safedep"
}
