# msi_e2e_test.ps1 - install, upgrade and uninstall the pmg MSI on a
# disposable Windows CI runner. PMG_MSI names the installer under test.
# PMG_MSI_UPGRADE, when set, names a second installer with the same version
# and a new product code, the shape of the next edge build. The test checks
# that it replaces the first in place.
$ErrorActionPreference = 'Stop'

if ($env:CI -ne 'true') {
  [Console]::Error.WriteLine('Error: the MSI E2E installs into Program Files and requires CI=true')
  exit 1
}
if (-not $env:PMG_MSI) {
  [Console]::Error.WriteLine('Error: PMG_MSI must be set')
  exit 1
}

$TestRoot = "$env:SystemDrive\pmg-msi-e2e-" + [guid]::NewGuid().ToString('N')
New-Item -ItemType Directory -Path $TestRoot | Out-Null
. "$PSScriptRoot\..\..\mdm\tests\e2e_lib_windows.ps1"

Assert-Elevated
Assert-PathPresent $env:PMG_MSI
if ($env:PMG_MSI_UPGRADE) { Assert-PathPresent $env:PMG_MSI_UPGRADE }
Assert-PathAbsent $ProductDir

function Invoke-Msiexec {
  param([string[]]$ArgumentList, [string]$Log)
  $process = Start-Process -FilePath msiexec.exe -ArgumentList ($ArgumentList + @('/qn', '/l*v', $Log)) -Wait -PassThru
  if ($process.ExitCode -ne 0) {
    Get-Content -LiteralPath $Log | Select-Object -Last 80 | ForEach-Object { Write-Host "  | $_" }
    Stop-OnFailure "msiexec $($ArgumentList -join ' ') exited with $($process.ExitCode)"
  }
}

function Get-ProductEntry {
  $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
  return @(Get-ChildItem -Path $keys -ErrorAction SilentlyContinue | Get-ItemProperty |
    Where-Object { $_.Publisher -eq 'SafeDep' -and $_.DisplayName -like 'pmg*' })
}

function Assert-MsiInstalled {
  Assert-PathPresent $PmgExe
  Assert-PathPresent "$ProductDir\bin\npm.cmd"
  Assert-PathPresent $GlobalConfig
  $entries = Get-MachinePathEntry
  if ($entries[0] -ine "$ProductDir\bin") { Stop-OnFailure "the shim directory is not first on the machine PATH: $($entries[0])" }
  Assert-Equal 1 @($entries | Where-Object { $_ -ieq $ProductDir }).Count 'product directory entries on the machine PATH'
  foreach ($object in $ProductDir, $PmgExe, "$ProductDir\bin\npm.cmd", $GlobalConfig) { Assert-PmgDescriptor $object }
  $version = Invoke-Pmg -ArgumentList @('version')
  Assert-Equal 0 $version.ExitCode 'pmg version exit code'
  Assert-Equal 1 @(Get-ProductEntry).Count 'pmg entries in Apps & Features'
}

# `pmg setup remove --system` keeps the product directory on the machine PATH
# by design, so the entry is not checked here.
function Assert-MsiUninstalled {
  Assert-PathAbsent $ProductDir
  Assert-PathAbsent "$env:ProgramFiles\safedep"
  Assert-PathAbsent $GlobalConfig
  $entries = Get-MachinePathEntry
  if ($entries | Where-Object { $_ -ieq "$ProductDir\bin" }) { Stop-OnFailure 'the shim directory is still on the machine PATH' }
  Assert-Equal 0 @(Get-ProductEntry).Count 'pmg entries in Apps & Features'
}

function Invoke-Cleanup {
  $ErrorActionPreference = 'Continue'
  foreach ($msi in $env:PMG_MSI_UPGRADE, $env:PMG_MSI) {
    if ($msi) { Start-Process -FilePath msiexec.exe -ArgumentList @('/x', $msi, '/qn') -Wait | Out-Null }
  }
  Remove-Item -LiteralPath $TestRoot -Recurse -Force -ErrorAction SilentlyContinue
}

try {
  Write-Step "installing $env:PMG_MSI"
  Invoke-Msiexec -ArgumentList @('/i', $env:PMG_MSI) -Log "$TestRoot\install.log"
  Assert-MsiInstalled
  $installed = $env:PMG_MSI

  if ($env:PMG_MSI_UPGRADE) {
    Write-Step "upgrading to $env:PMG_MSI_UPGRADE"
    Invoke-Msiexec -ArgumentList @('/i', $env:PMG_MSI_UPGRADE) -Log "$TestRoot\upgrade.log"
    Assert-MsiInstalled
    $installed = $env:PMG_MSI_UPGRADE
  }

  Write-Step "uninstalling $installed"
  Invoke-Msiexec -ArgumentList @('/x', $installed) -Log "$TestRoot\uninstall.log"
  Assert-MsiUninstalled
  Write-Host 'PASS: MSI install, upgrade and uninstall'
} finally {
  Invoke-Cleanup
}
