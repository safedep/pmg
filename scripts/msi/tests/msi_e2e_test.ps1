# msi_e2e_test.ps1 - exercise the pmg MSI on a disposable Windows CI runner.
#
# PMG_MSI names the installer under test and PMG_MSI_VERSION the version its
# pmg.exe reports. PMG_MSI_UPGRADE and PMG_MSI_UPGRADE_VERSION, when set,
# name a second installer with the same product version, a new product code
# and a binary that reports a different version, the shape of the next edge
# build.
#
# The test covers the failure paths as well as the happy path. A managed
# config that pmg did not write makes `pmg setup install --system` fail
# after it has written the shims. A first install that fails this way must
# leave no shims and no PATH entry behind. An upgrade that fails this way
# must leave the previous install in place. The upgrade runs while a pmg.exe
# process holds the image, so the move-aside path is exercised too.
$ErrorActionPreference = 'Stop'

if ($env:CI -ne 'true') {
  [Console]::Error.WriteLine('Error: the MSI E2E installs into Program Files and requires CI=true')
  exit 1
}
foreach ($name in 'PMG_MSI', 'PMG_MSI_VERSION') {
  if (-not (Get-Item -Path "Env:$name" -ErrorAction SilentlyContinue).Value) {
    [Console]::Error.WriteLine("Error: $name must be set")
    exit 1
  }
}
if ($env:PMG_MSI_UPGRADE -and -not $env:PMG_MSI_UPGRADE_VERSION) {
  [Console]::Error.WriteLine('Error: PMG_MSI_UPGRADE_VERSION must be set with PMG_MSI_UPGRADE')
  exit 1
}

$TestRoot = "$env:SystemDrive\pmg-msi-e2e-" + [guid]::NewGuid().ToString('N')
New-Item -ItemType Directory -Path $TestRoot | Out-Null
. "$PSScriptRoot\..\..\mdm\tests\e2e_lib_windows.ps1"

$StaleBinary = "$PmgExe.old"
$GlobalConfigDir = Split-Path $GlobalConfig
$Proxy = $null

Assert-Elevated
Assert-PathPresent $env:PMG_MSI
if ($env:PMG_MSI_UPGRADE) { Assert-PathPresent $env:PMG_MSI_UPGRADE }
Assert-PathAbsent $ProductDir
Assert-PathAbsent $GlobalConfigDir

# ERROR_INSTALL_FAILURE. Windows Installer returns it after a rollback.
$InstallFailure = 1603

function Invoke-Msiexec {
  param([string[]]$ArgumentList, [string]$Log, [int]$ExpectedExitCode = 0)
  $process = Start-Process -FilePath msiexec.exe -ArgumentList ($ArgumentList + @('/qn', '/l*v', $Log)) -Wait -PassThru
  if ($process.ExitCode -ne $ExpectedExitCode) {
    Get-Content -LiteralPath $Log | Select-Object -Last 80 | ForEach-Object { Write-Host "  | $_" }
    Stop-OnFailure "msiexec $($ArgumentList -join ' ') exited with $($process.ExitCode), expected $ExpectedExitCode"
  }
}

function Get-ProductEntry {
  $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
  return @(Get-ChildItem -Path $keys -ErrorAction SilentlyContinue | Get-ItemProperty |
    Where-Object { $_.Publisher -eq 'SafeDep' -and $_.DisplayName -like 'pmg*' })
}

function Assert-Version {
  param([string]$Expected)
  $result = Invoke-Pmg -ArgumentList @('version')
  Assert-Equal 0 $result.ExitCode 'pmg version exit code'
  $line = $result.Output | Where-Object { $_ -like 'Version:*' } | Select-Object -First 1
  Assert-Equal "Version: $Expected" $line 'installed pmg version'
}

function Assert-MsiInstalled {
  param([string]$Version)
  Assert-PathPresent $PmgExe
  Assert-PathPresent "$ProductDir\bin\npm.cmd"
  Assert-PathPresent $GlobalConfig
  $entries = Get-MachinePathEntry
  if ($entries[0] -ine "$ProductDir\bin") { Stop-OnFailure "the shim directory is not first on the machine PATH: $($entries[0])" }
  Assert-Equal 1 @($entries | Where-Object { $_ -ieq $ProductDir }).Count 'product directory entries on the machine PATH'
  foreach ($object in $ProductDir, $PmgExe, "$ProductDir\bin\npm.cmd", $GlobalConfig) { Assert-PmgDescriptor $object }
  Assert-Version $Version
  Assert-Equal 1 @(Get-ProductEntry).Count 'pmg entries in Apps & Features'
}

# `pmg setup remove --system` keeps the product directory on the machine PATH
# by design, so that entry is not checked here.
function Assert-NoShims {
  Assert-PathAbsent "$ProductDir\bin"
  if (Get-MachinePathEntry | Where-Object { $_ -ieq "$ProductDir\bin" }) { Stop-OnFailure 'the shim directory is still on the machine PATH' }
}

function Assert-MsiUninstalled {
  Assert-PathAbsent $ProductDir
  Assert-PathAbsent "$env:ProgramFiles\safedep"
  Assert-PathAbsent $GlobalConfig
  Assert-NoShims
  Assert-Equal 0 @(Get-ProductEntry).Count 'pmg entries in Apps & Features'
}

# A managed config that pmg did not write. `pmg setup install --system`
# refuses it after the shims are in place, so the install fails at the
# config step.
function New-UntrustedConfig {
  New-Item -ItemType Directory -Path $GlobalConfigDir -Force | Out-Null
  Set-Content -LiteralPath $GlobalConfig -Value 'paranoid: true' -Encoding Ascii
}

# Widen the DACL of the managed config. The install requires the exact PMG
# descriptor, so the next `pmg setup install --system` fails at the config
# step.
function Set-UntrustedConfig {
  & icacls $GlobalConfig /grant '*S-1-5-32-545:F' | Out-Null
  if ($LASTEXITCODE -ne 0) { Stop-OnFailure 'icacls could not widen the managed config' }
}

function Start-Proxy {
  $process = Start-Process -FilePath $PmgExe -ArgumentList @('proxy', 'start', '--host', '127.0.0.1', '--port', '0') -PassThru `
    -RedirectStandardOutput "$TestRoot\proxy.out" -RedirectStandardError "$TestRoot\proxy.err"
  Start-Sleep -Seconds 3
  if ($process.HasExited) {
    Get-Content -LiteralPath "$TestRoot\proxy.out", "$TestRoot\proxy.err" | ForEach-Object { Write-Host "  | $_" }
    Stop-OnFailure "the proxy exited with $($process.ExitCode) before the upgrade"
  }
  return $process
}

function Assert-ProxyRunning {
  if ($Proxy.HasExited) { Stop-OnFailure "the proxy started before the upgrade exited with $($Proxy.ExitCode)" }
}

function Invoke-Cleanup {
  $ErrorActionPreference = 'Continue'
  if ($Proxy -and -not $Proxy.HasExited) { Stop-Process -Id $Proxy.Id -Force }
  foreach ($msi in $env:PMG_MSI_UPGRADE, $env:PMG_MSI) {
    if ($msi) { Start-Process -FilePath msiexec.exe -ArgumentList @('/x', $msi, '/qn') -Wait | Out-Null }
  }
  Remove-Item -LiteralPath "$env:ProgramData\safedep" -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $TestRoot -Recurse -Force -ErrorAction SilentlyContinue
}

try {
  Write-Step 'a first install that fails at the config step leaves no shims behind'
  New-UntrustedConfig
  Invoke-Msiexec -ArgumentList @('/i', $env:PMG_MSI) -Log "$TestRoot\install-fail.log" -ExpectedExitCode $InstallFailure
  Assert-PathAbsent $PmgExe
  Assert-NoShims
  Assert-Equal 0 @(Get-ProductEntry).Count 'pmg entries in Apps & Features after a failed install'
  Remove-Item -LiteralPath "$env:ProgramData\safedep" -Recurse -Force

  Write-Step "installing $env:PMG_MSI"
  Invoke-Msiexec -ArgumentList @('/i', $env:PMG_MSI) -Log "$TestRoot\install.log"
  Assert-MsiInstalled -Version $env:PMG_MSI_VERSION
  $installed = $env:PMG_MSI

  if ($env:PMG_MSI_UPGRADE) {
    Write-Step 'starting a proxy so a pmg.exe process holds the image'
    $Proxy = Start-Proxy

    Write-Step 'an upgrade that fails at the config step keeps the previous install'
    Set-UntrustedConfig
    Invoke-Msiexec -ArgumentList @('/i', $env:PMG_MSI_UPGRADE) -Log "$TestRoot\upgrade-fail.log" -ExpectedExitCode $InstallFailure
    Assert-PathPresent "$ProductDir\bin\npm.cmd"
    Assert-Version $env:PMG_MSI_VERSION
    Assert-Equal 1 @(Get-ProductEntry).Count 'pmg entries in Apps & Features after a failed upgrade'
    Assert-ProxyRunning
    Remove-Item -LiteralPath $GlobalConfig -Force

    Write-Step "upgrading to $env:PMG_MSI_UPGRADE"
    Invoke-Msiexec -ArgumentList @('/i', $env:PMG_MSI_UPGRADE) -Log "$TestRoot\upgrade.log"
    Assert-MsiInstalled -Version $env:PMG_MSI_UPGRADE_VERSION
    Assert-PathPresent $StaleBinary
    Assert-ProxyRunning
    Stop-Process -Id $Proxy.Id -Force
    $Proxy.WaitForExit()
    $installed = $env:PMG_MSI_UPGRADE
  }

  Write-Step "uninstalling $installed"
  Invoke-Msiexec -ArgumentList @('/x', $installed) -Log "$TestRoot\uninstall.log"
  Assert-MsiUninstalled
  Write-Host 'PASS: MSI install, failed install, upgrade, failed upgrade and uninstall'
} finally {
  Invoke-Cleanup
}
