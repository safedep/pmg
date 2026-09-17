# msi_e2e_test.ps1 - exercise the pmg MSI on a disposable Windows CI runner.
#
# PMG_MSI names the installer under test and PMG_MSI_VERSION the version its
# pmg.exe reports. PMG_MSI_UPGRADE and PMG_MSI_UPGRADE2, with their _VERSION
# variables, name further installers with the same product version, a new
# product code each and a binary that reports a different version, the shape
# of the next edge builds. PMG_MSI_LOG_DIR, when set, receives the installer
# logs for the CI artifact.
#
# The test covers the failure paths as well as the happy path. A managed
# config that pmg did not write makes `pmg setup install --system` fail
# after it has written the shims. A first install that fails this way must
# leave no shims and no PATH entry behind. The same failure over a system
# install made by hand must leave that install working. A failed upgrade
# must leave the previous install in place. Each upgrade, and the uninstall,
# runs while a pmg.exe process of every earlier build still holds its image,
# so the move-aside path and its per-product backups are exercised too.
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
foreach ($name in 'PMG_MSI_UPGRADE', 'PMG_MSI_UPGRADE2') {
  $path = (Get-Item -Path "Env:$name" -ErrorAction SilentlyContinue).Value
  $version = (Get-Item -Path "Env:${name}_VERSION" -ErrorAction SilentlyContinue).Value
  if ($path -and -not $version) {
    [Console]::Error.WriteLine("Error: ${name}_VERSION must be set with $name")
    exit 1
  }
}
if ($env:PMG_MSI_UPGRADE2 -and -not $env:PMG_MSI_UPGRADE) {
  [Console]::Error.WriteLine('Error: PMG_MSI_UPGRADE2 requires PMG_MSI_UPGRADE')
  exit 1
}

$TestRoot = "$env:SystemDrive\pmg-msi-e2e-" + [guid]::NewGuid().ToString('N')
New-Item -ItemType Directory -Path $TestRoot | Out-Null
. "$PSScriptRoot\..\..\mdm\tests\e2e_lib_windows.ps1"

$GlobalConfigDir = Split-Path $GlobalConfig
$Proxies = @()

Assert-Elevated
foreach ($msi in $env:PMG_MSI, $env:PMG_MSI_UPGRADE, $env:PMG_MSI_UPGRADE2) {
  if ($msi) { Assert-PathPresent $msi }
}
Assert-PathAbsent $ProductDir
Assert-PathAbsent $GlobalConfigDir

# ERROR_INSTALL_FAILURE. Windows Installer returns it after a rollback.
$InstallFailure = 1603
# ERROR_SUCCESS_REBOOT_REQUIRED. Windows Installer returns it when its
# InstallValidate check saw pmg.exe in use. That check does not catch a
# running process every time, so an upgrade under a live proxy returns 0 or
# 3010. MoveAside renames the file either way, so the test checks the new
# file and the pending operations after the upgrade instead of the code.
$RebootRequired = 3010

function Invoke-Msiexec {
  param([string[]]$ArgumentList, [string]$Log, [int[]]$ExpectedExitCode = @(0))
  $process = Start-Process -FilePath msiexec.exe -ArgumentList ($ArgumentList + @('/qn', '/l*v', $Log)) -Wait -PassThru
  if ($process.ExitCode -notin $ExpectedExitCode) {
    Get-Content -LiteralPath $Log | Where-Object { $_ -match 'Doing action: (MoveAside|SetupInstall|CleanStale|CleanOld|SetupRemove)|return value 3|in use|Reboot' } |
      ForEach-Object { Write-Host "  | $_" }
    Get-Content -LiteralPath $Log | Select-Object -Last 40 | ForEach-Object { Write-Host "  | $_" }
    Stop-OnFailure "msiexec $($ArgumentList -join ' ') exited with $($process.ExitCode), expected $($ExpectedExitCode -join ' or ')"
  }
}

function Assert-NoPendingRename {
  $key = Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
  $pending = @($key.GetValue('PendingFileRenameOperations', @()) | Where-Object { $_ -like '*safedep\pmg*' })
  if ($pending) { Stop-OnFailure "a file operation for pmg waits for a restart: $($pending -join ' | ')" }
}

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
  Assert-NoShims
  Assert-Equal 0 @(Get-ProductEntry).Count 'pmg entries in Apps & Features'
}

function Assert-MsiUninstalled {
  Assert-MsiUnregistered
  Assert-PathAbsent $ProductDir
  Assert-PathAbsent "$env:ProgramFiles\safedep"
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

# A system install made by hand, the way docs/system-install.md describes:
# the binary copied into place, then `pmg setup install --system`. An
# administrative install of the MSI extracts the binary without any
# registration.
function Install-BySystemCommand {
  param([string]$Msi)
  $extract = "$TestRoot\admin"
  Invoke-Msiexec -ArgumentList @('/a', $Msi, "TARGETDIR=$extract") -Log "$TestRoot\admin.log"
  $source = Get-ChildItem -Path $extract -Recurse -Filter pmg.exe | Select-Object -First 1
  if (-not $source) { Stop-OnFailure "the administrative install of $Msi extracted no pmg.exe" }
  New-Item -ItemType Directory -Path $ProductDir -Force | Out-Null
  Copy-Item -LiteralPath $source.FullName -Destination $PmgExe
  $result = Invoke-Pmg -ArgumentList @('setup', 'install', '--system')
  Assert-Equal 0 $result.ExitCode 'pmg setup install --system exit code'
}

# One proxy per installed build. Each holds its image until the test stops
# it. A separate state file lets several run at once.
function Start-Proxy {
  param([string]$Name)
  $process = Start-Process -FilePath $PmgExe -ArgumentList @('proxy', 'start', '--state', "$TestRoot\proxy-$Name.state", '--host', '127.0.0.1', '--port', '0') -PassThru `
    -RedirectStandardOutput "$TestRoot\proxy-$Name.out" -RedirectStandardError "$TestRoot\proxy-$Name.err"
  Start-Sleep -Seconds 3
  if ($process.HasExited) {
    Get-Content -LiteralPath "$TestRoot\proxy-$Name.out", "$TestRoot\proxy-$Name.err" | ForEach-Object { Write-Host "  | $_" }
    Stop-OnFailure "the $Name proxy exited with $($process.ExitCode)"
  }
  return $process
}

function Assert-ProxiesRunning {
  foreach ($proxy in $Proxies) {
    if ($proxy.HasExited) { Stop-OnFailure "a proxy started before an upgrade exited with $($proxy.ExitCode)" }
  }
}

function Stop-Proxies {
  foreach ($proxy in $Proxies) {
    if (-not $proxy.HasExited) {
      Stop-Process -Id $proxy.Id -Force
      $proxy.WaitForExit()
    }
  }
}

function Invoke-Cleanup {
  $ErrorActionPreference = 'Continue'
  Stop-Proxies
  foreach ($msi in $env:PMG_MSI_UPGRADE2, $env:PMG_MSI_UPGRADE, $env:PMG_MSI) {
    if ($msi) { Start-Process -FilePath msiexec.exe -ArgumentList @('/x', $msi, '/qn') -Wait | Out-Null }
  }
  if ($env:PMG_MSI_LOG_DIR) {
    New-Item -ItemType Directory -Path $env:PMG_MSI_LOG_DIR -Force | Out-Null
    Copy-Item -Path "$TestRoot\*.log", "$TestRoot\*.out", "$TestRoot\*.err" -Destination $env:PMG_MSI_LOG_DIR -ErrorAction SilentlyContinue
  }
  Remove-Item -LiteralPath "$env:ProgramData\safedep" -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $TestRoot -Recurse -Force -ErrorAction SilentlyContinue
}

# Upgrade to the next build while every earlier build still runs. The first
# attempt fails at the config step and must leave the current build in
# place. The second succeeds.
function Invoke-Upgrade {
  param([string]$Msi, [string]$FromVersion, [string]$ToVersion, [int]$Backups, [string]$Name)
  Write-Step "an upgrade to $Msi that fails at the config step keeps the previous install"
  Set-UntrustedConfig
  Invoke-Msiexec -ArgumentList @('/i', $Msi) -Log "$TestRoot\upgrade-$Name-fail.log" -ExpectedExitCode $InstallFailure
  Assert-PathPresent "$ProductDir\bin\npm.cmd"
  Assert-Version $FromVersion
  Assert-Equal 1 @(Get-ProductEntry).Count 'pmg entries in Apps & Features after a failed upgrade'
  Assert-Equal ($Backups - 1) @(Get-Backup).Count 'pmg.exe backups after a failed upgrade'
  Assert-ProxiesRunning
  Remove-Item -LiteralPath $GlobalConfig -Force

  Write-Step "upgrading to $Msi"
  Invoke-Msiexec -ArgumentList @('/i', $Msi) -Log "$TestRoot\upgrade-$Name.log" -ExpectedExitCode @(0, $RebootRequired)
  Assert-MsiInstalled -Version $ToVersion -Backups $Backups
  Assert-NoPendingRename
  Assert-ProxiesRunning
}

try {
  Write-Step 'a first install that fails at the config step leaves no shims behind'
  New-UntrustedConfig
  Invoke-Msiexec -ArgumentList @('/i', $env:PMG_MSI) -Log "$TestRoot\install-fail.log" -ExpectedExitCode $InstallFailure
  Assert-PathAbsent $PmgExe
  Assert-NoShims
  Assert-Equal 0 @(Get-ProductEntry).Count 'pmg entries in Apps & Features after a failed install'
  Remove-Item -LiteralPath "$env:ProgramData\safedep" -Recurse -Force

  Write-Step 'a system install made by hand'
  Install-BySystemCommand -Msi $env:PMG_MSI
  Assert-SystemInstall -Version $env:PMG_MSI_VERSION

  Write-Step 'an install over it that fails at the config step leaves it working'
  Set-UntrustedConfig
  Invoke-Msiexec -ArgumentList @('/i', $env:PMG_MSI) -Log "$TestRoot\install-over-fail.log" -ExpectedExitCode $InstallFailure
  Assert-PathPresent "$ProductDir\bin\npm.cmd"
  Assert-Version $env:PMG_MSI_VERSION
  Assert-Equal 0 @(Get-ProductEntry).Count 'pmg entries in Apps & Features after a failed install over a system install'
  Assert-Equal 0 @(Get-Backup).Count 'pmg.exe backups after a failed install over a system install'
  Remove-Item -LiteralPath $GlobalConfig -Force

  Write-Step "installing $env:PMG_MSI over the system install"
  Invoke-Msiexec -ArgumentList @('/i', $env:PMG_MSI) -Log "$TestRoot\install.log"
  Assert-MsiInstalled -Version $env:PMG_MSI_VERSION -Backups 0
  $installed = $env:PMG_MSI

  if ($env:PMG_MSI_UPGRADE) {
    Write-Step 'starting a proxy so a pmg.exe process holds the first image'
    $Proxies += Start-Proxy -Name 'first'
    Invoke-Upgrade -Msi $env:PMG_MSI_UPGRADE -FromVersion $env:PMG_MSI_VERSION -ToVersion $env:PMG_MSI_UPGRADE_VERSION -Backups 1 -Name 'second'
    $installed = $env:PMG_MSI_UPGRADE
  }

  if ($env:PMG_MSI_UPGRADE2) {
    Write-Step 'starting a proxy so a pmg.exe process holds the second image too'
    $Proxies += Start-Proxy -Name 'second'
    Invoke-Upgrade -Msi $env:PMG_MSI_UPGRADE2 -FromVersion $env:PMG_MSI_UPGRADE_VERSION -ToVersion $env:PMG_MSI_UPGRADE2_VERSION -Backups 2 -Name 'third'
    $installed = $env:PMG_MSI_UPGRADE2
  }

  Write-Step "uninstalling $installed"
  if ($Proxies) {
    Invoke-Msiexec -ArgumentList @('/x', $installed) -Log "$TestRoot\uninstall.log" -ExpectedExitCode @(0, $RebootRequired)
    Assert-MsiUnregistered
    Assert-PathPresent $PmgExe
    Stop-Proxies
    Remove-Item -LiteralPath "$env:ProgramFiles\safedep" -Recurse -Force
  } else {
    Invoke-Msiexec -ArgumentList @('/x', $installed) -Log "$TestRoot\uninstall.log"
    Assert-MsiUninstalled
  }
  Write-Host 'PASS: MSI install, install over a system install, upgrades under running processes, their failures, and uninstall'
} finally {
  Invoke-Cleanup
}
