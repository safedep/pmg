# choco_e2e_test.ps1 - install, upgrade and uninstall pmg through the
# Chocolatey package on a disposable Windows CI runner.
#
# PMG_NUPKG_DIR holds the packages under test. PMG_CHOCO_VERSION is the
# stable package version to install and PMG_MSI_VERSION the version its
# pmg.exe reports. PMG_CHOCO_UPGRADE_VERSION, when set, is a prerelease
# package in the same directory and PMG_MSI_UPGRADE_VERSION the version its
# pmg.exe reports. The test checks that `choco upgrade pmg` skips the
# prerelease and that `choco upgrade pmg --pre` installs it.
$ErrorActionPreference = 'Stop'

if ($env:CI -ne 'true') {
  [Console]::Error.WriteLine('Error: the Chocolatey E2E installs into Program Files and requires CI=true')
  exit 1
}
foreach ($name in 'PMG_NUPKG_DIR', 'PMG_CHOCO_VERSION', 'PMG_MSI_VERSION') {
  if (-not (Get-Item -Path "Env:$name" -ErrorAction SilentlyContinue).Value) {
    [Console]::Error.WriteLine("Error: $name must be set")
    exit 1
  }
}
if ($env:PMG_CHOCO_UPGRADE_VERSION -and -not $env:PMG_MSI_UPGRADE_VERSION) {
  [Console]::Error.WriteLine('Error: PMG_MSI_UPGRADE_VERSION must be set with PMG_CHOCO_UPGRADE_VERSION')
  exit 1
}

$TestRoot = "$env:SystemDrive\pmg-choco-e2e-" + [guid]::NewGuid().ToString('N')
New-Item -ItemType Directory -Path $TestRoot | Out-Null
. "$PSScriptRoot\..\..\msi\tests\msi_lib.ps1"

Assert-Elevated
Assert-PathPresent "$env:PMG_NUPKG_DIR\pmg.$env:PMG_CHOCO_VERSION.nupkg"
if ($env:PMG_CHOCO_UPGRADE_VERSION) { Assert-PathPresent "$env:PMG_NUPKG_DIR\pmg.$env:PMG_CHOCO_UPGRADE_VERSION.nupkg" }
Assert-PathAbsent $ProductDir
Assert-PathAbsent $GlobalConfigDir

function Invoke-Choco {
  param([string[]]$ArgumentList)
  # --pre lets a pinned prerelease version through. It has no effect on a
  # pinned stable version.
  & choco @ArgumentList --source $env:PMG_NUPKG_DIR --yes --no-progress --pre
  if ($LASTEXITCODE -ne 0) { Stop-OnFailure "choco $($ArgumentList -join ' ') exited with $LASTEXITCODE" }
}

function Assert-ChocoInstalled {
  param([string]$PackageVersion, [string]$Version)
  Assert-Equal "pmg|$PackageVersion" (& choco list --exact pmg --limit-output) 'installed Chocolatey package'
  Assert-MsiInstalled -Version $Version -Backups 0
}

try {
  Write-Step "installing pmg $env:PMG_CHOCO_VERSION"
  Invoke-Choco @('install', 'pmg', '--version', $env:PMG_CHOCO_VERSION)
  Assert-ChocoInstalled -PackageVersion $env:PMG_CHOCO_VERSION -Version $env:PMG_MSI_VERSION

  if ($env:PMG_CHOCO_UPGRADE_VERSION) {
    Write-Step 'an upgrade without --pre keeps the stable version'
    & choco upgrade pmg --source $env:PMG_NUPKG_DIR --yes --no-progress
    if ($LASTEXITCODE -ne 0) { Stop-OnFailure "choco upgrade pmg exited with $LASTEXITCODE" }
    Assert-ChocoInstalled -PackageVersion $env:PMG_CHOCO_VERSION -Version $env:PMG_MSI_VERSION

    Write-Step "an upgrade with --pre installs $env:PMG_CHOCO_UPGRADE_VERSION"
    Invoke-Choco @('upgrade', 'pmg')
    Assert-ChocoInstalled -PackageVersion $env:PMG_CHOCO_UPGRADE_VERSION -Version $env:PMG_MSI_UPGRADE_VERSION
  }

  Write-Step 'uninstalling pmg'
  & choco uninstall pmg --yes
  if ($LASTEXITCODE -ne 0) { Stop-OnFailure "choco uninstall pmg exited with $LASTEXITCODE" }
  Assert-Equal '' "$(& choco list --exact pmg --limit-output)" 'Chocolatey packages after the uninstall'
  Assert-MsiUninstalled
  Write-Host 'PASS: Chocolatey install, upgrade gating, prerelease upgrade and uninstall'
} finally {
  $ErrorActionPreference = 'Continue'
  & choco uninstall pmg --yes | Out-Null
  Remove-Item -LiteralPath "$env:ProgramData\safedep" -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $TestRoot -Recurse -Force -ErrorAction SilentlyContinue
}
