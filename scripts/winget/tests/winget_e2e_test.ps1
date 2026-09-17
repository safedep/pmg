# winget_e2e_test.ps1 - validate the pmg winget manifests, then install and
# uninstall pmg from them on a disposable Windows CI runner.
#
# PMG_WINGET_MANIFEST_DIR holds the manifests under test and PMG_MSI_VERSION
# is the version the installed pmg.exe reports. The manifests point at an
# installer URL that must be reachable from the runner.
$ErrorActionPreference = 'Stop'

if ($env:CI -ne 'true') {
  [Console]::Error.WriteLine('Error: the winget E2E installs into Program Files and requires CI=true')
  exit 1
}
foreach ($name in 'PMG_WINGET_MANIFEST_DIR', 'PMG_MSI_VERSION') {
  if (-not (Get-Item -Path "Env:$name" -ErrorAction SilentlyContinue).Value) {
    [Console]::Error.WriteLine("Error: $name must be set")
    exit 1
  }
}

$TestRoot = "$env:SystemDrive\pmg-winget-e2e-" + [guid]::NewGuid().ToString('N')
New-Item -ItemType Directory -Path $TestRoot | Out-Null
. "$PSScriptRoot\..\..\msi\tests\msi_lib.ps1"

Assert-Elevated
Assert-PathPresent "$env:PMG_WINGET_MANIFEST_DIR\SafeDep.pmg.installer.yaml"
Assert-PathAbsent $ProductDir
Assert-PathAbsent $GlobalConfigDir

function Invoke-Winget {
  param([string[]]$ArgumentList)
  & winget @ArgumentList --disable-interactivity
  if ($LASTEXITCODE -ne 0) { Stop-OnFailure "winget $($ArgumentList -join ' ') exited with $LASTEXITCODE" }
}

try {
  Write-Step 'validating the manifests'
  Invoke-Winget @('validate', '--manifest', $env:PMG_WINGET_MANIFEST_DIR)

  Write-Step 'installing pmg from the manifests'
  Invoke-Winget @('settings', '--enable', 'LocalManifestFiles')
  Invoke-Winget @('install', '--manifest', $env:PMG_WINGET_MANIFEST_DIR, '--silent', '--accept-package-agreements')
  Assert-MsiInstalled -Version $env:PMG_MSI_VERSION -Backups 0

  Write-Step 'uninstalling pmg'
  Invoke-Winget @('uninstall', '--manifest', $env:PMG_WINGET_MANIFEST_DIR, '--silent')
  Assert-MsiUninstalled
  Write-Host 'PASS: winget manifest validation, install and uninstall'
} finally {
  $ErrorActionPreference = 'Continue'
  foreach ($entry in Get-ProductEntry) { Start-Process -FilePath msiexec.exe -ArgumentList @('/x', $entry.PSChildName, '/qn') -Wait | Out-Null }
  Remove-Item -LiteralPath "$env:ProgramData\safedep" -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $TestRoot -Recurse -Force -ErrorAction SilentlyContinue
}
