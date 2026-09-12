# Run the standalone Windows MDM scripts end to end on a disposable Windows
# CI runner. The workflow generates the installer with an embedded config and
# embedded dummy credentials into PMG_E2E_STANDALONE_DIR. No sibling files
# exist, so the installer downloads the release named by PMG_VERSION and
# checks its checksum. A pmg wrapper on PATH records the cloud calls.
$ErrorActionPreference = 'Stop'

if ($env:CI -ne 'true' -or $env:PMG_MDM_E2E -ne '1') {
  [Console]::Error.WriteLine('Error: standalone Windows E2E requires CI=true and PMG_MDM_E2E=1')
  exit 1
}
foreach ($name in 'PMG_E2E_STANDALONE_DIR', 'PMG_E2E_CONFIG', 'PMG_VERSION') {
  if (-not (Get-Item -Path "Env:$name" -ErrorAction SilentlyContinue).Value) {
    [Console]::Error.WriteLine("Error: $name must be set")
    exit 1
  }
}

$TestRoot = "$env:SystemDrive\pmg-mdm-e2e-" + [guid]::NewGuid().ToString('N')
New-Item -ItemType Directory -Path $TestRoot | Out-Null
. "$PSScriptRoot\e2e_lib_windows.ps1"

$Installer = "$env:PMG_E2E_STANDALONE_DIR\pmg_setup_install_windows_standalone.ps1"
$Uninstaller = "$env:PMG_E2E_STANDALONE_DIR\pmg_uninstall_windows_standalone.ps1"
Assert-PathPresent $Installer
Assert-PathPresent $Uninstaller
if (Test-Path -LiteralPath "$env:PMG_E2E_STANDALONE_DIR\pmg.exe") { Stop-OnFailure 'a sibling pmg.exe would skip the download under test' }

Assert-Elevated
New-PmgWrapper
Write-SessionReport

function Invoke-Cleanup {
  $ErrorActionPreference = 'Continue'
  Invoke-Script -Path $Uninstaller | Out-Null
  Remove-Item -LiteralPath $TestRoot -Recurse -Force -ErrorAction SilentlyContinue
}

try {
  Invoke-Script -Path $Uninstaller | Out-Null
  Assert-Uninstalled

  Write-Step "Testing the standalone installer with release $env:PMG_VERSION, embedded config and credentials"
  Reset-WrapperCapture
  Assert-Equal 0 (Invoke-Script -Path $Installer) 'standalone installer exit code'
  Assert-Installed -ConfigSource $env:PMG_E2E_CONFIG
  $version = Invoke-Pmg -ArgumentList @('version')
  $expected = $env:PMG_VERSION.TrimStart('v')
  if (-not ($version.Output | Where-Object { $_ -like "Version:*$expected*" })) { Stop-OnFailure "installed version is not ${expected}: $($version.Output -join ' | ')" }
  Assert-CloudCall -Identity $ExpectedIdentity -Expected @('cloud login --from-env', 'cloud sync --timeout 1m') 'cloud calls with embedded credentials'
  Assert-CloudCredential -Identity $ExpectedIdentity
  Assert-NoUnexpectedCloud

  Write-Step 'Testing the standalone uninstaller'
  Reset-WrapperCapture
  Assert-Equal 0 (Invoke-Script -Path $Uninstaller) 'standalone uninstaller exit code'
  Assert-CloudCall -Identity $ExpectedIdentity -Expected @('cloud logout') 'logout for the logged-on user'
  Assert-NoUnexpectedCloud
  Assert-Uninstalled
  Write-Host 'PASS'
} finally {
  Invoke-Cleanup
}
