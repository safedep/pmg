# Run the multi-file Windows MDM scripts end to end on a disposable Windows
# CI runner. The test uses dummy cloud credentials. A pmg wrapper on PATH
# records cloud login, sync and logout instead of reaching SafeDep Cloud.
# The installer runs once elevated in the runner's session and once as
# SYSTEM, which is how Intune runs it.
$ErrorActionPreference = 'Stop'

if ($env:CI -ne 'true' -or $env:PMG_MDM_E2E -ne '1') {
  [Console]::Error.WriteLine('Error: multifile Windows E2E requires CI=true and PMG_MDM_E2E=1')
  exit 1
}
if (-not $env:PMG_E2E_BINARY -or -not (Test-Path -LiteralPath $env:PMG_E2E_BINARY)) {
  [Console]::Error.WriteLine('Error: PMG_E2E_BINARY must name a built pmg.exe')
  exit 1
}

$ScriptDir = Split-Path -Parent $PSScriptRoot
# Under the system drive root, not the user's Temp: SYSTEM and the
# scheduled-task hop both read it.
$TestRoot = "$env:SystemDrive\pmg-mdm-e2e-" + [guid]::NewGuid().ToString('N')
New-Item -ItemType Directory -Path $TestRoot | Out-Null
. "$PSScriptRoot\e2e_lib_windows.ps1"

$StageDir = "$TestRoot\staged"
$Installer = "$StageDir\pmg_setup_install_windows.ps1"
$Uninstaller = "$StageDir\pmg_uninstall_windows.ps1"
$Credentials = @{ SAFEDEP_API_KEY = $TestApiKey; SAFEDEP_TENANT_ID = $TestTenantId }

Assert-Elevated
New-PmgWrapper
Write-SessionReport

# The installer reads a sibling pmg.exe and config.yml, so stage the scripts
# with both in a temp dir. The repo stays clean.
New-Item -ItemType Directory -Path $StageDir | Out-Null
Copy-Item -LiteralPath "$ScriptDir\windows\lib_windows.ps1", "$ScriptDir\windows\pmg_setup_install_windows.ps1", "$ScriptDir\windows\pmg_uninstall_windows.ps1" -Destination $StageDir
Copy-Item -LiteralPath $env:PMG_E2E_BINARY -Destination "$StageDir\pmg.exe"
Set-Content -LiteralPath "$StageDir\config.yml" -Value "paranoid: true`ncloud:`n  enabled: true" -Encoding Ascii

function Invoke-Cleanup {
  $ErrorActionPreference = 'Continue'
  Invoke-Script -Path $Uninstaller | Out-Null
  Remove-Item -LiteralPath $TestRoot -Recurse -Force -ErrorAction SilentlyContinue
}

function Test-ElevatedInstall {
  Write-Step 'Testing an elevated install with a sibling binary and config'
  Reset-WrapperCapture
  Assert-Equal 0 (Invoke-Script -Path $Installer -Environment $Credentials) 'installer exit code'
  Assert-Installed -ConfigSource "$StageDir\config.yml"
  Assert-CloudCall -Identity $ExpectedIdentity -Expected @('cloud login --from-env', 'cloud sync --timeout 1m') 'cloud calls for the logged-on user'
  Assert-CloudCredential -Identity $ExpectedIdentity
  Assert-NoUnexpectedCloud

  # A redeploy replaces the binary in place and rewrites the managed config.
  Write-Step 'Testing a second install over the first'
  Reset-WrapperCapture
  Set-Content -LiteralPath "$StageDir\config.yml" -Value "paranoid: true`ncloud:`n  enabled: true`ndisable_telemetry: true" -Encoding Ascii
  Assert-Equal 0 (Invoke-Script -Path $Installer -Environment $Credentials) 'second installer exit code'
  Assert-Installed -ConfigSource "$StageDir\config.yml"
  $telemetry = Invoke-Pmg -ArgumentList @('config', 'get', 'disable_telemetry')
  Assert-Equal 'true' ($telemetry.Output | Where-Object { $_ -in 'true', 'false' } | Select-Object -First 1) 'redeployed config value'
  Assert-PathAbsent "$PmgExe.old"
  Assert-NoUnexpectedCloud

  Write-Step 'Testing --cloud-sync-only'
  Reset-WrapperCapture
  Assert-Equal 0 (Invoke-Script -Path $Installer -ArgumentList '--cloud-sync-only' -Environment $Credentials) 'sync-only exit code'
  Assert-CloudCall -Identity $ExpectedIdentity -Expected @('cloud sync --timeout 1m') 'sync-only calls'
  Assert-NoUnexpectedCloud

  # A standard user may shape their own state tree. A junction at its root
  # and one inside it point at a directory the uninstall must not touch.
  Write-Step 'Testing the uninstall with junctions in the user state'
  Reset-WrapperCapture
  $victim = "$TestRoot\victim"
  New-Item -ItemType Directory -Path $victim | Out-Null
  Set-Content -LiteralPath "$victim\keep.txt" -Value 'keep'
  $roaming = "$env:APPDATA\safedep\pmg"
  if (Test-Path -LiteralPath $roaming) { [IO.Directory]::Delete($roaming, $true) }
  New-Item -ItemType Directory -Path (Split-Path $roaming) -Force | Out-Null
  & cmd /c mklink /J $roaming $victim | Out-Null
  $local = "$env:LOCALAPPDATA\safedep\pmg"
  New-Item -ItemType Directory -Path $local -Force | Out-Null
  & cmd /c mklink /J "$local\planted" $victim | Out-Null
  Assert-Equal 0 (Invoke-Script -Path $Uninstaller) 'uninstaller exit code'
  Assert-CloudCall -Identity $ExpectedIdentity -Expected @('cloud logout') 'logout for the logged-on user'
  Assert-NoUnexpectedCloud
  Assert-Uninstalled
  Assert-PathPresent "$victim\keep.txt"
}

# Intune runs the script as SYSTEM. SYSTEM is not a target user, so the only
# cloud calls are the ones the hop makes as the logged-on runner account.
function Test-SystemInstall {
  Write-Step 'Testing an install as SYSTEM'
  Reset-WrapperCapture
  Assert-Equal 0 (Invoke-ScriptAsSystem -Path $Installer -Environment $Credentials) 'SYSTEM installer exit code'
  Assert-Installed -ConfigSource "$StageDir\config.yml"
  Assert-CloudCall -Identity $ExpectedIdentity -Expected @('cloud login --from-env', 'cloud sync --timeout 1m') 'cloud calls made from SYSTEM as the logged-on user'
  Assert-CloudCredential -Identity $ExpectedIdentity
  Assert-NoUnexpectedCloud

  # A partial uninstall or a deleted binary leaves no pmg.exe to run
  # `pmg setup remove --system`. The uninstaller still clears the PATH.
  Write-Step 'Testing the uninstall without pmg.exe'
  Reset-WrapperCapture
  Remove-Item -LiteralPath $PmgExe -Force
  Assert-Equal 0 (Invoke-Script -Path $Uninstaller) 'uninstaller exit code without pmg.exe'
  Assert-Uninstalled
}

# A user in the middle of an install holds pmg.exe open. Windows refuses
# the delete, so the uninstaller moves the file aside and finishes.
function Test-UninstallUnderRunningBinary {
  Write-Step 'Testing the uninstall while pmg.exe runs'
  Reset-WrapperCapture
  Assert-Equal 0 (Invoke-Script -Path $Installer) 'installer exit code'
  $proxy = Start-Process -FilePath $PmgExe -ArgumentList 'proxy', 'start', '--port', '0' -PassThru -WindowStyle Hidden
  try {
    Start-Sleep -Seconds 5
    if ($proxy.HasExited) { Stop-OnFailure "pmg proxy start exited with $($proxy.ExitCode) before the uninstall" }
    Assert-Equal 0 (Invoke-Script -Path $Uninstaller) 'uninstaller exit code under a running pmg.exe'
    Assert-Uninstalled
    $stale = @(Get-ChildItem -Path "$env:SystemRoot\Temp" -Filter 'pmg-*.exe')
    if ($stale.Count -ne 1) { Stop-OnFailure "expected one moved-aside pmg.exe, found $($stale.Count)" }
  } finally {
    Stop-Process -Id $proxy.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    Get-ChildItem -Path "$env:SystemRoot\Temp" -Filter 'pmg-*.exe' | Remove-Item -Force -ErrorAction SilentlyContinue
  }
}

try {
  Invoke-Script -Path $Uninstaller | Out-Null
  Assert-Uninstalled

  Test-ElevatedInstall
  Test-SystemInstall
  Test-UninstallUnderRunningBinary
  Write-Host 'PASS'
} finally {
  Invoke-Cleanup
}
