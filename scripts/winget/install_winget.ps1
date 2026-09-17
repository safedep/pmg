# install_winget.ps1 - make sure winget runs for the current account on a
# Windows machine that has none on PATH. A CI runner image does not always
# register the App Installer package for the account that runs the job, and
# a new account on a client machine gets it at its first interactive logon
# only.
$ErrorActionPreference = 'Stop'

function Test-Winget {
  if (Get-Command winget -ErrorAction SilentlyContinue) { & winget --version; return $true }
  return $false
}

if (Test-Winget) { exit 0 }

# The package is provisioned on every Windows client image. Registering it
# for this account needs no download.
Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe -ErrorAction SilentlyContinue
$env:Path = "$env:LOCALAPPDATA\Microsoft\WindowsApps;$env:Path"
if (Test-Winget) { exit 0 }

# Windows PowerShell has the NuGet provider bootstrap that PowerShell 7 lacks
# on a fresh account.
powershell.exe -NoProfile -Command {
  $ErrorActionPreference = 'Stop'
  Install-PackageProvider -Name NuGet -Force | Out-Null
  Install-Module -Name Microsoft.WinGet.Client -Force -Repository PSGallery -Scope CurrentUser
  Repair-WinGetPackageManager -Latest -Force
}
if ($LASTEXITCODE -ne 0) { throw "Repair-WinGetPackageManager exited with $LASTEXITCODE" }
$env:Path = "$env:LOCALAPPDATA\Microsoft\WindowsApps;$env:Path"
if (-not (Test-Winget)) { throw 'winget is still not on PATH after Repair-WinGetPackageManager' }
