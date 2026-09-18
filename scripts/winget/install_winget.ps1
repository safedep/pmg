# install_winget.ps1 - make sure winget runs for the current account. A CI
# runner image does not always register the App Installer package for the
# account that runs the job, and a new account on a client machine gets it
# at its first interactive logon only. The package is provisioned on every
# Windows image, so registering it needs no download.
$ErrorActionPreference = 'Stop'

function Test-Winget {
  if (Get-Command winget -ErrorAction SilentlyContinue) { & winget --version; return $true }
  return $false
}

if (Test-Winget) { exit 0 }

Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe -ErrorAction SilentlyContinue
$env:Path = "$env:LOCALAPPDATA\Microsoft\WindowsApps;$env:Path"
if (-not (Test-Winget)) { throw 'winget is not available on this machine and the App Installer package could not be registered' }
