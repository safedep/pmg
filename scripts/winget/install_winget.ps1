# install_winget.ps1 - make sure winget runs on a Windows CI runner. The
# runner image does not always register the App Installer package for the
# service account that runs the job.
$ErrorActionPreference = 'Stop'

if (Get-Command winget -ErrorAction SilentlyContinue) {
  & winget --version
  exit 0
}

Install-PackageProvider -Name NuGet -Force | Out-Null
Install-Module -Name Microsoft.WinGet.Client -Force -Repository PSGallery -Scope CurrentUser
Repair-WinGetPackageManager -Latest -Force
if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
  throw 'winget is still not on PATH after Repair-WinGetPackageManager'
}
& winget --version
