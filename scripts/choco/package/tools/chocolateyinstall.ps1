$ErrorActionPreference = 'Stop'

if ((Get-OSArchitectureWidth) -ne 64) {
  throw 'pmg ships a 64-bit installer only'
}

$packageArgs = @{
  packageName    = $env:ChocolateyPackageName
  fileType       = 'msi'
  url64bit       = '{{MSI_URL}}'
  checksum64     = '{{MSI_SHA256}}'
  checksumType64 = 'sha256'
  silentArgs     = '/qn /norestart'
  # 3010: Windows Installer saw a running pmg.exe. The new file is in place
  # and no restart is needed.
  validExitCodes = @(0, 3010)
}
Install-ChocolateyPackage @packageArgs
