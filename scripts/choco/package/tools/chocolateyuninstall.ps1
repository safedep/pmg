$ErrorActionPreference = 'Stop'

# Apps & Features lists the product as pmg or pmg (edge). The publisher check
# keeps another product with that prefix out of the match.
$entries = @(Get-UninstallRegistryKey -SoftwareName 'pmg*' | Where-Object { $_.Publisher -eq 'SafeDep' })
if (-not $entries) {
  Write-Warning "$env:ChocolateyPackageName is not in Apps & Features. Nothing to uninstall."
  return
}

foreach ($entry in $entries) {
  $packageArgs = @{
    packageName    = $env:ChocolateyPackageName
    fileType       = 'msi'
    file           = ''
    silentArgs     = "$($entry.PSChildName) /qn /norestart"
    # 1605: the product is already gone, for example after an upgrade
    # removed it between the lookup and this call.
    validExitCodes = @(0, 1605, 3010)
  }
  Uninstall-ChocolateyPackage @packageArgs
}
