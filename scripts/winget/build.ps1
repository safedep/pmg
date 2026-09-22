# build.ps1 - write the winget manifests for one stable pmg release.
#
# Version is the release version without the v, for example 1.4.2. winget
# gets stable releases only, so a prerelease version is an error. MsiUrl is
# the installer URL the manifest points at. MsiPath is the local copy, for
# its SHA-256, its product code and its upgrade code.
param(
  [Parameter(Mandatory)][string]$Version,
  [Parameter(Mandatory)][string]$MsiPath,
  [Parameter(Mandatory)][string]$MsiUrl,
  [Parameter(Mandatory)][string]$OutDir
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\msi\wrap_lib.ps1"

if ((Split-ReleaseVersion $Version).Prerelease) {
  throw "winget gets stable releases only, got $Version"
}

if (Test-Path -LiteralPath $OutDir) { Remove-Item -LiteralPath $OutDir -Recurse -Force }
Expand-PackageTemplate -TemplateDir (Join-Path $PSScriptRoot 'manifests') -OutDir $OutDir -Values @{
  VERSION      = $Version
  MSI_URL      = $MsiUrl
  MSI_SHA256   = (Get-FileSha256 $MsiPath).ToUpperInvariant()
  PRODUCT_CODE = Get-MsiProperty -Path $MsiPath -Name ProductCode
  UPGRADE_CODE = (Get-MsiProperty -Path $MsiPath -Name UpgradeCode).ToUpperInvariant()
  RELEASE_DATE = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd')
}
Write-Host "wrote the winget manifests for SafeDep.pmg $Version to $OutDir"
