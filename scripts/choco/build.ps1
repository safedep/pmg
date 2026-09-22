# build.ps1 - build the Chocolatey package that wraps the pmg MSI.
#
# Version is the release version without the v, for example 1.4.2. The
# package ships stable releases only, so a prerelease version is an error.
# MsiUrl is where the package downloads the installer from. A local path
# works too, for a test.
param(
  [Parameter(Mandatory)][string]$Version,
  [Parameter(Mandatory)][string]$MsiPath,
  [Parameter(Mandatory)][string]$MsiUrl,
  [Parameter(Mandatory)][string]$OutDir
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\msi\wrap_lib.ps1"

if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
  throw 'choco is not installed. It packs the Chocolatey package'
}
if ((Split-ReleaseVersion $Version).Prerelease) {
  throw "Chocolatey gets stable releases only, got $Version"
}

$stage = Join-Path $OutDir 'pmg'
if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
Expand-PackageTemplate -TemplateDir (Join-Path $PSScriptRoot 'package') -OutDir $stage -Values @{
  VERSION     = $Version
  RELEASE_TAG = "v$Version"
  MSI_URL     = $MsiUrl
  MSI_SHA256  = Get-FileSha256 $MsiPath
}

choco pack (Join-Path $stage 'pmg.nuspec') --outputdirectory $OutDir
if ($LASTEXITCODE -ne 0) { throw "choco pack exited with $LASTEXITCODE" }
Write-Host "built $OutDir\pmg.$Version.nupkg from $MsiUrl"
