# build.ps1 - build the Chocolatey package that wraps the pmg MSI.
#
# Version is the release version without the v, for example 1.4.2 or
# 1.4.2-edge.3. An edge version becomes a Chocolatey prerelease, so
# `choco install pmg` never picks it and `choco install pmg --pre` does.
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

$chocoVersion = ConvertTo-ChocolateyVersion $Version
$stage = Join-Path $OutDir 'pmg'
if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
Expand-PackageTemplate -TemplateDir (Join-Path $PSScriptRoot 'package') -OutDir $stage -Values @{
  VERSION     = $chocoVersion
  RELEASE_TAG = "v$Version"
  MSI_URL     = $MsiUrl
  MSI_SHA256  = Get-FileSha256 $MsiPath
}

choco pack (Join-Path $stage 'pmg.nuspec') --outputdirectory $OutDir
if ($LASTEXITCODE -ne 0) { throw "choco pack exited with $LASTEXITCODE" }
Write-Host "built $OutDir\pmg.$chocoVersion.nupkg from $MsiUrl"
