# download_release.ps1 - download the pmg MSI of one GitHub release and check
# it against the release's checksums.txt.
param(
  [Parameter(Mandatory)][string]$Repository,
  [Parameter(Mandatory)][string]$Tag,
  [Parameter(Mandatory)][string]$OutDir
)
$ErrorActionPreference = 'Stop'

$name = 'pmg_Windows_x86_64.msi'
$base = "https://github.com/$Repository/releases/download/$Tag"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$msi = Join-Path $OutDir $name
Invoke-WebRequest -Uri "$base/$name" -OutFile $msi
Invoke-WebRequest -Uri "$base/checksums.txt" -OutFile (Join-Path $OutDir 'checksums.txt')

$entry = Get-Content (Join-Path $OutDir 'checksums.txt') | Where-Object { $_ -like "*  $name" }
if (-not $entry) { throw "no checksum entry for $name" }
$expected = ($entry -split ' ')[0]
$actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $msi).Hash
if ($actual -ine $expected) { throw "checksum mismatch for ${name}: expected $expected, got $actual" }
Write-Host "downloaded $msi from $base"
