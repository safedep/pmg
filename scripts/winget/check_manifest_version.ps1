# check_manifest_version.ps1 - fail when the pinned winget manifest version is deprecated.
#
# `winget validate` accepts a deprecated schema, because the schema itself is
# still well formed. The winget-pkgs repository rejects it later, through a
# moderator bot, after the pull request has waited in the review queue. This
# check moves that failure into our own CI.
#
# It reads the version the manifest templates pin and looks it up in the
# schema list that winget-pkgs publishes. A version the list marks
# "(deprecated)", or does not name at all, stops the build.
$ErrorActionPreference = 'Stop'

$SchemaList = 'https://raw.githubusercontent.com/microsoft/winget-pkgs/master/doc/manifest/README.md'
$ManifestDir = Join-Path $PSScriptRoot 'manifests'

$pinned = @{}
foreach ($file in Get-ChildItem -Path $ManifestDir -Filter '*.yaml') {
  $match = Select-String -LiteralPath $file.FullName -Pattern '^ManifestVersion:\s*(\S+)' | Select-Object -First 1
  if (-not $match) { throw "$($file.Name) names no ManifestVersion" }
  $pinned[$file.Name] = $match.Matches[0].Groups[1].Value
}
if ($pinned.Count -eq 0) { throw "no manifest templates under $ManifestDir" }

$versions = $pinned.Values | Sort-Object -Unique
if ($versions.Count -ne 1) {
  $detail = ($pinned.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', '
  throw "the manifest templates pin different versions: $detail"
}
$version = $versions[0]

$readme = (Invoke-WebRequest -Uri $SchemaList -UseBasicParsing).Content
$entry = $readme -split "`n" | Where-Object { $_ -match "^\*\s*\[$([regex]::Escape($version))(\s|\])" } | Select-Object -First 1

if (-not $entry) {
  throw "winget manifest version $version is not in the schema list at $SchemaList"
}
if ($entry -match 'deprecated') {
  throw "winget manifest version $version is deprecated. Pick a current version from $SchemaList"
}

Write-Host "winget manifest version $version is current"
