# wrap_lib.ps1 - helpers for the packages that wrap the pmg MSI: the
# Chocolatey package and the winget manifests. Dot-source it.
$ErrorActionPreference = 'Stop'

# Split a release version such as 1.4.2-edge.3 into 1.4.2 and edge.3.
function Split-ReleaseVersion {
  param([string]$Version)
  if ($Version -notmatch '^(?<base>\d+\.\d+\.\d+)(-(?<prerelease>[0-9A-Za-z.-]+))?$') {
    throw "version $Version is not major.minor.patch with an optional prerelease part"
  }
  return [pscustomobject]@{ Base = $Matches.base; Prerelease = $Matches.prerelease }
}

# The Chocolatey community repository orders a prerelease label as a plain
# string, so edge.10 would sort before edge.9. The label becomes edge010.
function ConvertTo-ChocolateyVersion {
  param([string]$Version)
  $parts = Split-ReleaseVersion $Version
  if (-not $parts.Prerelease) { return $parts.Base }
  if ($parts.Prerelease -notmatch '^(?<label>[a-z]+)\.(?<number>\d+)$') {
    throw "prerelease part $($parts.Prerelease) is not <label>.<number>"
  }
  if ([int]$Matches.number -gt 999) {
    throw "prerelease number $($Matches.number) is above 999, the most the three-digit label can order"
  }
  return '{0}-{1}{2:d3}' -f $parts.Base, $Matches.label, [int]$Matches.number
}

function Get-FileSha256 {
  param([string]$Path)
  return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

# Read one row of the MSI Property table through the Windows Installer COM
# object. PowerShell has no typed binding for it, so every call goes through
# InvokeMember.
function Get-MsiProperty {
  param([string]$Path, [string]$Name)
  $installer = New-Object -ComObject WindowsInstaller.Installer
  $database = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @((Resolve-Path -LiteralPath $Path).Path, 0))
  $view = $database.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $database, @("SELECT Value FROM Property WHERE Property = '$Name'"))
  $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null) | Out-Null
  $record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
  if (-not $record) { throw "$Path has no $Name property" }
  return $record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, 1)
}

# Copy the files under $TemplateDir to $OutDir and replace every {{NAME}}
# with $Values[NAME]. A placeholder without a value is an error.
function Expand-PackageTemplate {
  param([string]$TemplateDir, [string]$OutDir, [hashtable]$Values)
  foreach ($file in Get-ChildItem -LiteralPath $TemplateDir -File -Recurse) {
    $content = Get-Content -LiteralPath $file.FullName -Raw
    foreach ($name in $Values.Keys) { $content = $content.Replace("{{$name}}", [string]$Values[$name]) }
    if ($content -match '\{\{[A-Z_]+\}\}') { throw "$($file.FullName) has a placeholder without a value: $($Matches[0])" }
    $target = Join-Path $OutDir $file.FullName.Substring($TemplateDir.Length).TrimStart('\', '/')
    New-Item -ItemType Directory -Path (Split-Path $target) -Force | Out-Null
    [IO.File]::WriteAllText($target, $content, [Text.UTF8Encoding]::new($false))
  }
}
