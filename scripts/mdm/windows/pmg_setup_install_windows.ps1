# pmg_setup_install_windows.ps1 - Install and configure PMG on a Windows machine.
#
# Deploy via Intune, JumpCloud or any MDM, alongside lib_windows.ps1 in the
# same directory. Run as SYSTEM or as an administrator, it installs pmg.exe
# under Program Files, runs the system install (shims first on the machine
# PATH, a managed config in ProgramData) and deploys a bundled config.yml.
# When cloud credentials are set, the script stores them and syncs for each
# logged-on user. Run as a standard user, it does the cloud steps for that
# user only. See lib_windows.ps1 for the model.
#
# A sibling pmg.exe is installed in place of a download. A sibling config.yml
# becomes the managed config.
#
# Environment variables:
#   SAFEDEP_API_KEY    - SafeDep Cloud API key (with tenant ID, enables cloud sync)
#   SAFEDEP_TENANT_ID  - SafeDep Cloud tenant ID
#   PMG_VERSION        - Release tag to install. Default: the latest release.
#
# Options:
#   --cloud-sync-only  - Skip installation and sync every logged-on user's cloud data

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$CloudApiKey = [string]$env:SAFEDEP_API_KEY
$CloudTenantId = [string]$env:SAFEDEP_TENANT_ID
Remove-Item -Path Env:SAFEDEP_API_KEY, Env:SAFEDEP_TENANT_ID -ErrorAction SilentlyContinue

$CloudSyncOnly = $args -contains '--cloud-sync-only'

. "$PSScriptRoot\lib_windows.ps1"

Assert-Windows

$Repo = 'safedep/pmg'
$PmgBin = $null

function Read-EmbeddedCloudCredential {
  $embeddedApiKey = [string](Get-Variable -Name EMBEDDED_SAFEDEP_API_KEY_B64 -ValueOnly -Scope Script -ErrorAction SilentlyContinue)
  $embeddedTenantId = [string](Get-Variable -Name EMBEDDED_SAFEDEP_TENANT_ID_B64 -ValueOnly -Scope Script -ErrorAction SilentlyContinue)
  Remove-Variable -Name EMBEDDED_SAFEDEP_API_KEY_B64, EMBEDDED_SAFEDEP_TENANT_ID_B64 -Scope Script -ErrorAction SilentlyContinue

  if ($script:CloudApiKey -and $script:CloudTenantId) { return }
  if (-not $embeddedApiKey -and -not $embeddedTenantId) { return }
  if ($script:CloudApiKey -or $script:CloudTenantId) {
    Fail 'SAFEDEP_API_KEY and SAFEDEP_TENANT_ID must be set together'
  }
  if (-not $embeddedApiKey -or -not $embeddedTenantId) {
    Fail 'embedded cloud credentials are incomplete'
  }
  try {
    $script:CloudApiKey = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($embeddedApiKey))
  } catch {
    Fail 'could not decode embedded cloud API key'
  }
  try {
    $script:CloudTenantId = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($embeddedTenantId))
  } catch {
    Fail 'could not decode embedded cloud tenant ID'
  }
}

function Get-CloudEnvironment {
  return @{ SAFEDEP_API_KEY = $script:CloudApiKey; SAFEDEP_TENANT_ID = $script:CloudTenantId }
}

function Invoke-CloudSync {
  param([Parameter(Mandatory)]$User)
  return Invoke-AsUser -User $User -PmgBin $script:PmgBin -ArgumentList @('cloud', 'sync', '--timeout', '1m') -Environment (Get-CloudEnvironment)
}

function Invoke-CloudLogin {
  param([Parameter(Mandatory)]$User)
  return Invoke-AsUser -User $User -PmgBin $script:PmgBin -ArgumentList @('cloud', 'login', '--from-env') -Environment (Get-CloudEnvironment)
}

# Sync every logged-on user. A logged-off user has no logon to run pmg in.
# Returns $false when any sync failed.
function Sync-EveryUser {
  $synced = 0
  $failed = 0
  $skipped = 0
  foreach ($user in @(Get-TargetUser)) {
    if (-not (Test-UserSession -User $user)) {
      Write-Info "  $($user.Name) has no active session; cloud sync skipped"
      $skipped++
      continue
    }
    Write-Info "Syncing pmg cloud data for $($user.Name)"
    if (Invoke-CloudSync -User $user) {
      $synced++
    } else {
      Write-Warn "cloud sync failed for $($user.Name)"
      $failed++
    }
  }
  if ($synced -eq 0 -and $failed -eq 0) {
    if ($skipped -eq 0) {
      Write-Info 'No users found for cloud sync'
    } else {
      Write-Info "No logged-on users to sync; $skipped skipped"
    }
    return $true
  }
  if ($failed -ne 0) {
    Write-Warn "cloud sync failed for $failed of $($synced + $failed) users"
    return $false
  }
  Write-Info "pmg cloud sync complete for $synced users"
  return $true
}

function Get-LatestReleaseTag {
  $request = [Net.HttpWebRequest]::Create("https://github.com/$Repo/releases/latest")
  $request.Method = 'HEAD'
  $request.AllowAutoRedirect = $false
  $response = $request.GetResponse()
  try {
    $location = [string]$response.Headers['Location']
  } finally {
    $response.Close()
  }
  $tag = $location.Split('/')[-1]
  if (-not $tag) { Fail 'could not determine latest release' }
  return $tag
}

# Copy the binary into place. Windows locks a running image against
# overwrite but not against rename, so an upgrade under a running pmg.exe
# moves the old file aside first. The stale copy goes on the next run.
function Copy-Binary {
  param([Parameter(Mandatory)][string]$Source)
  $stale = "$PmgBinary.old"
  Remove-Item -LiteralPath $stale -Force -ErrorAction SilentlyContinue
  try {
    Copy-Item -LiteralPath $Source -Destination $PmgBinary -Force
  } catch {
    # A running image, a read-only attribute or a scanner's handle each
    # raise a different exception. The rename works for all of them. When
    # the second copy fails too, the old file goes back, so the shims that
    # call this path keep a binary.
    Move-Item -LiteralPath $PmgBinary -Destination $stale -Force
    try {
      Copy-Item -LiteralPath $Source -Destination $PmgBinary -Force
    } catch {
      Move-Item -LiteralPath $stale -Destination $PmgBinary -Force
      throw
    }
  }
}

function Install-ViaRelease {
  Write-Info 'Installing pmg from GitHub releases'
  if (-not [Environment]::Is64BitOperatingSystem) { Fail 'unsupported architecture: 32-bit Windows' }
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

  $tag = [string]$env:PMG_VERSION
  if (-not $tag) { $tag = Get-LatestReleaseTag }
  Write-Info "Release: $tag"

  $asset = 'pmg_Windows_x86_64.zip'
  $base = "https://github.com/$Repo/releases/download/$tag"
  $tempDir = Join-Path $env:TEMP ('pmg-install-' + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $tempDir | Out-Null
  try {
    Write-Info "Downloading $asset"
    Invoke-WebRequest -Uri "$base/$asset" -OutFile (Join-Path $tempDir $asset) -UseBasicParsing
    Invoke-WebRequest -Uri "$base/checksums.txt" -OutFile (Join-Path $tempDir 'checksums.txt') -UseBasicParsing

    $entry = Get-Content -LiteralPath (Join-Path $tempDir 'checksums.txt') | Where-Object { $_ -like "*  $asset" } | Select-Object -First 1
    if (-not $entry) { Fail "no checksum entry found for $asset" }
    $expected = ($entry -split ' ')[0].ToLowerInvariant()
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $tempDir $asset)).Hash.ToLowerInvariant()
    if ($actual -ne $expected) { Fail "checksum mismatch for $asset (expected $expected, got $actual)" }
    Write-Info 'Checksum verified'

    Expand-Archive -LiteralPath (Join-Path $tempDir $asset) -DestinationPath (Join-Path $tempDir 'unpacked') -Force
    Copy-Binary -Source (Join-Path $tempDir 'unpacked\pmg.exe')
    Write-Info "Installed pmg $tag to $PmgBinary"
  } finally {
    Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
  }
}

function Install-Binary {
  New-Item -ItemType Directory -Path $ProductDir -Force | Out-Null
  $sibling = Join-Path $PSScriptRoot 'pmg.exe'
  if (Test-Path -LiteralPath $sibling -PathType Leaf) {
    if (-not (Test-AdministrativeOwner -Acl (Get-Acl -LiteralPath $sibling))) {
      Fail "$sibling is not owned by Administrators or SYSTEM"
    }
    Write-Info "Installing pmg from $sibling"
    Copy-Binary -Source $sibling
    return
  }
  Install-ViaRelease
}

function Install-RequestedGlobalConfig {
  $embeddedConfig = [string](Get-Variable -Name EMBEDDED_GLOBAL_CONFIG_B64 -ValueOnly -Scope Script -ErrorAction SilentlyContinue)
  Remove-Variable -Name EMBEDDED_GLOBAL_CONFIG_B64 -Scope Script -ErrorAction SilentlyContinue

  if (-not $embeddedConfig) {
    $sibling = Join-Path $PSScriptRoot 'config.yml'
    if (Test-Path -LiteralPath $sibling -PathType Leaf) {
      Install-GlobalConfig -Source $sibling
      Assert-ManagedConfigReadable
    }
    return
  }

  $decoded = [IO.Path]::GetTempFileName()
  try {
    try {
      [IO.File]::WriteAllBytes($decoded, [Convert]::FromBase64String($embeddedConfig))
    } catch {
      Fail 'could not decode embedded global config'
    }
    Install-GlobalConfig -Source $decoded
  } finally {
    Remove-Item -LiteralPath $decoded -Force -ErrorAction SilentlyContinue
  }
  Assert-ManagedConfigReadable
}

# The managed config governs every account, so a bundled file pmg cannot
# parse breaks pmg for the whole machine. One read catches that while the
# MDM run can still report a failure.
function Assert-ManagedConfigReadable {
  if ((Invoke-Native -FilePath $PmgBinary -ArgumentList @('config', 'get', 'paranoid') -Capture).ExitCode -ne 0) {
    Fail 'pmg cannot read the managed config; check the bundled config.yml'
  }
}

function Test-CloudEnabled {
  $result = Invoke-Native -FilePath $script:PmgBin -ArgumentList @('config', 'get', 'cloud.enabled') -Capture
  return $result.ExitCode -eq 0 -and $result.Output -contains 'true'
}

# Store credentials and sync for one user. The managed config decides
# whether cloud is enabled, so there is no per-user `config set` here.
function Set-UserCloud {
  param([Parameter(Mandatory)]$User)
  if (-not (Test-UserSession -User $User)) {
    Write-Info "  $($User.Name) has no active session; cloud credentials were not stored in their Credential Manager"
    return
  }
  Write-Info "Configuring pmg cloud for $($User.Name)"
  if (-not (Invoke-CloudLogin -User $User)) { Write-Warn "cloud login failed for $($User.Name)" }
  if (-not (Invoke-CloudSync -User $User)) { Write-Warn "cloud sync failed for $($User.Name)" }
}

function Write-InstalledVersion {
  $result = Invoke-Native -FilePath $script:PmgBin -ArgumentList @('version') -Capture
  $line = $result.Output | Where-Object { $_ -like 'Version:*' } | Select-Object -First 1
  $version = if ($line) { ($line -replace '^Version:\s*', '') } else { 'unknown' }
  Write-Info "pmg installed: $version"
}

# The unit test dot-sources this file for its functions and stops here.
if ($env:PMG_MDM_TEST_LOAD_ONLY) { return }

Read-EmbeddedCloudCredential

if ($CloudSyncOnly) {
  if (-not $CloudApiKey -or -not $CloudTenantId) {
    Write-Info 'Cloud credentials are not configured; skipping cloud sync'
    exit 0
  }
  $PmgBin = Resolve-Pmg
  if (-not $PmgBin) {
    Write-Info 'pmg is not installed; skipping cloud sync'
    exit 0
  }
  $synced = Sync-EveryUser
  $CloudApiKey = ''
  $CloudTenantId = ''
  if ($synced) { exit 0 } else { exit 1 }
}

if (Test-Elevated) {
  Install-Binary
  if ((Invoke-Native -FilePath $PmgBinary -ArgumentList @('setup', 'install', '--system')) -ne 0) {
    Fail 'pmg setup install --system failed'
  }
  $PmgBin = Resolve-Pmg
  Write-InstalledVersion
  Install-RequestedGlobalConfig
} else {
  Write-Warn 'not elevated; machine-scope steps skipped'
  $PmgBin = Resolve-Pmg
  if (-not $PmgBin) { Fail 'pmg is not installed' }
}

if ($CloudApiKey -and $CloudTenantId) {
  if (-not (Test-CloudEnabled)) {
    Write-Info "Config is globally managed; set 'cloud.enabled: true' in the bundled config.yml to enable sync"
  }
  foreach ($user in @(Get-TargetUser)) {
    Set-UserCloud -User $user
  }
}

$CloudApiKey = ''
$CloudTenantId = ''

Write-Info 'pmg setup complete'
