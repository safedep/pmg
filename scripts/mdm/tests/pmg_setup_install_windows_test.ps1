# pmg_setup_install_windows_test.ps1 - test the Windows installer's functions
# with mocked helpers. The installer is copied next to a stub lib_windows.ps1
# and driven with a fake pmg that records argv and environment. Runs on
# Windows PowerShell 5.1 and on PowerShell 7 on any OS.
$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$TestRoot = Join-Path ([IO.Path]::GetTempPath()) ('pmg-install-test-' + [guid]::NewGuid().ToString('N'))
$HostExe = (Get-Process -Id $PID).Path
New-Item -ItemType Directory -Path $TestRoot | Out-Null

function Stop-OnFailure {
  param([string]$Message)
  [Console]::Error.WriteLine("FAIL: $Message")
  exit 1
}

function Assert-Equal {
  param($Expected, $Actual, [string]$Message)
  if ("$Actual" -ne "$Expected") { Stop-OnFailure "${Message}: expected '$Expected', got '$Actual'" }
}

function Assert-LineMatch {
  param([string[]]$Lines, [string]$Expected, [string]$Message)
  if (-not ($Lines | Where-Object { $_ -like "*$Expected*" })) { Stop-OnFailure "${Message}: no line contains '$Expected' in: $($Lines -join ' | ')" }
}

function Assert-NoLineMatch {
  param([string[]]$Lines, [string]$Unexpected, [string]$Message)
  if ($Lines | Where-Object { $_ -like "*$Unexpected*" }) { Stop-OnFailure "${Message}: a line contains '$Unexpected' in: $($Lines -join ' | ')" }
}

function Get-CaptureLine {
  param([string]$Path)
  if (Test-Path -LiteralPath $Path) { return @(Get-Content -LiteralPath $Path) }
  return @()
}

# The fake pmg appends "<args>;<api key>;<tenant>" to PMG_TEST_TRACE and fails
# when its argument line equals PMG_TEST_FAIL_ARGS.
$FakePmg = if ($env:OS -eq 'Windows_NT') {
  $path = Join-Path $TestRoot 'pmg.cmd'
  Set-Content -LiteralPath $path -Value @'
@echo off
echo %*;%SAFEDEP_API_KEY%;%SAFEDEP_TENANT_ID%>>"%PMG_TEST_TRACE%"
if "%*"=="%PMG_TEST_FAIL_ARGS%" exit /b 1
exit /b 0
'@
  $path
} else {
  $path = Join-Path $TestRoot 'pmg'
  Set-Content -LiteralPath $path -Value @'
#!/bin/sh
printf '%s;%s;%s\n' "$*" "${SAFEDEP_API_KEY:-}" "${SAFEDEP_TENANT_ID:-}" >> "$PMG_TEST_TRACE"
[ "$*" != "${PMG_TEST_FAIL_ARGS:-}" ]
'@
  chmod 0755 $path
  $path
}

# The stub lib replaces every helper with one driven by PMG_TEST_* variables
# and logs to PMG_TEST_LOG, so the same stub serves in-process calls and
# child-process runs of the whole installer.
$StageDir = Join-Path $TestRoot 'staged'
New-Item -ItemType Directory -Path $StageDir | Out-Null
Copy-Item -LiteralPath (Join-Path $ScriptDir 'windows\pmg_setup_install_windows.ps1') -Destination $StageDir
Set-Content -LiteralPath (Join-Path $StageDir 'lib_windows.ps1') -Value @'
function Assert-Windows {}
function Write-Info { param([string]$Message) Add-Content -LiteralPath $env:PMG_TEST_LOG -Value "log:$Message" }
function Write-Warn { param([string]$Message) Add-Content -LiteralPath $env:PMG_TEST_LOG -Value "warning:$Message" }
function Fail { param([string]$Message) Add-Content -LiteralPath $env:PMG_TEST_LOG -Value "error:$Message"; throw "Error: $Message" }
function Test-Elevated { return $env:PMG_TEST_ELEVATED -eq '1' }
function Resolve-Pmg { if ($env:PMG_TEST_INSTALLED -eq '1') { return $env:PMG_TEST_PMG } }
function Get-TargetUser {
  Add-Content -LiteralPath $env:PMG_TEST_LOG -Value "credentials-in-env:$($null -ne $env:SAFEDEP_API_KEY -or $null -ne $env:SAFEDEP_TENANT_ID)"
  foreach ($name in @($env:PMG_TEST_USERS -split ',' | Where-Object { $_ })) {
    [pscustomobject]@{ Name = $name; Sid = "S-1-5-21-$name"; Home = "C:\Users\$name" }
  }
}
function Test-UserSession { param($User) return @($env:PMG_TEST_SESSIONS -split ',') -contains $User.Name }
function Invoke-AsUser {
  param($User, [string]$PmgBin, [string[]]$ArgumentList, [hashtable]$Environment = @{})
  Add-Content -LiteralPath $env:PMG_TEST_LOG -Value "as-user:$($User.Name):$($ArgumentList -join ' ')"
  foreach ($name in $Environment.Keys) { Set-Item -Path "Env:$name" -Value $Environment[$name] }
  try {
    $process = Start-Process -FilePath $PmgBin -ArgumentList $ArgumentList -NoNewWindow -Wait -PassThru
    return $process.ExitCode -eq 0
  } finally {
    foreach ($name in $Environment.Keys) { Remove-Item -Path "Env:$name" -ErrorAction SilentlyContinue }
  }
}
function Invoke-Native {
  param([string]$FilePath, [string[]]$ArgumentList, [switch]$Capture)
  Add-Content -LiteralPath $env:PMG_TEST_LOG -Value "native:$($ArgumentList -join ' ')"
  $exit = if ($env:PMG_TEST_NATIVE_EXIT) { [int]$env:PMG_TEST_NATIVE_EXIT } else { 0 }
  if ($Capture) { return [pscustomobject]@{ ExitCode = $exit; Output = @($env:PMG_TEST_NATIVE_OUTPUT -split ',') } }
  return $exit
}
function Install-GlobalConfig { param([string]$Source) Copy-Item -LiteralPath $Source -Destination $env:PMG_TEST_CAPTURED_CONFIG }
$ProductDir = 'C:\Program Files\safedep\pmg'
$PmgBinary = 'C:\Program Files\safedep\pmg\pmg.exe'
$GlobalConfigFile = 'C:\ProgramData\safedep\pmg\config.yml'
'@

$TestLog = Join-Path $TestRoot 'test.log'
$Trace = Join-Path $TestRoot 'trace.txt'
$CapturedConfig = Join-Path $TestRoot 'captured.yml'
$env:PMG_TEST_LOG = $TestLog
$env:PMG_TEST_TRACE = $Trace
$env:PMG_TEST_PMG = $FakePmg
$env:PMG_TEST_CAPTURED_CONFIG = $CapturedConfig

function Reset-Capture {
  Remove-Item -LiteralPath $TestLog, $Trace, $CapturedConfig -Force -ErrorAction SilentlyContinue
  Remove-Item -Path Env:PMG_TEST_FAIL_ARGS, Env:PMG_TEST_USERS, Env:PMG_TEST_SESSIONS, Env:PMG_TEST_ELEVATED, Env:PMG_TEST_INSTALLED, Env:PMG_TEST_NATIVE_OUTPUT, Env:PMG_TEST_NATIVE_EXIT -ErrorAction SilentlyContinue
}

# Run the staged installer in a child host with the given environment.
# Returns the exit code. Logs and traces land in the capture files.
function Invoke-Installer {
  param([hashtable]$Environment = @{}, [string[]]$ArgumentList = @())
  foreach ($name in $Environment.Keys) { Set-Item -Path "Env:$name" -Value $Environment[$name] }
  try {
    $arguments = @('-NoProfile', '-NonInteractive', '-File', (Join-Path $StageDir 'pmg_setup_install_windows.ps1')) + $ArgumentList
    $process = Start-Process -FilePath $HostExe -ArgumentList $arguments -NoNewWindow -Wait -PassThru `
      -RedirectStandardOutput (Join-Path $TestRoot 'child.out') -RedirectStandardError (Join-Path $TestRoot 'child.err')
    return $process.ExitCode
  } finally {
    foreach ($name in $Environment.Keys) { Remove-Item -Path "Env:$name" -ErrorAction SilentlyContinue }
  }
}

function ConvertTo-Base64 {
  param([string]$Value)
  return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Value))
}

Write-Host '==> Testing pmg_setup_install_windows.ps1'

# Variables the installer reads are set with Set-Variable, because they are
# the installer's, not this file's.
# Load the installer's functions in this scope. The stub lib makes every
# helper a recorder, and PMG_MDM_TEST_LOAD_ONLY stops the flow.
$env:PMG_MDM_TEST_LOAD_ONLY = '1'
. (Join-Path $StageDir 'pmg_setup_install_windows.ps1')
Remove-Item -Path Env:PMG_MDM_TEST_LOAD_ONLY

# Credential precedence: runtime values win, embedded values fill in, a
# half-set pair is an error, and the embedded variables are removed.
Reset-Capture
$CloudApiKey = 'runtime-api-key'
$CloudTenantId = 'runtime-tenant'
Set-Variable -Name EMBEDDED_SAFEDEP_API_KEY_B64 -Value (ConvertTo-Base64 'embedded-api-key')
Set-Variable -Name EMBEDDED_SAFEDEP_TENANT_ID_B64 -Value (ConvertTo-Base64 'embedded-tenant')
Read-EmbeddedCloudCredential
Assert-Equal 'runtime-api-key' $CloudApiKey 'runtime API key wins'
Assert-Equal 'runtime-tenant' $CloudTenantId 'runtime tenant wins'
if (Get-Variable -Name EMBEDDED_SAFEDEP_API_KEY_B64 -ErrorAction SilentlyContinue) { Stop-OnFailure 'embedded API key must be removed after loading' }

$CloudApiKey = ''
$CloudTenantId = ''
Set-Variable -Name EMBEDDED_SAFEDEP_API_KEY_B64 -Value (ConvertTo-Base64 'embedded-api-key')
Set-Variable -Name EMBEDDED_SAFEDEP_TENANT_ID_B64 -Value (ConvertTo-Base64 'embedded-tenant')
Read-EmbeddedCloudCredential
Assert-Equal 'embedded-api-key' $CloudApiKey 'embedded API key decoded'
Assert-Equal 'embedded-tenant' $CloudTenantId 'embedded tenant decoded'

$CloudApiKey = 'runtime-api-key'
$CloudTenantId = ''
Set-Variable -Name EMBEDDED_SAFEDEP_API_KEY_B64 -Value (ConvertTo-Base64 'embedded-api-key')
Set-Variable -Name EMBEDDED_SAFEDEP_TENANT_ID_B64 -Value (ConvertTo-Base64 'embedded-tenant')
try { Read-EmbeddedCloudCredential; Stop-OnFailure 'a half-set runtime pair must fail' } catch { Assert-Equal 'Error: SAFEDEP_API_KEY and SAFEDEP_TENANT_ID must be set together' $_.Exception.Message 'half-set runtime pair' }

$CloudApiKey = ''
$CloudTenantId = ''
Set-Variable -Name EMBEDDED_SAFEDEP_API_KEY_B64 -Value (ConvertTo-Base64 'embedded-api-key')
Set-Variable -Name EMBEDDED_SAFEDEP_TENANT_ID_B64 -Value ('')
try { Read-EmbeddedCloudCredential; Stop-OnFailure 'a half-set embedded pair must fail' } catch { Assert-Equal 'Error: embedded cloud credentials are incomplete' $_.Exception.Message 'half-set embedded pair' }

# Managed config: the embedded config wins over a sibling config.yml, the
# sibling is the fallback, and nothing is installed without either.
Reset-Capture
Set-Content -LiteralPath (Join-Path $StageDir 'config.yml') -Value 'source: adjacent'
Set-Variable -Name EMBEDDED_GLOBAL_CONFIG_B64 -Value (ConvertTo-Base64 "source: embedded`n")
Install-RequestedGlobalConfig
Assert-Equal 'source: embedded' (Get-Content -LiteralPath $CapturedConfig -Raw).Trim() 'embedded config wins'
if (Get-Variable -Name EMBEDDED_GLOBAL_CONFIG_B64 -ErrorAction SilentlyContinue) { Stop-OnFailure 'embedded config must be removed after loading' }

Reset-Capture
Install-RequestedGlobalConfig
Assert-Equal 'source: adjacent' (Get-Content -LiteralPath $CapturedConfig -Raw).Trim() 'sibling config is the fallback'
Assert-LineMatch (Get-CaptureLine $TestLog) 'native:config get paranoid' 'the managed config is read back after the write'

# A bundled config pmg cannot parse fails the install.
Reset-Capture
$env:PMG_TEST_NATIVE_EXIT = '1'
try { Install-RequestedGlobalConfig; Stop-OnFailure 'an unreadable managed config must fail' } catch { Assert-Equal 'Error: pmg cannot read the managed config; check the bundled config.yml' $_.Exception.Message 'unreadable managed config' }
Remove-Item -Path Env:PMG_TEST_NATIVE_EXIT

Reset-Capture
Remove-Item -LiteralPath (Join-Path $StageDir 'config.yml')
Install-RequestedGlobalConfig
if (Test-Path -LiteralPath $CapturedConfig) { Stop-OnFailure 'no config must be installed without a source' }

# Per-user cloud steps run inside the user's logon, and only with a session.
Set-Variable -Name PmgBin -Value $FakePmg
$CloudApiKey = 'test-api-key'
$CloudTenantId = 'test-tenant'
$user = [pscustomobject]@{ Name = 'test-user'; Sid = 'S-1-5-21-test-user'; Home = 'C:\Users\test-user' }

Reset-Capture
$env:PMG_TEST_SESSIONS = 'test-user'
Set-UserCloud -User $user
Assert-Equal "cloud login --from-env;test-api-key;test-tenant`ncloud sync --timeout 1m;test-api-key;test-tenant" ((Get-CaptureLine $Trace) -join "`n") 'login then sync with credentials'
Assert-LineMatch (Get-CaptureLine $TestLog) 'as-user:test-user:cloud login --from-env' 'login runs as the user'
Assert-NoLineMatch (Get-CaptureLine $TestLog) 'warning:' 'no warning on success'

Reset-Capture
$env:PMG_TEST_SESSIONS = ''
Set-UserCloud -User $user
Assert-Equal 0 (Get-CaptureLine $Trace).Count 'no pmg call without a session'
Assert-LineMatch (Get-CaptureLine $TestLog) 'test-user has no active session; cloud credentials were not stored' 'session skip is reported'

Reset-Capture
$env:PMG_TEST_SESSIONS = 'test-user'
$env:PMG_TEST_FAIL_ARGS = 'cloud login --from-env'
Set-UserCloud -User $user
Assert-LineMatch (Get-CaptureLine $TestLog) 'warning:cloud login failed for test-user' 'failed login is a warning'
Assert-LineMatch (Get-CaptureLine $Trace) 'cloud sync --timeout 1m' 'sync still runs after a failed login'

Reset-Capture
$env:PMG_TEST_SESSIONS = 'test-user'
$env:PMG_TEST_FAIL_ARGS = 'cloud sync --timeout 1m'
Set-UserCloud -User $user
Assert-LineMatch (Get-CaptureLine $TestLog) 'warning:cloud sync failed for test-user' 'failed sync is a warning'

# Sync-EveryUser skips users without a session and fails when any sync fails.
Reset-Capture
$env:PMG_TEST_USERS = 'test-user,second-user'
$env:PMG_TEST_SESSIONS = 'test-user'
Assert-Equal $true (Sync-EveryUser) 'one synced user is a success'
Assert-Equal 1 (Get-CaptureLine $Trace).Count 'only the user with a session syncs'
Assert-LineMatch (Get-CaptureLine $TestLog) 'second-user has no active session; cloud sync skipped' 'skipped user is reported'
Assert-LineMatch (Get-CaptureLine $TestLog) 'pmg cloud sync complete for 1 users' 'synced count is reported'

Reset-Capture
$env:PMG_TEST_USERS = 'test-user,second-user'
$env:PMG_TEST_SESSIONS = 'test-user,second-user'
$env:PMG_TEST_FAIL_ARGS = 'cloud sync --timeout 1m'
Assert-Equal $false (Sync-EveryUser) 'a failed sync fails the run'
Assert-Equal 2 (Get-CaptureLine $Trace).Count 'every user is attempted'
Assert-LineMatch (Get-CaptureLine $TestLog) 'warning:cloud sync failed for 2 of 2 users' 'failure count is reported'

Reset-Capture
$env:PMG_TEST_USERS = ''
Assert-Equal $true (Sync-EveryUser) 'no users is a success'
Assert-LineMatch (Get-CaptureLine $TestLog) 'No users found for cloud sync' 'empty user list is reported'

Reset-Capture
$env:PMG_TEST_USERS = 'test-user,second-user'
$env:PMG_TEST_SESSIONS = ''
Assert-Equal $true (Sync-EveryUser) 'every user logged off is a success'
Assert-Equal 0 (Get-CaptureLine $Trace).Count 'no sync runs when every user is logged off'
Assert-LineMatch (Get-CaptureLine $TestLog) 'No logged-on users to sync; 2 skipped' 'logged-off users are counted'
Assert-NoLineMatch (Get-CaptureLine $TestLog) 'No users found for cloud sync' 'existing users are not reported as missing'

# Whole-installer runs in a child host: --cloud-sync-only in any argument
# position, the credential environment is cleared before helpers run, and
# an unelevated run does the cloud steps for the current user only.
Reset-Capture
$exit = Invoke-Installer -Environment @{ PMG_TEST_INSTALLED = '1'; PMG_TEST_USERS = 'test-user' } -ArgumentList '--cloud-sync-only'
Assert-Equal 0 $exit 'sync-only without credentials exits zero'
Assert-LineMatch (Get-CaptureLine $TestLog) 'Cloud credentials are not configured; skipping cloud sync' 'missing credentials are reported'
if (Test-Path -LiteralPath $Trace) { Stop-OnFailure 'sync-only must not run pmg without credentials' }

Reset-Capture
$exit = Invoke-Installer -Environment @{ SAFEDEP_API_KEY = 'test-api-key'; SAFEDEP_TENANT_ID = 'test-tenant'; PMG_TEST_INSTALLED = '0'; PMG_TEST_USERS = 'test-user' } -ArgumentList '--cloud-sync-only'
Assert-Equal 0 $exit 'sync-only without pmg exits zero'
Assert-LineMatch (Get-CaptureLine $TestLog) 'pmg is not installed; skipping cloud sync' 'missing pmg is reported'
if (Test-Path -LiteralPath $Trace) { Stop-OnFailure 'sync-only must not run pmg when it is missing' }

Reset-Capture
$exit = Invoke-Installer -Environment @{ SAFEDEP_API_KEY = 'test-api-key'; SAFEDEP_TENANT_ID = 'test-tenant'; PMG_TEST_INSTALLED = '1'; PMG_TEST_USERS = 'test-user,second-user'; PMG_TEST_SESSIONS = 'test-user,second-user' } -ArgumentList '/', 'computer', 'user', '--cloud-sync-only', 'custom'
Assert-Equal 0 $exit 'sync-only with two users exits zero'
Assert-Equal "cloud sync --timeout 1m;test-api-key;test-tenant`ncloud sync --timeout 1m;test-api-key;test-tenant" ((Get-CaptureLine $Trace) -join "`n") 'sync-only calls'
Assert-LineMatch (Get-CaptureLine $TestLog) 'credentials-in-env:False' 'credentials leave the environment before helpers run'

Reset-Capture
$exit = Invoke-Installer -Environment @{ SAFEDEP_API_KEY = 'test-api-key'; SAFEDEP_TENANT_ID = 'test-tenant'; PMG_TEST_INSTALLED = '1'; PMG_TEST_USERS = 'test-user,second-user'; PMG_TEST_SESSIONS = 'test-user,second-user'; PMG_TEST_FAIL_ARGS = 'cloud sync --timeout 1m' } -ArgumentList '--cloud-sync-only'
Assert-Equal 1 $exit 'a failed user sync fails sync-only'
Assert-Equal 2 (Get-CaptureLine $Trace).Count 'sync-only attempts every user after a failure'

Reset-Capture
$exit = Invoke-Installer -Environment @{ SAFEDEP_API_KEY = 'test-api-key'; SAFEDEP_TENANT_ID = 'test-tenant'; PMG_TEST_ELEVATED = '0'; PMG_TEST_INSTALLED = '1'; PMG_TEST_USERS = 'test-user'; PMG_TEST_SESSIONS = 'test-user'; PMG_TEST_NATIVE_OUTPUT = 'false' }
Assert-Equal 0 $exit 'an unelevated install run exits zero'
Assert-LineMatch (Get-CaptureLine $TestLog) 'warning:not elevated; machine-scope steps skipped' 'unelevated run skips machine steps'
Assert-LineMatch (Get-CaptureLine $TestLog) 'native:config get cloud.enabled' 'the managed config is checked for cloud.enabled'
Assert-LineMatch (Get-CaptureLine $TestLog) "set 'cloud.enabled: true' in the bundled config.yml" 'a disabled cloud is reported'
Assert-Equal "cloud login --from-env;test-api-key;test-tenant`ncloud sync --timeout 1m;test-api-key;test-tenant" ((Get-CaptureLine $Trace) -join "`n") 'unelevated run stores credentials and syncs'
Assert-LineMatch (Get-CaptureLine $TestLog) 'log:pmg setup complete' 'the run completes'

Reset-Capture
$exit = Invoke-Installer -Environment @{ PMG_TEST_ELEVATED = '0'; PMG_TEST_INSTALLED = '0' }
Assert-Equal 1 $exit 'an unelevated run without pmg fails'
Assert-LineMatch (Get-CaptureLine $TestLog) 'error:pmg is not installed' 'missing pmg is an error'

# The real lib: the unelevated Invoke-AsUser passes the environment to pmg
# and clears it afterwards, and the state directories honour the overrides.
& {
  if ($env:OS -ne 'Windows_NT') {
    $env:ProgramFiles = 'C:\Program Files'
    $env:ProgramData = 'C:\ProgramData'
  }
  . (Join-Path $ScriptDir 'windows\lib_windows.ps1')
  function Test-Elevated { return $false }
  Reset-Capture
  $user = [pscustomobject]@{ Name = 'test-user'; Sid = 'S-1-5-21-test-user'; Home = 'C:\Users\test-user' }
  $ok = Invoke-AsUser -User $user -PmgBin $FakePmg -ArgumentList @('cloud', 'sync', '--timeout', '1m') -Environment @{ SAFEDEP_API_KEY = 'test-api-key'; SAFEDEP_TENANT_ID = 'test-tenant' }
  Assert-Equal $true $ok 'unelevated Invoke-AsUser reports success'
  Assert-Equal 'cloud sync --timeout 1m;test-api-key;test-tenant' ((Get-CaptureLine $Trace) -join "`n") 'unelevated Invoke-AsUser passes the environment'
  if ($null -ne $env:SAFEDEP_API_KEY) { Stop-OnFailure 'Invoke-AsUser must clear the environment' }
  $env:PMG_TEST_FAIL_ARGS = 'cloud sync --timeout 1m'
  Assert-Equal $false (Invoke-AsUser -User $user -PmgBin $FakePmg -ArgumentList @('cloud', 'sync', '--timeout', '1m')) 'unelevated Invoke-AsUser reports failure'

  # Local and Entra ID accounts with a home under \Users are targets. A
  # service profile and a profile with no home directory are not.
  Reset-Capture
  function Test-Elevated { return $true }
  $root = Join-Path $TestRoot 'drive'
  New-Item -ItemType Directory -Path "$root\Users\local", "$root\Users\entra", "$root\Windows\ServiceProfiles\LocalService" | Out-Null
  $env:SystemDrive = $root
  function Get-ProfileEntry {
    [pscustomobject]@{ Sid = 'S-1-5-21-1111-2222-3333-1001'; Home = "$root\Users\local" }
    [pscustomobject]@{ Sid = 'S-1-12-1-4444-5555-6666-7777'; Home = "$root\Users\entra" }
    [pscustomobject]@{ Sid = 'S-1-5-19'; Home = "$root\Windows\ServiceProfiles\LocalService" }
    [pscustomobject]@{ Sid = 'S-1-5-21-1111-2222-3333-1002'; Home = "$root\Users\gone" }
  }
  $targets = @(Get-TargetUser)
  Assert-Equal 2 $targets.Count 'target user count'
  Assert-Equal 'S-1-5-21-1111-2222-3333-1001' $targets[0].Sid 'local account SID'
  Assert-Equal 'S-1-12-1-4444-5555-6666-7777' $targets[1].Sid 'Entra ID account SID'
  Assert-Equal 'entra' $targets[1].Name 'a SID that does not translate falls back to the folder name'
  Remove-Item -Path Env:SystemDrive -ErrorAction SilentlyContinue

  # Remove-Tree deletes a link inside the tree, and one at the root,
  # without touching what it points at.
  $victim = Join-Path $TestRoot 'victim'
  New-Item -ItemType Directory -Path $victim | Out-Null
  Set-Content -LiteralPath (Join-Path $victim 'keep.txt') -Value 'keep'
  $tree = Join-Path $TestRoot 'tree'
  New-Item -ItemType Directory -Path (Join-Path $tree 'nested') | Out-Null
  Set-Content -LiteralPath (Join-Path $tree 'nested\file.txt') -Value 'x'
  Set-ItemProperty -LiteralPath (Join-Path $tree 'nested\file.txt') -Name IsReadOnly -Value $true
  $linkType = if ($env:OS -eq 'Windows_NT') { 'Junction' } else { 'SymbolicLink' }
  New-Item -ItemType $linkType -Path (Join-Path $tree 'planted') -Target $victim | Out-Null
  Remove-Tree -Path $tree
  if (Test-Path -LiteralPath $tree) { Stop-OnFailure 'Remove-Tree left the tree' }
  if (-not (Test-Path -LiteralPath (Join-Path $victim 'keep.txt'))) { Stop-OnFailure 'Remove-Tree followed the link inside the tree' }
  $rootLink = Join-Path $TestRoot 'rootlink'
  New-Item -ItemType $linkType -Path $rootLink -Target $victim | Out-Null
  Remove-Tree -Path $rootLink
  if (Test-Path -LiteralPath $rootLink) { Stop-OnFailure 'Remove-Tree left the root link' }
  if (-not (Test-Path -LiteralPath (Join-Path $victim 'keep.txt'))) { Stop-OnFailure 'Remove-Tree followed the root link' }

  $dirs = Get-UserStateDir -UserHome 'C:\Users\dev'
  Assert-Equal 'C:\Users\dev\AppData\Roaming\safedep\pmg' $dirs[0] 'default config dir'
  Assert-Equal 'C:\Users\dev\AppData\Local\safedep\pmg' $dirs[1] 'default cache dir'
  Assert-Equal 'C:\Users\dev\.pmg' $dirs[2] 'legacy dir'
  $env:PMG_CONFIG_DIR = 'D:\pmg-config'
  $env:PMG_CACHE_DIR = 'D:\pmg-cache'
  $dirs = Get-UserStateDir -UserHome 'C:\Users\dev'
  Assert-Equal 'D:\pmg-config' $dirs[0] 'PMG_CONFIG_DIR override'
  Assert-Equal 'D:\pmg-cache' $dirs[1] 'PMG_CACHE_DIR override'
  Remove-Item -Path Env:PMG_CONFIG_DIR, Env:PMG_CACHE_DIR
}

Remove-Item -LiteralPath $TestRoot -Recurse -Force
Write-Host 'PASS'
