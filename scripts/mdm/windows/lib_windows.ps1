# lib_windows.ps1 - shared helpers for the PMG Windows install and uninstall scripts.
#
# MDM tools (Intune, JumpCloud, ...) run scripts as SYSTEM, as an elevated
# administrator, or as the logged-on user. These helpers make each case work
# without the caller branching on it:
#
#   - Machine-scope actions (pmg.exe, the system shims, the managed config)
#     need an elevated process. Test-Elevated says whether this one is.
#   - Per-user actions (cloud credentials, cloud sync, a per-user removal)
#     go through Invoke-AsUser. Elevated, it runs the command inside the
#     user's own logon through a temporary scheduled task. Unelevated, it
#     runs the command in this process for the current user.
#
# Credential Manager needs the user's logon, so credential steps are gated on
# Test-UserSession. A logged-off user has no logon token, so no command can
# run as that user. The system install covers every account, so no per-user
# `pmg setup install` runs.
#
# This file is dot-sourced by the install and uninstall scripts. Deploy them
# together. Windows PowerShell 5.1 and PowerShell 7 both run it.

function Assert-Windows {
  $isWindowsHost = Get-Variable -Name IsWindows -ValueOnly -ErrorAction SilentlyContinue
  if ($PSVersionTable.PSEdition -eq 'Core' -and -not $isWindowsHost) {
    [Console]::Error.WriteLine('Error: this script is for Windows only')
    exit 1
  }
}

function Write-Info {
  param([string]$Message)
  Write-Host "==> $Message"
}

function Write-Warn {
  param([string]$Message)
  [Console]::Error.WriteLine("==> warning: $Message")
}

function Fail {
  param([string]$Message)
  [Console]::Error.WriteLine("Error: $Message")
  exit 1
}

function Test-Elevated {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ProgramW6432 names the 64-bit Program Files in a 32-bit host too. pmg.exe
# is 64-bit and resolves the same folder.
$ProgramFilesDir = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
$ProductDir = "$ProgramFilesDir\safedep\pmg"
$PmgBinary = "$ProductDir\pmg.exe"

# Machine-wide managed config. When this file is present and carries the PMG
# security descriptor, pmg treats it as authoritative and ignores every
# user's config. It must match the path pmg resolves on Windows.
$GlobalConfigDir = "$env:ProgramData\safedep\pmg"
$GlobalConfigFile = "$GlobalConfigDir\config.yml"

# Absolute path to the pmg binary. An MDM process has a minimal PATH, so fall
# back to the machine-wide install location.
function Resolve-Pmg {
  $command = Get-Command pmg -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($command) { return $command.Path }
  if (Test-Path -LiteralPath $PmgBinary -PathType Leaf) { return $PmgBinary }
  return $null
}

# Start-Process hands the child the console streams as they are. Windows
# PowerShell would otherwise wrap stderr lines into error records, and stop
# the script when an MDM redirects its output. Returns the exit code, or with
# -Capture an object with ExitCode and Output.
function Invoke-Native {
  param(
    [Parameter(Mandatory)][string]$FilePath,
    [Parameter(Mandatory)][string[]]$ArgumentList,
    [switch]$Capture
  )
  if (-not $Capture) {
    $process = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -NoNewWindow -Wait -PassThru
    return $process.ExitCode
  }
  # Not New-TemporaryFile: some Windows PowerShell hosts lack it.
  $output = [IO.Path]::GetTempFileName()
  try {
    $process = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -NoNewWindow -Wait -PassThru -RedirectStandardOutput $output
    return [pscustomobject]@{ ExitCode = $process.ExitCode; Output = @(Get-Content -LiteralPath $output -Encoding UTF8) }
  } finally {
    Remove-Item -LiteralPath $output -Force -ErrorAction SilentlyContinue
  }
}

# Get-ProfileEntry lists the profiles Windows knows, as Sid and Home. It is
# its own function so a test can feed the list.
function Get-ProfileEntry {
  foreach ($entry in Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList') {
    [pscustomobject]@{ Sid = $entry.PSChildName; Home = (Get-ItemProperty -LiteralPath $entry.PSPath).ProfileImagePath }
  }
}

# Emit one object per target user with Name, Sid and Home.
#   - elevated: every profile with a local or domain SID (S-1-5-21) or an
#     Entra ID SID (S-1-12-1) and a home under \Users. Service profiles
#     live under %SystemRoot%, so the home check drops them.
#   - unelevated: the current user only (the MDM ran us in user context).
function Get-TargetUser {
  if (-not (Test-Elevated)) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    return [pscustomobject]@{ Name = $identity.Name; Sid = $identity.User.Value; Home = $env:USERPROFILE }
  }
  $usersRoot = "$env:SystemDrive\Users"
  foreach ($entry in @(Get-ProfileEntry)) {
    if ($entry.Sid -notlike 'S-1-5-21-*' -and $entry.Sid -notlike 'S-1-12-1-*') { continue }
    $profileHome = [string]$entry.Home
    if (-not $profileHome) { continue }
    if (-not $profileHome.StartsWith($usersRoot, [StringComparison]::OrdinalIgnoreCase)) { continue }
    if (-not (Test-Path -LiteralPath $profileHome -PathType Container)) { continue }
    try {
      $name = (New-Object Security.Principal.SecurityIdentifier($entry.Sid)).Translate([Security.Principal.NTAccount]).Value
    } catch {
      $name = Split-Path $profileHome -Leaf
    }
    [pscustomobject]@{ Name = $name; Sid = $entry.Sid; Home = $profileHome }
  }
}

# True if this user has a live interactive logon, read as "their desktop
# shell runs". A replacement shell or a crashed Explorer reads as logged
# off. Win32_LogonSession is the direct question, and the Explorer check is
# enough for the desktop fleet this targets.
function Test-UserSession {
  param([Parameter(Mandatory)]$User)
  if (-not (Test-Elevated)) {
    return $User.Sid -eq [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  }
  $shells = Get-CimInstance -ClassName Win32_Process -Filter "Name = 'explorer.exe'"
  foreach ($shell in $shells) {
    $owner = Invoke-CimMethod -InputObject $shell -MethodName GetOwnerSid
    if ($owner.Sid -eq $User.Sid) { return $true }
  }
  return $false
}

# Run pmg as the given user with extra environment variables. Returns $true
# when pmg exited zero. Only call when Test-UserSession is true.
#
# Elevated, a temporary scheduled task with the Interactive logon type runs
# the command inside the user's logon, so Credential Manager and DPAPI work.
# The work directory sits under the product directory in ProgramData, which
# the system install owns, not under a path the user controls. Its ACL
# names SYSTEM, Administrators and that user only. The job file holds the
# credentials until the task reads it, which is its first step, and the
# whole directory is deleted before this function returns.
function Invoke-AsUser {
  param(
    [Parameter(Mandatory)]$User,
    [Parameter(Mandatory)][string]$PmgBin,
    [Parameter(Mandatory)][string[]]$ArgumentList,
    [hashtable]$Environment = @{}
  )
  if (-not (Test-Elevated)) {
    foreach ($name in $Environment.Keys) { Set-Item -Path "Env:$name" -Value $Environment[$name] }
    try {
      return (Invoke-Native -FilePath $PmgBin -ArgumentList $ArgumentList) -eq 0
    } finally {
      foreach ($name in $Environment.Keys) { Remove-Item -Path "Env:$name" -ErrorAction SilentlyContinue }
    }
  }

  $taskName = 'pmg-mdm-' + [guid]::NewGuid().ToString('N')
  $workDir = "$GlobalConfigDir\mdm\$taskName"
  $exitFile = Join-Path $workDir 'exit.txt'
  try {
    New-UserWorkDirectory -Path $workDir -UserSid $User.Sid
    $job = [ordered]@{ Exe = $PmgBin; Args = @($ArgumentList); Env = $Environment }
    Set-Content -LiteralPath (Join-Path $workDir 'job.json') -Value ($job | ConvertTo-Json -Compress) -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $workDir 'run.ps1') -Value $script:AsUserRunner -Encoding UTF8

    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $action = New-ScheduledTaskAction -Execute $powershell -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$workDir\run.ps1`" -WorkDir `"$workDir`""
    $principal = New-ScheduledTaskPrincipal -UserId $User.Sid -LogonType Interactive
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings | Out-Null
    Start-ScheduledTask -TaskName $taskName

    # The task takes a moment to reach Running. Once it ran, or after a
    # grace period, a task that is not Running and left no exit file
    # never started or was killed by its time limit.
    $started = Get-Date
    $deadline = $started.AddMinutes(6)
    $seenRunning = $false
    while (-not (Test-Path -LiteralPath $exitFile) -and (Get-Date) -lt $deadline) {
      Start-Sleep -Milliseconds 500
      $running = (Get-ScheduledTask -TaskName $taskName).State -eq 'Running'
      if ($running) { $seenRunning = $true; continue }
      if ($seenRunning -or (Get-Date) -gt $started.AddSeconds(30)) {
        Start-Sleep -Milliseconds 500
        if (-not (Test-Path -LiteralPath $exitFile)) { break }
      }
    }

    foreach ($stream in 'stdout', 'stderr') {
      $log = Join-Path $workDir "$stream.log"
      if (Test-Path -LiteralPath $log) {
        foreach ($line in Get-Content -LiteralPath $log -Encoding UTF8) { Write-Host "  $line" }
      }
    }
    if (-not (Test-Path -LiteralPath $exitFile)) {
      Write-Warn "the command did not finish for $($User.Name); task result $((Get-ScheduledTaskInfo -TaskName $taskName).LastTaskResult)"
      return $false
    }
    return (Get-Content -LiteralPath $exitFile -Raw).Trim() -eq '0'
  } catch {
    Write-Warn "could not run pmg as $($User.Name): $($_.Exception.Message)"
    return $false
  } finally {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    # The user has Modify on this directory, so a process of theirs can hold
    # a file open. That must not end the run for the other users.
    try {
      if (Test-Path -LiteralPath $workDir) { Remove-Tree -Path $workDir }
    } catch {
      Write-Warn "could not remove ${workDir}: $($_.Exception.Message)"
    }
  }
}

# New-UserWorkDirectory creates the work directory of one hop. The two
# directories above it must be the system install's: they exist, they are
# no reparse points, Administrators or SYSTEM own them and nothing is
# inherited. Then the new directory gets its own ACL for SYSTEM,
# Administrators and the user.
function New-UserWorkDirectory {
  param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$UserSid)
  foreach ($dir in (Split-Path $GlobalConfigDir), $GlobalConfigDir) {
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) { throw "$dir does not exist; the system install is missing" }
    $item = Get-Item -LiteralPath $dir -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$dir is a link or a junction" }
    $acl = Get-Acl -LiteralPath $dir
    if (-not (Test-AdministrativeOwner -Acl $acl) -or -not $acl.AreAccessRulesProtected) {
      throw "$dir does not carry the PMG security descriptor; run pmg setup install --system first"
    }
  }
  New-Item -ItemType Directory -Path (Split-Path $Path) -Force | Out-Null
  New-Item -ItemType Directory -Path $Path | Out-Null
  $acl = Get-Acl -LiteralPath $Path
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($grant in @(@('S-1-5-18', 'FullControl'), @('S-1-5-32-544', 'FullControl'), @($UserSid, 'Modify'))) {
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
          (New-Object Security.Principal.SecurityIdentifier($grant[0])), $grant[1], 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
  }
  Set-Acl -LiteralPath $Path -AclObject $acl
}

# Test-AdministrativeOwner compares the owner SID, because the account name
# is localized. Administrators or SYSTEM own what PMG writes, the same rule
# as internal/platform in the binary.
function Test-AdministrativeOwner {
  param([Parameter(Mandatory)]$Acl)
  $owner = $Acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
  return $owner -eq 'S-1-5-32-544' -or $owner -eq 'S-1-5-18'
}

# Remove-Tree deletes a directory that another account may have shaped. A
# junction or a symbolic link, at the root or inside, is removed as a link
# and never followed. Remove-Item -Recurse in Windows PowerShell follows
# both, and .NET Framework's recursive Directory.Delete throws on a
# junction, so the walk is explicit.
function Remove-Tree {
  param([Parameter(Mandatory)][string]$Path)
  if ([IO.File]::GetAttributes($Path) -band [IO.FileAttributes]::ReparsePoint) {
    [IO.Directory]::Delete($Path)
    return
  }
  foreach ($child in [IO.Directory]::GetDirectories($Path)) {
    Remove-Tree -Path $child
  }
  foreach ($file in [IO.Directory]::GetFiles($Path)) {
    [IO.File]::SetAttributes($file, [IO.FileAttributes]::Normal)
    [IO.File]::Delete($file)
  }
  [IO.Directory]::Delete($Path)
}

# The script the scheduled task runs as the user. It reads the job file, sets
# the environment, runs pmg with its output in files, and records the exit code.
$AsUserRunner = @'
param([Parameter(Mandatory)][string]$WorkDir)
$ErrorActionPreference = 'Stop'
$job = Get-Content -LiteralPath (Join-Path $WorkDir 'job.json') -Raw | ConvertFrom-Json
Remove-Item -LiteralPath (Join-Path $WorkDir 'job.json') -Force
foreach ($variable in $job.Env.PSObject.Properties) {
  Set-Item -Path "Env:$($variable.Name)" -Value $variable.Value
}
$process = Start-Process -FilePath $job.Exe -ArgumentList @($job.Args) -NoNewWindow -Wait -PassThru `
  -RedirectStandardOutput (Join-Path $WorkDir 'stdout.log') -RedirectStandardError (Join-Path $WorkDir 'stderr.log')
Set-Content -LiteralPath (Join-Path $WorkDir 'exit.txt') -Value $process.ExitCode
'@

# Install-GlobalConfig <src> replaces the content of the managed config that
# `pmg setup install --system` wrote. The write truncates the existing file
# in place, so the PMG security descriptor stays. A check confirms that.
function Install-GlobalConfig {
  param([Parameter(Mandatory)][string]$Source)
  Write-Info "Installing globally managed config to $GlobalConfigFile"
  if (-not (Test-Path -LiteralPath $GlobalConfigFile -PathType Leaf)) {
    Fail "the managed config $GlobalConfigFile does not exist; run pmg setup install --system first"
  }
  [IO.File]::WriteAllBytes($GlobalConfigFile, [IO.File]::ReadAllBytes($Source))
  $acl = Get-Acl -LiteralPath $GlobalConfigFile
  if (-not (Test-AdministrativeOwner -Acl $acl) -or -not $acl.AreAccessRulesProtected) {
    Fail "the managed config lost the PMG security descriptor; delete it and run pmg setup install --system again"
  }
}

# Remove-GlobalConfig removes the managed config when present, unless
# PMG_KEEP_GLOBAL_CONFIG is set, then prunes the empty ProgramData directories.
# The hops' scratch directory goes first in every case. It is the script's,
# not the config's, and the tree is SYSTEM's, so a leftover from an aborted
# run is safe to delete.
function Remove-GlobalConfig {
  if (Test-Path -LiteralPath "$GlobalConfigDir\mdm") { Remove-Tree -Path "$GlobalConfigDir\mdm" }
  if ($env:PMG_KEEP_GLOBAL_CONFIG) {
    if (Test-Path -LiteralPath $GlobalConfigFile) {
      Write-Info "Keeping globally managed config ($GlobalConfigFile); PMG_KEEP_GLOBAL_CONFIG is set"
    }
    return
  }
  if (Test-Path -LiteralPath $GlobalConfigFile) {
    Write-Info "Removing globally managed config $GlobalConfigFile"
    Remove-Item -LiteralPath $GlobalConfigFile -Force
  }
  Remove-EmptyDirectory $GlobalConfigDir
  Remove-EmptyDirectory (Split-Path $GlobalConfigDir)
}

function Remove-EmptyDirectory {
  param([Parameter(Mandatory)][string]$Path)
  if ((Test-Path -LiteralPath $Path -PathType Container) -and -not (Get-ChildItem -LiteralPath $Path -Force)) {
    Remove-Item -LiteralPath $Path -Force
  }
}

# Remove-MachinePathEntry <dir> drops a directory from the machine PATH.
# `pmg setup remove --system` keeps the pmg.exe entry by design, so the
# uninstaller removes it once the binary is gone. The compare and the write
# follow pathScope.remove in the binary: an entry may carry quotes, and the
# value keeps its kind. Other entries stay as written. A new logon reads the
# registry, so no broadcast is needed.
function Remove-MachinePathEntry {
  param([Parameter(Mandatory)][string]$Directory)
  $key = Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
  $entries = @($key.GetValue('Path', '', 'DoNotExpandEnvironmentNames') -split ';' | Where-Object { $_ })
  $target = $Directory.TrimEnd('\')
  $kept = @($entries | Where-Object {
      [Environment]::ExpandEnvironmentVariables($_.Trim('"')).TrimEnd('\') -ine $target
    })
  if ($kept.Count -eq $entries.Count) { return }
  Set-ItemProperty -Path $key.PSPath -Name Path -Value ($kept -join ';') -Type $key.GetValueKind('Path')
}

# Per-user pmg state directories: env overrides win, else the Windows layout.
function Get-UserStateDir {
  param([Parameter(Mandatory)][string]$UserHome)
  $configDir = if ($env:PMG_CONFIG_DIR) { $env:PMG_CONFIG_DIR } else { "$UserHome\AppData\Roaming\safedep\pmg" }
  $cacheDir = if ($env:PMG_CACHE_DIR) { $env:PMG_CACHE_DIR } else { "$UserHome\AppData\Local\safedep\pmg" }
  return @($configDir, $cacheDir, "$UserHome\.pmg")
}
