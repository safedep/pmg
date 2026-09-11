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
  $output = New-TemporaryFile
  try {
    $process = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -NoNewWindow -Wait -PassThru -RedirectStandardOutput $output.FullName
    return [pscustomobject]@{ ExitCode = $process.ExitCode; Output = @(Get-Content -LiteralPath $output.FullName) }
  } finally {
    Remove-Item -LiteralPath $output.FullName -Force -ErrorAction SilentlyContinue
  }
}

# Emit one object per target user with Name, Sid and Home.
#   - elevated: every local profile with a domain or machine SID and a home
#     under \Users. That is the passwd equivalent of a human account.
#   - unelevated: the current user only (the MDM ran us in user context).
function Get-TargetUser {
  if (-not (Test-Elevated)) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    return [pscustomobject]@{ Name = $identity.Name; Sid = $identity.User.Value; Home = $env:USERPROFILE }
  }
  $usersRoot = Join-Path $env:SystemDrive 'Users'
  $profiles = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
  foreach ($entry in $profiles) {
    $sid = $entry.PSChildName
    if ($sid -notlike 'S-1-5-21-*') { continue }
    $profileHome = (Get-ItemProperty -LiteralPath $entry.PSPath).ProfileImagePath
    if (-not $profileHome) { continue }
    if (-not $profileHome.StartsWith($usersRoot, [StringComparison]::OrdinalIgnoreCase)) { continue }
    if (-not (Test-Path -LiteralPath $profileHome -PathType Container)) { continue }
    try {
      $name = (New-Object Security.Principal.SecurityIdentifier($sid)).Translate([Security.Principal.NTAccount]).Value
    } catch {
      $name = Split-Path $profileHome -Leaf
    }
    [pscustomobject]@{ Name = $name; Sid = $sid; Home = $profileHome }
  }
}

# True if this user has a live interactive logon. Their desktop shell runs.
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
# The job file holds the credentials for the seconds the task runs. It lives
# in the user's own Temp directory, which only that user, SYSTEM and
# Administrators can read, and is deleted before this function returns.
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
  $workDir = Join-Path $User.Home "AppData\Local\Temp\$taskName"
  $exitFile = Join-Path $workDir 'exit.txt'
  New-Item -ItemType Directory -Path $workDir -Force | Out-Null
  try {
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
        foreach ($line in Get-Content -LiteralPath $log) { Write-Host "  $line" }
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
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
  }
}

# The script the scheduled task runs as the user. It reads the job file, sets
# the environment, runs pmg with its output in files, and records the exit code.
$AsUserRunner = @'
param([Parameter(Mandatory)][string]$WorkDir)
$ErrorActionPreference = 'Stop'
$job = Get-Content -LiteralPath (Join-Path $WorkDir 'job.json') -Raw | ConvertFrom-Json
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
  if ($acl.Owner -ne 'BUILTIN\Administrators' -or -not $acl.AreAccessRulesProtected) {
    Fail "the managed config lost the PMG security descriptor; delete it and run pmg setup install --system again"
  }
}

# Remove-GlobalConfig removes the managed config when present, unless
# PMG_KEEP_GLOBAL_CONFIG is set, then prunes the empty ProgramData directories.
function Remove-GlobalConfig {
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
# uninstaller removes it once the binary is gone. The value stays
# REG_EXPAND_SZ and other entries stay as written. A new logon reads the
# registry, so no broadcast is needed.
function Remove-MachinePathEntry {
  param([Parameter(Mandatory)][string]$Directory)
  $key = Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
  $entries = @($key.GetValue('Path', '', 'DoNotExpandEnvironmentNames') -split ';' | Where-Object { $_ })
  $target = $Directory.TrimEnd('\')
  $kept = @($entries | Where-Object {
      [Environment]::ExpandEnvironmentVariables($_).TrimEnd('\') -ine $target
    })
  if ($kept.Count -eq $entries.Count) { return }
  Set-ItemProperty -Path $key.PSPath -Name Path -Value ($kept -join ';') -Type ExpandString
}

# Per-user pmg state directories: env overrides win, else the Windows layout.
function Get-UserStateDir {
  param([Parameter(Mandatory)][string]$UserHome)
  $configDir = if ($env:PMG_CONFIG_DIR) { $env:PMG_CONFIG_DIR } else { "$UserHome\AppData\Roaming\safedep\pmg" }
  $cacheDir = if ($env:PMG_CACHE_DIR) { $env:PMG_CACHE_DIR } else { "$UserHome\AppData\Local\safedep\pmg" }
  return @($configDir, $cacheDir, "$UserHome\.pmg")
}
