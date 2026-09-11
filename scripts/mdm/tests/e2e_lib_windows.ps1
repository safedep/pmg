# e2e_lib_windows.ps1 - shared helpers for the Windows MDM E2E test scripts.
# Set $TestRoot before you dot-source this file. It is test-only and not part
# of any deployment package.
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') {
  [Console]::Error.WriteLine('Error: the Windows E2E tests run on Windows only')
  exit 1
}

$ProductDir = "$env:ProgramFiles\safedep\pmg"
$PmgExe = "$ProductDir\pmg.exe"
$GlobalConfig = "$env:ProgramData\safedep\pmg\config.yml"
$WrapperDir = "$TestRoot\pmg-wrapper"
$CloudCalls = "$WrapperDir\cloud.calls"
$CloudEnv = "$WrapperDir\cloud.env"
$CloudUnexpected = "$WrapperDir\cloud.unexpected"
$TestApiKey = 'pmg-mdm-e2e-api-key'
$TestTenantId = 'pmg-mdm-e2e-tenant'
$ExpectedIdentity = (& whoami).Trim()
# Intune runs Windows PowerShell, so the scripts under test run in it too.
$WindowsPowerShell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

function Stop-OnFailure {
  param([string]$Message)
  [Console]::Error.WriteLine("FAIL: $Message")
  exit 1
}

function Write-Step {
  param([string]$Message)
  Write-Host "==> $Message"
}

function Assert-Equal {
  param($Expected, $Actual, [string]$Message)
  if ("$Actual" -ne "$Expected") { Stop-OnFailure "${Message}: expected '$Expected', got '$Actual'" }
}

function Assert-PathPresent {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { Stop-OnFailure "missing path: $Path" }
}

function Assert-PathAbsent {
  param([string]$Path)
  if (Test-Path -LiteralPath $Path) { Stop-OnFailure "path still exists: $Path" }
}

function Get-CaptureLine {
  param([string]$Path)
  if (Test-Path -LiteralPath $Path) { return @(Get-Content -LiteralPath $Path | Where-Object { $_ }) }
  return @()
}

# The wrapper shadows pmg on PATH. It records cloud login, sync and logout
# calls with the identity that made them instead of reaching SafeDep Cloud,
# and forwards every other call to the installed binary. The scripts resolve
# it through Get-Command, and the scheduled-task hop runs it as the user.
function New-PmgWrapper {
  New-Item -ItemType Directory -Path $WrapperDir -Force | Out-Null
  # Every local account may write the capture files: the hop runs the wrapper
  # as the target user, and SYSTEM runs it in the SYSTEM scenario.
  & icacls $TestRoot /grant '*S-1-5-32-545:(OI)(CI)F' | Out-Null
  $wrapper = @'
@echo off
setlocal
set "WRAPPER_DIR=%~dp0"
set "REAL=%ProgramFiles%\safedep\pmg\pmg.exe"
if /i "%~1"=="cloud" goto cloud
if not exist "%REAL%" goto missing
"%REAL%" %*
exit /b %ERRORLEVEL%
:missing
echo Error: installed pmg binary not found 1>&2
exit /b 1
:cloud
for /f "usebackq delims=" %%u in (`whoami`) do set "WHO=%%u"
>>"%WRAPPER_DIR%cloud.calls" echo %WHO%;%*
>>"%WRAPPER_DIR%cloud.env" echo %WHO%;%SAFEDEP_API_KEY%;%SAFEDEP_TENANT_ID%
if "%*"=="cloud login --from-env" exit /b 0
if "%*"=="cloud logout" exit /b 0
if "%*"=="cloud sync --timeout 1m" exit /b 0
>>"%WRAPPER_DIR%cloud.unexpected" echo %WHO%;%*
exit /b 1
'@
  Set-Content -LiteralPath "$WrapperDir\pmg.cmd" -Value $wrapper -Encoding Ascii
  Reset-WrapperCapture
}

function Reset-WrapperCapture {
  foreach ($capture in $CloudCalls, $CloudEnv, $CloudUnexpected) {
    Set-Content -LiteralPath $capture -Value '' -Encoding Ascii
  }
}

# Run a script under Windows PowerShell with the wrapper first on PATH and
# the given environment. Prints the output and returns the exit code.
function Invoke-Script {
  param([string]$Path, [string[]]$ArgumentList = @(), [hashtable]$Environment = @{})
  $savedPath = $env:Path
  $savedModulePath = $env:PSModulePath
  $env:Path = "$WrapperDir;$env:Path"
  # This test runs in pwsh, which exports its own module path. Windows
  # PowerShell cannot load those modules and then fails to autoload its own.
  # An MDM starts Windows PowerShell fresh, so give it a fresh environment.
  Remove-Item -Path Env:PSModulePath
  foreach ($name in $Environment.Keys) { Set-Item -Path "Env:$name" -Value $Environment[$name] }
  $stdout = "$TestRoot\script.out"
  $stderr = "$TestRoot\script.err"
  try {
    $arguments = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $Path) + $ArgumentList
    $process = Start-Process -FilePath $WindowsPowerShell -ArgumentList $arguments -NoNewWindow -Wait -PassThru `
      -RedirectStandardOutput $stdout -RedirectStandardError $stderr
  } finally {
    $env:Path = $savedPath
    $env:PSModulePath = $savedModulePath
    foreach ($name in $Environment.Keys) { Remove-Item -Path "Env:$name" -ErrorAction SilentlyContinue }
  }
  Get-Content -LiteralPath $stdout | ForEach-Object { Write-Host "  | $_" }
  Get-Content -LiteralPath $stderr | ForEach-Object { Write-Host "  ! $_" }
  return $process.ExitCode
}

# Run a script as SYSTEM through a scheduled task, the way Intune runs it.
# A small runner sets PATH and the environment, then records the exit code.
function Invoke-ScriptAsSystem {
  param([string]$Path, [hashtable]$Environment = @{})
  $workDir = "$TestRoot\system"
  New-Item -ItemType Directory -Path $workDir -Force | Out-Null
  Remove-Item -LiteralPath "$workDir\exit.txt" -Force -ErrorAction SilentlyContinue
  $environmentLines = foreach ($name in $Environment.Keys) { "`$env:$name = '$($Environment[$name])'" }
  $runner = @"
`$env:Path = '$WrapperDir;' + `$env:Path
$($environmentLines -join "`n")
`$process = Start-Process -FilePath '$WindowsPowerShell' -ArgumentList @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', '$Path') -NoNewWindow -Wait -PassThru ``
  -RedirectStandardOutput '$workDir\stdout.log' -RedirectStandardError '$workDir\stderr.log'
Set-Content -LiteralPath '$workDir\exit.txt' -Value `$process.ExitCode
"@
  Set-Content -LiteralPath "$workDir\run.ps1" -Value $runner -Encoding Ascii

  $taskName = 'pmg-mdm-e2e-system'
  $action = New-ScheduledTaskAction -Execute $WindowsPowerShell -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$workDir\run.ps1`""
  $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Force | Out-Null
  try {
    Start-ScheduledTask -TaskName $taskName
    $deadline = (Get-Date).AddMinutes(10)
    while (-not (Test-Path -LiteralPath "$workDir\exit.txt") -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 1 }
  } finally {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
  }
  foreach ($log in "$workDir\stdout.log", "$workDir\stderr.log") {
    if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log | ForEach-Object { Write-Host "  | $_" } }
  }
  if (-not (Test-Path -LiteralPath "$workDir\exit.txt")) { Stop-OnFailure 'the SYSTEM run did not finish' }
  return [int](Get-Content -LiteralPath "$workDir\exit.txt" -Raw).Trim()
}

# Run the installed pmg.exe and return its exit code and output lines.
function Invoke-Pmg {
  param([string[]]$ArgumentList)
  $stdout = "$TestRoot\pmg.out"
  $process = Start-Process -FilePath $PmgExe -ArgumentList $ArgumentList -NoNewWindow -Wait -PassThru -RedirectStandardOutput $stdout
  return [pscustomobject]@{ ExitCode = $process.ExitCode; Output = @(Get-Content -LiteralPath $stdout) }
}

function Get-MachinePathEntry {
  $key = Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
  return @($key.GetValue('Path', '', 'DoNotExpandEnvironmentNames') -split ';' | Where-Object { $_ })
}

# The descriptor `pmg setup install --system` writes: Administrators own the
# object, nothing is inherited, SYSTEM and Administrators have full control,
# Users may read and execute.
function Assert-PmgDescriptor {
  param([string]$Path)
  $acl = Get-Acl -LiteralPath $Path
  if ($acl.Owner -ne 'BUILTIN\Administrators') { Stop-OnFailure "$Path is owned by $($acl.Owner)" }
  if (-not $acl.AreAccessRulesProtected) { Stop-OnFailure "$Path inherits its DACL" }
  $rules = $acl.Access
  if ($rules.Count -ne 3) { Stop-OnFailure "$Path has $($rules.Count) entries, not 3" }
  $users = $rules | Where-Object { $_.IdentityReference -eq 'BUILTIN\Users' }
  if (-not $users -or $users.FileSystemRights -ne 'ReadAndExecute, Synchronize') { Stop-OnFailure "$Path gives Users $($users.FileSystemRights)" }
  foreach ($admin in 'BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM') {
    $entry = $rules | Where-Object { $_.IdentityReference -eq $admin }
    if (-not $entry -or $entry.FileSystemRights -ne 'FullControl') { Stop-OnFailure "$Path does not give $admin full control" }
  }
}

function Assert-Installed {
  param([string]$ConfigSource)
  Assert-PathPresent $PmgExe
  Assert-PathPresent "$ProductDir\bin\npm.cmd"
  $entries = Get-MachinePathEntry
  if ($entries[0] -ine "$ProductDir\bin") { Stop-OnFailure "the shim directory is not first on the machine PATH: $($entries[0])" }
  Assert-Equal 1 @($entries | Where-Object { $_ -ieq $ProductDir }).Count 'product directory entries on the machine PATH'
  Assert-PathPresent $GlobalConfig
  Assert-Equal (Get-Content -LiteralPath $ConfigSource -Raw).Trim() (Get-Content -LiteralPath $GlobalConfig -Raw).Trim() 'managed config content'
  foreach ($object in $GlobalConfig, $ProductDir, $PmgExe, "$ProductDir\bin\npm.cmd") { Assert-PmgDescriptor $object }
  $get = Invoke-Pmg -ArgumentList @('config', 'get', 'paranoid')
  Assert-Equal 0 $get.ExitCode 'pmg config get exit code'
  Assert-Equal 'true' ($get.Output | Where-Object { $_ -in 'true', 'false' } | Select-Object -First 1) 'managed config value'
  $set = Invoke-Pmg -ArgumentList @('config', 'set', 'paranoid', 'false')
  if ($set.ExitCode -eq 0) { Stop-OnFailure 'pmg config set must refuse under a managed config' }
}

function Assert-Uninstalled {
  Assert-PathAbsent $ProductDir
  $entries = Get-MachinePathEntry
  if ($entries | Where-Object { $_ -ieq "$ProductDir\bin" -or $_ -ieq $ProductDir }) { Stop-OnFailure "a PMG entry is still on the machine PATH: $($entries -join ';')" }
  Assert-PathAbsent $GlobalConfig
  Assert-PathAbsent "$env:APPDATA\safedep\pmg"
  Assert-PathAbsent "$env:LOCALAPPDATA\safedep\pmg"
}

function Assert-CloudCall {
  param([string]$Identity, [string[]]$Expected, [string]$Message)
  $calls = @(Get-CaptureLine $CloudCalls | Where-Object { $_ -like "$Identity;*" } | ForEach-Object { $_.Substring($Identity.Length + 1) })
  Assert-Equal ($Expected -join "`n") ($calls -join "`n") $Message
}

function Assert-CloudCredential {
  param([string]$Identity)
  $lines = @(Get-CaptureLine $CloudEnv | Where-Object { $_ -like "$Identity;*" })
  if (-not $lines) { Stop-OnFailure "no cloud call recorded credentials for $Identity" }
  foreach ($line in $lines) { Assert-Equal "$Identity;$TestApiKey;$TestTenantId" $line 'cloud call credentials' }
}

function Assert-NoUnexpectedCloud {
  $unexpected = Get-CaptureLine $CloudUnexpected
  if ($unexpected) { Stop-OnFailure "unexpected cloud call: $($unexpected -join ' | ')" }
}

function Assert-Elevated {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Stop-OnFailure 'the Windows E2E must run elevated' }
}

# Say who is logged on. The scheduled-task hop needs the runner account to
# own a desktop shell, and this output explains a failure of that assumption.
function Write-SessionReport {
  Write-Step "running as $ExpectedIdentity"
  foreach ($shell in Get-CimInstance -ClassName Win32_Process -Filter "Name = 'explorer.exe'") {
    $owner = Invoke-CimMethod -InputObject $shell -MethodName GetOwnerSid
    Write-Host "  explorer.exe owned by $($owner.Sid)"
  }
}
