# pmg_uninstall_windows.ps1 - Remove PMG from a Windows machine.
#
# Deploy via Intune, JumpCloud or any MDM, alongside lib_windows.ps1 in the
# same directory. Run as SYSTEM or as an administrator, it cleans up every
# local user's config, cache and shims, clears Credential Manager credentials
# for logged-on users, then removes the system install, the binary and the
# managed config. Run as a standard user, it cleans up just that user. See
# lib_windows.ps1 for the model.

$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\lib_windows.ps1"

Assert-Windows

$PmgBin = Resolve-Pmg

function Remove-UserState {
  param([Parameter(Mandatory)]$User)
  Write-Info "Removing pmg state for $($User.Name)"

  if ($PmgBin -and (Test-UserSession -User $User)) {
    if (-not (Invoke-AsUser -User $User -PmgBin $PmgBin -ArgumentList @('setup', 'remove'))) {
      Write-Warn "failed to remove shims for $($User.Name)"
    }
    if (-not (Invoke-AsUser -User $User -PmgBin $PmgBin -ArgumentList @('cloud', 'logout'))) {
      Write-Warn "failed to clear Credential Manager credentials for $($User.Name)"
    }
  } elseif ($PmgBin) {
    Write-Info "  $($User.Name) has no active session; a per-user PATH entry and Credential Manager credentials (if any) remain"
  } else {
    Write-Warn "pmg binary not found; a per-user PATH entry for $($User.Name) may remain"
  }

  foreach ($dir in Get-UserStateDir -UserHome $User.Home) {
    if (Test-Path -LiteralPath $dir) {
      try {
        Remove-Item -LiteralPath $dir -Recurse -Force
      } catch {
        Write-Warn "failed to remove $dir for $($User.Name): $($_.Exception.Message)"
      }
    }
  }
}

function Remove-Binary {
  if (Test-Path -LiteralPath $PmgBinary) {
    Write-Info "Removing $PmgBinary"
    Remove-Item -LiteralPath $PmgBinary -Force
  }
  if (Test-Path -LiteralPath $ProductDir) {
    Remove-Item -LiteralPath $ProductDir -Recurse -Force
  }
  Remove-EmptyDirectory (Split-Path $ProductDir)
  # `pmg setup remove --system` drops the shim entry, but it did not run
  # when pmg.exe was already gone or when it failed. The directory is gone
  # in every case, so the entry goes too.
  Remove-MachinePathEntry -Directory "$ProductDir\bin"
  Remove-MachinePathEntry -Directory $ProductDir
}

$Elevated = Test-Elevated

# The system removal runs first. It keeps pmg.exe for the per-user steps,
# and every pmg run writes state under the invoking user, which the user
# loop then deletes.
if ($Elevated -and (Test-Path -LiteralPath $PmgBinary)) {
  if ((Invoke-Native -FilePath $PmgBinary -ArgumentList @('setup', 'remove', '--system')) -ne 0) {
    Write-Warn 'pmg setup remove --system failed'
  }
}

foreach ($user in @(Get-TargetUser)) {
  Remove-UserState -User $user
}

if (-not $Elevated) {
  Write-Warn 'not elevated; machine-scope steps skipped'
  Write-Info 'pmg uninstall complete'
  exit 0
}

Remove-Binary
Remove-GlobalConfig

Write-Info 'pmg uninstall complete'
