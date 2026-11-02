# Windows Support

Use `pmg setup install` on Windows to run `npm`, `pip` and the other supported package managers through PMG with no change to how you type.

```powershell
pmg setup install
```

**Requires Windows 10 or 11 on x86-64.**
The release ships `pmg_Windows_x86_64.zip` and `pmg_Windows_x86_64.msi`.
Windows 11 on ARM64 can run the x64 build through [emulation](https://learn.microsoft.com/en-us/windows/arm/apps-on-arm-x86-emulation).
Windows 10 on ARM is unsupported.

The MSI performs a machine-wide setup automatically.
Run it from an administrator terminal, or use Chocolatey.
No per-user `pmg setup install` is needed after an MSI install.

```powershell
msiexec /i pmg_Windows_x86_64.msi /qn
# Or use Chocolatey.
choco install pmg
```

The npm route is `npm install -g @safedep/pmg`.
For a manual ZIP or npm install, run per-user setup from your own normal terminal.
Cross-account elevation can configure a different user's profile.
Use administrator `--system` setup for all users.
See [system installation](system-install.md).

`pmg setup install` writes one `.cmd` shim for each supported package manager and puts the shim directory first on your user `PATH`. PMG installs no shell alias and no PowerShell profile function on Windows. The shims are the whole interception layer. `cmd.exe`, PowerShell and any program that applies `PATHEXT` find them.

Open a new terminal, then confirm with:

```powershell
Get-Command npm    # should resolve under %LOCALAPPDATA%\safedep\pmg\bin
pmg setup doctor
```

CI steps do not reread the registry PATH.
For manual GitHub Actions setup, append the shim directory to the job PATH after setup.
Use the current step's explicit `pmg` prefix until the later step receives that PATH.
The PMG GitHub Action itself supports Linux runners only.

```powershell
"$env:LOCALAPPDATA\safedep\pmg\bin" | Out-File -FilePath $env:GITHUB_PATH -Append -Encoding utf8
```

For a manual ZIP upgrade, keep `pmg.exe` at a stable path.
Stop the running executable before replacing it in place.
If you move it, run setup again from the new binary.
Shims retain the recorded PMG path and can otherwise use an old binary or fail with exit 127.
Use `pmg setup doctor` to check the result.
MSI upgrades use the separate [system upgrade procedure](system-install.md).

To uninstall:

```powershell
pmg setup remove
```

This removes the user shims and user PATH entry.
Configuration and cache stay.
Use `pmg setup remove --config-file` to request config removal too.
Remove setup before deleting a manual executable or uninstalling the npm package.
If the binary is already gone, remove the stale per-user shim directory and its user PATH entry.
Use the elevated system removal procedure for machine shims.

## Files created

| Item                   | Path                                          |
| ---------------------- | --------------------------------------------- |
| Configuration          | `%APPDATA%\safedep\pmg\config.yml`            |
| Package-manager shims  | `%LOCALAPPDATA%\safedep\pmg\bin\<manager>.cmd` |
| PATH entry             | `HKCU\Environment`, user scope, prepended     |
| Event log, cache, data | `%LOCALAPPDATA%\safedep\pmg`                  |
| Managed configuration  | `%PROGRAMDATA%\safedep\pmg\config.yml`        |

The managed configuration file exists only when an administrator deploys one. For a fleet, the scripts in [`scripts/mdm`](../scripts/mdm) install PMG machine-wide and deploy it.

## Supported package managers

npm, npx, pnpm, pnpx, yarn, pip, pip3, pipx, poetry, uv, uvx and bun get a shim. Each one trusts PMG's ephemeral certificate authority through the environment variables PMG injects, so by default no certificate goes into the Windows certificate store.
After `pmg setup cert install`, all managers can reuse that persisted CA.

PMG also writes aube, aubr and aubx shims, but aube is not part of the initial Windows version. See [safedep/pmg#457](https://github.com/safedep/pmg/issues/457).

Experimental `pmg go` and `pmg cargo` have no automatic shim.
Use the explicit PMG prefix.
Cargo receives `CARGO_HTTP_CAINFO` and `CARGO_HTTP_CHECK_REVOKE=false`.
On Windows, the latter disables Cargo revocation checks for all HTTPS traffic in the guarded run, including Cargo nested under another manager.

`pmg go` needs persistent OS trust. Go reads the OS trust store only, so run `pmg setup cert install` once before `pmg go get`. macOS has the same requirement. See [cert.md](./cert.md).

## How a shim starts the manager

When you type `npm install lodash`, the shell finds `npm.cmd` in the shim directory and runs it. `cmd.exe` and PowerShell both resolve it this way, through `PATH` and `PATHEXT`. The shim does two things:

1. It stores your argument text, unchanged, in the environment variable `PMG_RAW_ARGS`.
2. It runs `pmg npm` with the same arguments.

PMG then locates the real `npm`. On Windows that is `npm.cmd`, a batch file, and a batch file is not a program. PMG starts it through `cmd.exe` and passes it the text from `PMG_RAW_ARGS` as it is. PMG adds no quoting of its own. The real `npm` reads your arguments after one parse, the same as when you run it with no PMG. PMG's tests compare the two, argument by argument, in `cmd.exe` and in PowerShell.

`pmg npm install lodash` typed by hand takes a different route. PMG receives parsed arguments without the raw text.
Go rebuilds a command line with standard Windows C-runtime quoting.
`cmd.exe` parses it again with different rules, so the text has two parsing stages. The result is the same for normal arguments. For an argument that carries a quote or a caret, prefer the shim, where the text is parsed once.

`cmd.exe` expands `%NAME%` in the text before the real `npm` reads it. `%USERNAME%` is expanded before PMG sees it, so PMG passes the value, not the reference. A variable whose value itself contains `%NAME%` is expanded a second time.

## Limitations

A `PATH` shim does not intercept everything. `pmg setup doctor` reports the state on your machine rather than assuming it.

- **Current directory.** `cmd.exe` searches the current directory before `PATH`. A repository that holds its own `npm.cmd` runs that file, not the shim.
- **Programs that skip the shell.** A program that starts `npm` directly, with no shell, appends `.exe` only and never finds a `.cmd` shim. For `.cmd`-based managers such as npm, npx, or npm-installed pnpm and Yarn, this can mean no program is found.
  Managers that ship an `.exe`, including pip, pip3, pipx, uv, uvx, Bun, and Poetry, can instead run directly without PMG.
  Use `pmg <manager>` explicitly in scripts and IDE tasks.
- **Node.js from the MSI is not intercepted by a per-user install.** The nodejs.org installer, `winget install OpenJS.NodeJS` and Chocolatey put `C:\Program Files\nodejs` on the machine `PATH`. Windows builds a process `PATH` as the machine value, then the user value, so the per-user shim directory can never move ahead of it. On such a machine a bare `npm install` runs Node's own `npm`. `pmg setup install` and `pmg setup doctor` report this. The fix is a machine-wide install: `pmg setup install --system` from a terminal started as administrator puts administrator-owned shims first on the machine `PATH`. The binary must first be at `%ProgramFiles%\safedep\pmg\pmg.exe` without a reparse point on that path.
  The MSI puts it there and performs system setup.
  See [system-install.md](./system-install.md). Until then, run it as `pmg npm`. Do not put `%LOCALAPPDATA%\safedep\pmg\bin` on the machine `PATH` yourself: a user-writable directory there lets a standard user plant a binary that an elevated process runs.
- **User PATH.** A per-user installer can prepend its own directory. The python.org installer does. Run `pmg setup install` again: it moves the shim directory back to the front of the user `PATH`.
- **Shell profile.** `fnm env | Invoke-Expression` in `$PROFILE` prepends the directory that holds `npm`, and PMG cannot reorder a profile. Run it as `pmg npm`, or drop that line from the profile. `pmg setup install` and `pmg setup doctor` name each manager that resolves ahead of the shims and give a corrective action.
  They do not show the per-manager resolved path.
- **Git Bash.** Git Bash does not apply `PATHEXT`, so it never runs a `.cmd` shim and resolves `npm` to Node's own `npm` shell script. Run `pmg npm ...` in Git Bash, or use PowerShell or `cmd.exe`.
- **Unquoted metacharacters.** The shim forwards your arguments to `cmd.exe`, which reads an unquoted `&`, `|`, `<` or `>` as its own. `npm.cmd` behaves the same way, so PMG changes nothing here. Quote the argument.
- **Interpreter entry points.** `python -m pip` and `py -m pip` do not invoke a pip shim.
  Use `pmg pip install ...`, or import the proxy and trust environment for a running foreground proxy.
  Starting a proxy alone does not route Python through it.
- **No sandbox.** Windows does not support the current sandbox model.
  Keep `sandbox.enabled: false` in Windows fleet configuration.
  Commands that reach sandbox resolution with it enabled fail instead of silently running unconfined.
  See [sandbox.md](sandbox.md).
- **No proxy daemon.** `pmg proxy start --daemon` needs a detached process, a liveness check and a stop path that Windows does not share with Unix. Use a foreground start and Ctrl+C shutdown.
  The current liveness probe makes stop, status, and stop/report gating unsupported on Windows.
  Stop can remove a live server's state and return an error while it continues running.
  Import plain `KEY=VALUE` output in PowerShell as shown below.
  `--export` produces POSIX syntax, not PowerShell syntax.
- **WSL.** WSL 2 uses the Linux build subject to its kernel and driver requirements.
  WSL 1 has no Linux kernel and cannot provide Landlock or Bubblewrap.
  Enabling sandboxing there fails.
  Check with `pmg setup doctor`.
  PMG inside WSL protects only that environment's toolchain.

For a foreground proxy in another terminal, import its environment in the client terminal.
Use the same config, cache, and state scope for both terminals.

```powershell
pmg proxy env | ForEach-Object {
    $name, $value = $_ -split '=', 2
    [Environment]::SetEnvironmentVariable($name, $value, 'Process')
}
```

See [persistent proxy commands](persistent-proxy.md#commands) for the Windows lifecycle limit.
