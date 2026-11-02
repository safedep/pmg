# Windows Support

Use `pmg setup install` on Windows to run `npm`, `pip` and the other supported package managers through PMG with no change to how you type.

```powershell
pmg setup install
```

**Requires Windows 10 or 11 on x86-64.** The release ships `pmg_Windows_x86_64.zip` and `pmg_Windows_x86_64.msi`. Windows 11 on ARM64 can run the x64 build through [emulation](https://learn.microsoft.com/en-us/windows/arm/apps-on-arm-x86-emulation). Windows 10 on ARM is unsupported.

`pmg setup install` writes one `.cmd` shim for each supported package manager and puts the shim directory first on your user `PATH`. PMG installs no shell alias and no PowerShell profile function on Windows. The shims are the whole interception layer. `cmd.exe`, PowerShell and any program that applies `PATHEXT` find them.

Open a new terminal, then confirm with:

```powershell
Get-Command npm    # should resolve under %LOCALAPPDATA%\safedep\pmg\bin
pmg setup doctor
```

The MSI runs the machine-wide setup for you. Run it from an administrator terminal, or install it with Chocolatey. After an MSI install, you do not need a per-user `pmg setup install`. See [system installation](system-install.md).

```powershell
msiexec /i pmg_Windows_x86_64.msi /qn
# Or use Chocolatey.
choco install pmg
```

You can also install with `npm install -g @safedep/pmg`. The npm package has no native Windows ARM64 binary. It does not work with an ARM64 build of Node.js. For a ZIP or npm install, run `pmg setup install` from your own terminal without elevation. An elevated terminal can run as a different account. Setup then configures the profile of that account. To protect all users, use the MSI.

CI steps do not reread the registry `PATH`. For a manual GitHub Actions setup, append the shim directory to the job `PATH` after setup. The change applies from the next step. In the current step, use the `pmg` prefix. The PMG GitHub Action supports Linux runners only.

```powershell
"$env:LOCALAPPDATA\safedep\pmg\bin" | Out-File -FilePath $env:GITHUB_PATH -Append -Encoding utf8
```

For a manual ZIP upgrade, keep `pmg.exe` at a stable path. Stop the running executable before you replace it in place. If you move it, run setup again from the new binary. The shims run the PMG path that setup recorded. Without a new setup, they run an old binary or fail with exit code 127. Use `pmg setup doctor` to check the result. MSI upgrades replace the binary in place. See [system installation](system-install.md).

To uninstall:

```powershell
pmg setup remove
```

This deletes the shims and the `PATH` entry. Per-user configuration and cache stay, as on macOS and Linux.

Add `--config-file` to also delete the per-user `config.yml`. Run `pmg setup remove` before you delete a manual `pmg.exe` or uninstall the npm package. If the binary is already gone, delete the per-user shim directory and its user `PATH` entry yourself. To remove machine shims, run `pmg setup remove --system` from an administrator terminal.

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

npm, npx, pnpm, pnpx, yarn, pip, pip3, pipx, poetry, uv, uvx and bun get a shim. Each one trusts PMG's ephemeral certificate authority through the environment variables PMG injects, so by default no certificate goes into the Windows certificate store. After `pmg setup cert install`, all managers can reuse that persisted CA.

PMG also writes aube, aubr and aubx shims, but aube is not part of the initial Windows version. See [safedep/pmg#457](https://github.com/safedep/pmg/issues/457).

Experimental `pmg go` and `pmg cargo` get no shim. Run them with the `pmg` prefix. On Windows, `pmg cargo` and any cargo nested in a guarded run skip certificate revocation checks. Go reads the OS trust store only, so run `pmg setup cert install` once before `pmg go get`. macOS has the same requirement. See [cert.md](./cert.md).

## How a shim starts the manager

When you type `npm install lodash`, the shell finds `npm.cmd` in the shim directory and runs it. `cmd.exe` and PowerShell both resolve it this way, through `PATH` and `PATHEXT`. The shim does two things:

1. It stores your argument text, unchanged, in the environment variable `PMG_RAW_ARGS`.
2. It runs `pmg npm` with the same arguments.

PMG then locates the real `npm`. On Windows that is `npm.cmd`, a batch file, and a batch file is not a program. PMG starts it through `cmd.exe` and passes it the text from `PMG_RAW_ARGS` as it is. PMG adds no quoting of its own. The real `npm` reads your arguments after one parse, the same as when you run it with no PMG. PMG's tests compare the two, argument by argument, in `cmd.exe` and in PowerShell.

`pmg npm install lodash` typed by hand takes a different route. PMG receives parsed arguments without the raw text. Go rebuilds a command line with standard Windows C-runtime quoting. `cmd.exe` parses it again with different rules, so the text has two parsing stages. The result is the same for normal arguments. For an argument that carries a quote or a caret, prefer the shim, where the text is parsed once.

`cmd.exe` expands `%NAME%` in the text before the real `npm` reads it. `%USERNAME%` is expanded before PMG sees it, so PMG passes the value, not the reference. A variable whose value itself contains `%NAME%` is expanded a second time.

## Limitations

A `PATH` shim does not intercept everything. `pmg setup doctor` reports the state on your machine rather than assuming it.

- **Current directory.** `cmd.exe` searches the current directory before `PATH`. A repository that holds its own `npm.cmd` runs that file, not the shim.
- **Programs that skip the shell.** A program that starts `npm` directly, with no shell, appends `.exe` only and never finds a `.cmd` shim. On a stock machine it finds no `npm` at all, so for npm this is missing coverage rather than a bypass. An IDE task that does not run through a shell behaves the same way. pip, pip3, pipx, uv, uvx, Bun and Poetry ship an `.exe`, so such a program runs them directly without PMG. Use `pmg <manager>` explicitly in scripts and IDE tasks.
- **Node.js from the MSI is not intercepted by a per-user install.** The nodejs.org installer, `winget install OpenJS.NodeJS` and Chocolatey put `C:\Program Files\nodejs` on the machine `PATH`. Windows builds a process `PATH` as the machine value, then the user value, so the per-user shim directory can never move ahead of it. On such a machine a bare `npm install` runs Node's own `npm`. `pmg setup install` and `pmg setup doctor` report this. Use a machine-wide install to fix this. Run `pmg setup install --system` from a terminal started as administrator. This puts administrator-owned shims first on the machine `PATH`. The binary must first be at `%ProgramFiles%\safedep\pmg\pmg.exe`, not through a symbolic link or junction. The MSI puts it there and runs the system setup. See [system-install.md](./system-install.md). Until then, run it as `pmg npm`. Do not put `%LOCALAPPDATA%\safedep\pmg\bin` on the machine `PATH` yourself. A user-writable directory there lets a standard user plant a binary that an elevated process runs.
- **User PATH.** A per-user installer can prepend its own directory. The python.org installer does. Run `pmg setup install` again: it moves the shim directory back to the front of the user `PATH`.
- **Shell profile.** `fnm env | Invoke-Expression` in `$PROFILE` prepends the directory that holds `npm`, and PMG cannot reorder a profile. Run it as `pmg npm`, or drop that line from the profile. `pmg setup install` and `pmg setup doctor` name each manager that resolves ahead of the shims and what to do.
- **Git Bash.** Git Bash does not apply `PATHEXT`, so it never runs a `.cmd` shim and resolves `npm` to Node's own `npm` shell script. Run `pmg npm ...` in Git Bash, or use PowerShell or `cmd.exe`.
- **Unquoted metacharacters.** The shim forwards your arguments to `cmd.exe`, which reads an unquoted `&`, `|`, `<` or `>` as its own. `npm.cmd` behaves the same way, so PMG changes nothing here. Quote the argument.
- **Interpreter entry points.** `python -m pip` and `py -m pip` do not invoke a pip shim. Use `pmg pip install ...`, or start a foreground proxy and [import its environment](#foreground-proxy). Starting a proxy alone does not route Python through it.
- **No sandbox.** Windows has no Landlock or Seatbelt equivalent that fits the current policy model. Keep `sandbox.enabled: false` in Windows fleet configuration. With it enabled, install commands stop with an error. See [sandbox.md](./sandbox.md).
- **No proxy daemon.** `pmg proxy start --daemon` needs a detached process, a liveness check and a stop path that Windows does not share with Unix. Use a foreground `pmg proxy start` and stop it with Ctrl+C. `pmg proxy stop`, `pmg proxy status` and the `--fail-on-violation` gate do not work on Windows. `pmg proxy stop` can remove the state of a running proxy and return an error. The proxy then continues to run. See [persistent-proxy.md](./persistent-proxy.md#commands).
- **WSL.** PMG under WSL 2 runs the Linux build. The sandbox works when the WSL kernel meets the Linux driver requirements. It protects package managers inside WSL only. A native Windows toolchain needs the Windows build. WSL 1 has no Linux kernel, so the sandbox does not work there. With the sandbox enabled, PMG stops with an error. Check with `pmg setup doctor`.

## Foreground proxy

To use a foreground proxy from another terminal, import its environment into that terminal. Run both terminals as the same user with the same `PMG_CACHE_DIR`, or give both commands the same `--state` file. `pmg proxy env --export` prints POSIX shell syntax. In PowerShell, import the plain `KEY=VALUE` output:

```powershell
pmg proxy env | ForEach-Object {
    $name, $value = $_ -split '=', 2
    [Environment]::SetEnvironmentVariable($name, $value, 'Process')
}
```
