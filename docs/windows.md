# Windows Support

Use `pmg setup install` on Windows to run `npm`, `pip` and the other supported package managers through PMG with no change to how you type.

```powershell
pmg setup install
```

**Requires Windows 10 or 11 on x86-64.** The release ships `windows_x86_64.zip` only. An ARM64 machine runs the amd64 build under emulation.

`pmg setup install` writes one `.cmd` shim for each supported package manager and puts the shim directory first on your user `PATH`. PMG installs no shell alias and no PowerShell profile function on Windows. The shims are the whole interception layer. `cmd.exe`, PowerShell and any program that applies `PATHEXT` find them.

Open a new terminal, then confirm with:

```powershell
Get-Command npm    # should resolve under %LOCALAPPDATA%\safedep\pmg\bin
pmg setup doctor
```

To uninstall:

```powershell
pmg setup remove
```

This deletes the shims and the `PATH` entry. Per-user configuration and cache stay, as on macOS and Linux.

## Files created

| Item                   | Path                                          |
| ---------------------- | --------------------------------------------- |
| Configuration          | `%APPDATA%\safedep\pmg\config.yml`            |
| Package-manager shims  | `%LOCALAPPDATA%\safedep\pmg\bin\<manager>.cmd` |
| PATH entry             | `HKCU\Environment`, user scope, prepended     |
| Event log, cache, data | `%LOCALAPPDATA%\safedep\pmg`                  |
| Managed configuration  | `%PROGRAMDATA%\safedep\pmg\config.yml`        |

The managed configuration file exists only when an administrator deploys one.

## Supported package managers

npm, npx, pnpm, pnpx, yarn, pip, pip3, pipx, poetry, uv, uvx, bun, aube, aubr and aubx get a shim. Each one trusts PMG's ephemeral certificate authority through the environment variables PMG injects, so no certificate goes into the Windows certificate store.

`pmg go` is the exception. Go reads the OS trust store only, so run `pmg setup cert install` once before `pmg go get`. macOS has the same requirement. See [cert.md](./cert.md).

## How a shim starts the manager

A Node manager installed through npm is a `.cmd` file. A batch file is not a program, so PMG starts it through `cmd.exe` and hands it the argument text exactly as the shim received it. PMG adds no quoting of its own. The manager sees the result of one parse, the same as when you run it with no PMG. PMG's own tests compare the two, argument by argument, in `cmd.exe` and in PowerShell.

`pmg npm install ...` typed by hand also works, and it takes a different route: the shell has already split your text into arguments, so PMG passes those to `cmd.exe` and your text is quoted twice. For an argument that carries a quote or a caret, prefer the shim, where it is quoted once.

An argument PMG replays can hold a variable reference. `%USERNAME%` is expanded before PMG sees it, so it is safe. A variable whose value itself contains `%..%` is expanded a second time.

## Limitations

A `PATH` shim does not intercept everything. `pmg setup doctor` reports the state on your machine rather than assuming it.

- **Current directory.** `cmd.exe` searches the current directory before `PATH`. A repository that holds its own `npm.cmd` runs that file, not the shim.
- **Programs that skip the shell.** A program that starts `npm` directly, with no shell, appends `.exe` only and never finds a `.cmd` shim. On a stock machine it finds no `npm` at all, so this is missing coverage rather than a bypass. An IDE task that does not run through a shell behaves the same way.
- **Machine PATH.** Windows builds a process `PATH` as the machine value, then the user value, so a user `PATH` entry can never move ahead of a machine one. `npm` from the Node.js MSI, under `C:\Program Files\nodejs`, is the common case. Run it as `pmg npm`, or move that directory behind `%LOCALAPPDATA%\safedep\pmg\bin` in the machine `PATH`, which needs an administrator.
- **User PATH.** A per-user installer can prepend its own directory. The python.org installer does. Run `pmg setup install` again: it moves the shim directory back to the front of the user `PATH`.
- **Shell profile.** `fnm env | Invoke-Expression` in `$PROFILE` prepends the directory that holds `npm`, and PMG cannot reorder a profile. Run it as `pmg npm`, or drop that line from the profile. `pmg setup install` and `pmg setup doctor` name each manager that resolves ahead of the shims, where it resolves, and what to do.
- **Git Bash.** Git Bash does not apply `PATHEXT`, so it never runs a `.cmd` shim and resolves `npm` to Node's own `npm` shell script. Run `pmg npm ...` in Git Bash, or use PowerShell or `cmd.exe`.
- **Unquoted metacharacters.** The shim forwards your arguments to `cmd.exe`, which reads an unquoted `&`, `|`, `<` or `>` as its own. `npm.cmd` behaves the same way, so PMG changes nothing here. Quote the argument.
- **No sandbox.** Windows has no Landlock or Seatbelt equivalent that fits the current policy model. See [sandbox.md](./sandbox.md).
- **No proxy daemon.** `pmg proxy start --daemon` needs a detached process, a liveness check and a stop path that Windows does not share with Unix. Foreground mode works. See [persistent-proxy.md](./persistent-proxy.md).
- **No system install.** `pmg setup install --system` needs an ownership check that PMG does not implement on Windows. See [system-install.md](./system-install.md).
- **No GitHub Action.** The PMG GitHub Action refuses every non-Linux runner.
- **WSL.** PMG under WSL runs the Linux build with every Linux capability, the sandbox included. It protects package managers inside WSL only. A native Windows toolchain needs the Windows build.
