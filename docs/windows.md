# Windows

PMG supports Windows 10 and 11 on x86-64. `pmg setup install` writes one `.cmd` shim for each supported package manager and puts the shim directory first on your user PATH. A new terminal then runs `npm install` through PMG with no change to how you type.

```powershell
pmg setup install
# open a new terminal
npm install lodash
pmg setup doctor
```

## What PMG installs

| Item | Path |
| --- | --- |
| Configuration | `%APPDATA%\safedep\pmg\config.yml` |
| Package-manager shims | `%LOCALAPPDATA%\safedep\pmg\bin\<manager>.cmd` |
| PATH entry | `HKCU\Environment`, user scope, prepended |
| Event log, cache, data | `%LOCALAPPDATA%\safedep\pmg` |
| Managed configuration, when an administrator deploys one | `%PROGRAMDATA%\safedep\pmg\config.yml` |

PMG installs no shell alias and no PowerShell profile function on Windows. The shims are the whole interception layer. `cmd.exe`, PowerShell and any program that applies `PATHEXT` find them.

`pmg setup remove` deletes the shims and the PATH entry. Per-user configuration and cache stay, as on macOS and Linux.

## Supported package managers

npm, npx, pnpm, pnpx, yarn, pip, pip3, pipx, poetry, uv, uvx, bun, aube, aubr and aubx get a shim. Each one trusts PMG's ephemeral certificate authority through the environment variables PMG injects, so no certificate goes into the Windows certificate store.

`pmg go` is the exception. Go reads the OS trust store only, so run `pmg setup cert install` once before `pmg go get`. macOS has the same requirement.

## How a shim starts the manager

A Node manager installed through npm is a `.cmd` file. A batch file is not a program, so PMG starts it through `cmd.exe` and hands it the argument text exactly as the shim received it. PMG adds no quoting of its own. The manager sees the result of one parse, the same as when you run it with no PMG. PMG's own tests compare the two, argument by argument, in `cmd.exe` and in PowerShell.

`pmg npm install ...` typed by hand also works, and it takes a different route: the shell has already split your text into arguments, so PMG passes those to `cmd.exe` and your text is quoted twice. For an argument that carries a quote or a caret, prefer the shim, where it is quoted once.

An argument PMG replays can hold a variable reference. `%USERNAME%` is expanded before PMG sees it, so it is safe. A variable whose value itself contains `%..%` is expanded a second time.

## Coverage limits

A PATH shim does not intercept everything. `pmg setup doctor` reports the state on your machine rather than assuming it.

| Limit | Effect |
| --- | --- |
| `cmd.exe` searches the current directory before PATH | A repository that holds its own `npm.cmd` runs that file, not the shim |
| A program that starts `npm` directly, with no shell, appends `.exe` only | It never finds a `.cmd` shim. On a stock machine it finds no `npm` at all, so this is missing coverage rather than a bypass |
| An IDE task does not always run through a shell | Same as the row above |
| A directory ahead of the shims on PATH | A manager in a directory that PATH names before the shim directory resolves first, and PMG does not see it. `pmg setup install` and `pmg setup doctor` name each manager, where it resolves, and what to do. The action depends on where that directory came from, so the next three rows give each one |
| The machine PATH sits ahead of the user PATH | Windows builds a process PATH as the machine value, then the user value, so a user PATH entry can never move ahead of a machine one. `npm` from the Node.js MSI, under `C:\Program Files\nodejs`, is the common case. Run it as `pmg npm`, or move that directory behind `%LOCALAPPDATA%\safedep\pmg\bin` in the machine PATH, which needs an administrator |
| A user PATH entry ahead of the shims | A per-user installer can prepend its own directory. The python.org installer does. Run `pmg setup install` again: it moves the shim directory back to the front of the user PATH |
| A shell profile adds a directory | `fnm env \| Invoke-Expression` in `$PROFILE` prepends the directory that holds `npm`, and PMG cannot reorder a profile. Run it as `pmg npm`, or drop that line from the profile |
| Git Bash resolves `npm` to Node's own `npm` shell script | Git Bash does not apply `PATHEXT`, so it never runs a `.cmd` shim. Run `pmg npm ...` in Git Bash, or use PowerShell or `cmd.exe` |
| An argument with an unquoted `&`, `\|`, `<` or `>` splits the line | The shim forwards your arguments to `cmd.exe`, which reads those characters as its own. `npm.cmd` behaves the same way, so PMG changes nothing here. Quote the argument |

## Not supported on Windows

| Feature | Reason |
| --- | --- |
| Sandbox | Windows has no Landlock or Seatbelt equivalent that fits the current policy model |
| `pmg proxy start --daemon` | The daemon needs a detached process, a liveness check and a stop path that Windows does not share with Unix |
| `pmg setup install --system` | Machine-scope shims need an ownership check that PMG does not implement on Windows |
| The PMG GitHub Action on a Windows runner | The action refuses every non-Linux runner |

## WSL

PMG under WSL runs the Linux build with every Linux capability, the sandbox included. It protects package managers inside WSL only. A native Windows toolchain needs the Windows build.

## ARM64

The release holds `windows_x86_64.zip` only. An ARM64 machine runs the amd64 build under emulation.
