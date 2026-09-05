# Sandbox Exec

`pmg sandbox exec` runs any program inside the PMG sandbox. The program keeps its own stdin,
stdout, stderr and exit code. PMG blocks credential files, scrubs credential environment
variables, protects agent hook configuration and contains writes to the repository.

The first use is a coding agent. Claude Code, Codex and Pi run dozens of tool calls per session.
Under `pmg sandbox exec` every process the agent spawns runs under the same kernel policy.

```bash
pmg sandbox exec -- claude
pmg sandbox exec --sandbox-allow preset=codex -- codex
pmg sandbox exec -- make test
```

Flag parsing stops at the first non-flag argument, so the program's own flags pass through. Put
`--` before a program name that starts with a dash.

## What the exec profile enforces

The built-in `exec` profile is deliberately broad on read and exec. A coding agent reads the whole
toolchain and runs whatever the repository needs, so a narrow allow list only produces false
denials. The value is in the deny rules:

- The mandatory credential denies: `.env`, `.ssh`, `.aws`, `.gcloud`, `.kube`, `.gnupg`,
  `.netrc` and the rest of the list in [dangerous.go](../sandbox/util/dangerous.go).
- `.git/hooks` is never writable. `.git/config` is not writable.
- Credential environment variables are scrubbed, including model API keys such as
  `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` and `GEMINI_API_KEY`.
- Writes land only in the repository, temp directories, tool caches and the state directories the
  presets add.
- System directories are read-only.
- Agent hook configuration is read-only: `~/.claude/settings.json`, `~/.claude/hooks`,
  `~/.cursor/hooks.json`, `~/.codex/hooks.json`, `~/.gemini/settings.json`, and the equivalent
  files for Devin, OpenCode, Windsurf and Pi. A hook runs an arbitrary command on every tool call,
  so a write here is code execution and a way to unhook an agent security layer such as
  [Gryph](https://github.com/safedep/gryph).
- Gryph's policy files and receipt keys and PMG's own config and sandbox definitions are
  read-only. A sandboxed agent cannot loosen the sandbox for its next run.

Network is not filtered. The current drivers cannot filter outbound traffic per host, and an
agent needs its model API. Use a custom profile with `network_via_proxy_only` for egress control.

Show the full profile with `pmg sandbox profile show exec`.

## Agent presets

A preset adds the footprint of one agent: its state directory and its own API key. Deny rules win
over a preset allow, so the hook configuration stays read-only.

| Preset   | Writes                             | Re-allows                                          |
| -------- | ---------------------------------- | -------------------------------------------------- |
| `claude` | `~/.claude/**`, `~/.claude.json`   | `ANTHROPIC_API_KEY`                                |
| `codex`  | `~/.codex/**`                      | `OPENAI_API_KEY`                                   |
| `pi`     | `~/.pi/**`                         | `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY` |

Apply a preset for one run, or save it for the current repository:

```bash
pmg sandbox exec --sandbox-allow preset=claude -- claude
pmg sandbox allow preset=claude && pmg sandbox exec -- claude
```

Each preset file states the residual risk of each allowance. Read it with
`pmg sandbox preset show claude`. The accepted trade-off is the same as `NPM_TOKEN` in the npm
profile: the agent's own key is visible to every process the agent spawns. An OAuth login does
not need the key at all.

## When something is denied

The program sees a plain permission error. Run `pmg sandbox explain --last` after the run to see
what was denied and the `pmg sandbox allow` command that opts out of it. Saved allowances live in
the per-repository overlay. See [sandbox.md](./sandbox.md#project-overlays).

A tool that must edit its own settings file while sandboxed needs an exact-match opt-out:

```bash
pmg sandbox allow write=$HOME/.claude/settings.json
```

## Custom profiles

A custom profile must list the `exec` workload:

```yaml
name: exec-tight
inherits: exec
package_managers: [exec]
presets: [claude]
filesystem:
  deny_write:
    - ${CWD}/infra/**
```

```bash
pmg sandbox exec --sandbox-profile exec-tight -- claude
```

Or map the workload to the profile in the PMG config:

```yaml
sandbox:
  policies:
    exec:
      enabled: true
      profile: exec-tight
```

`pmg sandbox exec` fails when the exec policy is missing or disabled. It never runs a program
without a sandbox. It turns the sandbox on for the run even when `sandbox.enabled` is false in the
config file.

## Package managers inside the sandbox

PMG strips its own shim directories from the child's `PATH`. An `npm install` the agent runs
inside `pmg sandbox exec` reaches the real npm, not the PMG proxy. Malware analysis and dependency
cooldown do not apply to it. The sandbox still applies.

## Limits

- Windows is not supported. The sandbox drivers are macOS Seatbelt and Linux Landlock or
  Bubblewrap.
- Network is allow-all. See above.
- The exec profile grants exec access under `${HOME}`. `pmg sandbox profile lint exec` reports
  this as a warning on purpose.
