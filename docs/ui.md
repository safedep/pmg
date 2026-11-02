# User Interface

PMG has silent, normal, and verbose UI levels.
Normal is the default.
Use root flags before a package-manager name.
Flags after that name belong to the package manager.

```sh
pmg --verbose npm install express
pmg --silent npm install express
```

Set `verbosity` in [configuration](config.md) or use `PMG_VERBOSITY` for aliases and shims.
For example, `PMG_VERBOSITY=silent npm install express` selects the PMG level through a POSIX shell alias.
Lockdown can disable that environment override.
`--silent` and `--verbose` are mutually exclusive.
The local `pmg sandbox profile lint --verbose` flag adds info-level lint issues instead of changing global UI verbosity.

## Messaging

Use UI helpers for user decisions and results.
Use logs for diagnostic detail.
Child process output has its own rules and does not disappear in PMG silent mode.

### UI messages

| Message or report | Silent | Normal | Verbose |
| --- | --- | --- | --- |
| Status, info, success | Hidden | Shown | Shown |
| Fatal errors | Shown | Shown | Shown with help and underlying detail |
| `ShowWarning` warnings | Shown | Shown | Shown |
| Malware block and its advisory | Shown | Shown | Shown with package detail |
| Suspicious-package prompt on an interactive TTY | Shown | Shown | Shown |
| Cooldown-only, insecure-bypass, and network-policy execution reports | Hidden | Shown subject to outcome selection | Detailed |

This table describes the shared UI and report helpers.
Other commands can print directly.
Normal insecure reporting returns before cooldown detail, even though cooldown can still enforce.
Verbose output adds the execution report, flagged-package summaries, network decisions, and withheld cooldown versions.

A suspicious-package prompt defaults to refusal.
The helper accepts a trimmed case-insensitive answer beginning with `y`.
EOF, an empty answer, and other answers decline.
Direct noninteractive execution declines without a prompt.
Paranoid mode blocks suspicious verdicts instead of offering confirmation.
Silent mode alone does not disable an interactive prompt.
Verified malicious verdicts block without prompting, subject to [trust exceptions](trusted-packages.md).

Contributors should use the existing helper for the message category.

| Purpose | Helper and stream |
| --- | --- |
| Transient progress | `SetStatus`, `ClearStatus`, and spinner helpers. Silent suppresses them. |
| Information or success | `Infof`, `Successf`. These write stdout and honor silent mode. |
| Immediate warning | `ShowWarning`. This writes stderr in every UI level. |
| Fatal useful error | `ErrorExit` or `ErrorExitWithCode`. These write stderr and preserve parseable child stdout. |
| Child command exit | `ExitFromCommandError`. This preserves the command's exit semantics. |
| Suspicious confirmation | `GetConfirmationOnMalwareWithReader`. Supply the routed PTY reader where applicable. |
| Proxy result | Use the presenter in [proxy_presenter.go](../internal/ui/proxy_presenter.go) and `ui.Report`. |

Some reports and prompts write stdout.
Do not add unsolicited result output to a machine-readable command path.
Follow [error conventions](../CLAUDE.md#error-handling) and [development guidance](development.md).

Colors turn off for nonterminal output and with `TERM=dumb`.
Set `NO_COLOR=1` to request plain output explicitly.

### Logs

UI verbosity does not set diagnostic log levels.
Logs are hidden by default.
Use `--debug` for stdout debug logs or `--log <file>` for an info-level file sink.
Combine them for file debug detail.

```sh
pmg --debug npm install express
pmg --debug --log /tmp/pmg-debug.log npm install express
APP_LOG_LEVEL=debug APP_LOG_FILE=/tmp/pmg-debug.log pmg npm install express
```

The environment-only example writes a file.
Without `--debug`, PMG forces stdout logging off.
Using `--log` without `--debug` sets the level to info.
The root `--log` option also redirects audit events into that file.
It disables the default daily event-log directory for that process.
Profile proposal commands that read the daily directory cannot discover those redirected runs.
