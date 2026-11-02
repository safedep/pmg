# User Interface

PMG is an interactive tool. We support multiple interactivity modes such as `silent`, `verbose` etc. to meet different developer experience needs. As such, we need to standardize the UI, UX and interactive messaging guidance for developers.

Normal is the default UI level.
Use root flags before a package-manager name.
Flags after that name belong to the package manager.

```sh
pmg --verbose npm install express
pmg --silent npm install express
```

The verbosity level can be set per-invocation using `--silent` or `--verbose` CLI flags, or persisted via the `verbosity` option in the [configuration file](config.md).
Use `PMG_VERBOSITY` for aliases and shims.
For example, `PMG_VERBOSITY=silent npm install express` selects the PMG level through a POSIX shell alias.
`--silent` and `--verbose` are mutually exclusive.
The local `pmg sandbox profile lint --verbose` flag adds info-level lint issues instead of changing global UI verbosity.

## Messaging

Two types of messages to users are supported:

1. UI messages
2. Logs

Child process output has its own rules and does not disappear in PMG silent mode.

### UI messages

UI messages are displayed in the user interface, currently in the terminal. Following types of messages are supported:

1. **Status updates** - Meant for showing the stage or status of the workflow.
2. **Error messages** - Meant for showing fatal error messages

| Message or report | Silent | Normal | Verbose |
| --- | --- | --- | --- |
| Status, info, success | Hidden | Shown | Shown |
| Fatal errors | Shown | Shown | Shown with additional help and the original error |
| `ShowWarning` warnings | Shown | Shown | Shown |
| Malware block and its advisory | Shown | Shown | Shown with package detail |
| Suspicious-package prompt on an interactive TTY | Shown | Shown | Shown |
| Cooldown-only, insecure-bypass, and network-policy execution reports | Hidden | Shown when that outcome applies | Detailed |

This table describes the shared UI and report helpers.
Other commands can print directly.
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
Follow the [development guidance](development.md).

Colors turn off for nonterminal output and with `TERM=dumb`.
Set `NO_COLOR=1` to request plain output explicitly.

### Logs

Logs are by default for inspection and debugging purposes. They are not shown by default. Consider logs as something meant for use only when there is an unexpected behavior.
UI verbosity does not set diagnostic log levels.
Use `--debug` for stdout debug logs or `--log <file>` for an info-level file sink.
Combine them to write debug logs to the file and to stdout.

```sh
pmg --debug npm install express
pmg --debug --log /tmp/pmg-debug.log npm install express
APP_LOG_LEVEL=debug APP_LOG_FILE=/tmp/pmg-debug.log pmg npm install express
```

The `APP_LOG_*` example writes only to the file.
The root `--log` option also redirects event-log entries into that file.
It disables the default daily event-log directory for that process.
Profile proposal commands that read the daily directory cannot discover those redirected runs.
