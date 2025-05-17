# User Interface

PMG is an interactive tool. We support multiple interactivity modes such as `silent`, `verbose` etc. to meet different developer experience needs. As such, we need to standardize the UI, UX and interactive messaging guidance for developers.

## Messaging

Two types of messages to users are supported:

1. UI messages
2. Logs

### UI messages

UI messages are displayed in the user interface, currently in the terminal. Following types of messages are supported:

1. **Status updates** - Meant for showing the stage or status of the workflow.
2. **Error messages** - Meant for showing fatal error messages

| Type   | Mode    | Show? |
| ------ | ------- | ----- |
| Status | Silent  | No    |
| Status | Verbose | Yes   |
| Error  | Silent  | Yes   |
| Error  | Verbose | Yes   |

### Logs

Logs are by default for inspection and debugging purposes. They are not shown by default but can be configured through verbosity levels or logging to files. Consider logs as something meant for use only when there is an unexpected behavior.

