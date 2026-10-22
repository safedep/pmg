## PMG

**Passed with violations.** 1 package(s) were blocked by the proxy and 2 connection(s) were denied by the network policy. `fail-on-violation` is off, so the job does not fail.

| Packages blocked | Network mode | Network profile | Destinations observed |
|---|---|---|---|
| 1 | enforce | `github-actions < /home/runner/work/app/app/.pmg/ci.yml` | 2 |

### Denied connections

| Destination | Rule | Program | Count |
|---|---|---|---|
| `pastebin.com:443` | `*:*` | node | 2 |

