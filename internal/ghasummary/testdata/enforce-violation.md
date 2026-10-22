## PMG

**Failed.** 1 package(s) were blocked by the proxy and 2 connection(s) were denied by the network policy.

| Packages blocked | Network mode | Network profile | Destinations observed |
|---|---|---|---|
| 1 | enforce | `github-actions < ci` | 2 |

### Denied connections

| Destination | Rule | Program | Count |
|---|---|---|---|
| `pastebin.com:443` | `*:*` | node | 2 |

To allow a destination, add it to `network.allow_outbound` in `.pmg/ci.yml`.

