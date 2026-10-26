## PMG

**Failed.** 1 package(s) were blocked by the proxy and 2 connection(s) were denied by the network policy.

| Packages blocked | Network mode | Network profile | Destinations observed |
|---|---|---|---|
| 1 | enforce | `github-actions < /home/runner/work/app/app/.pmg/ci.yml` | 2 |

### Denied connections

| Destination | Rule | Program | Count |
|---|---|---|---|
| `pastebin.com:443` | `*:*` | node | 2 |

`github-actions` is a built-in profile. To allow a destination, make a profile file that inherits `github-actions`, add the destination to its `network.allow_outbound`, and set `network-profile` to the file.

