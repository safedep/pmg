## PMG

**Failed.** 1 package(s) were blocked by the proxy and 2 connection(s) were denied by the network policy.

| Packages blocked | Network mode | Network profile | Destinations observed |
|---|---|---|---|
| 1 | enforce | `github-actions < /home/runner/work/app/app/.pmg/ci.yml` | 2 |

### Denied connections

| Destination | Rule | Program | Count |
|---|---|---|---|
| `pastebin.com:443` | `*:*` | node | 2 |

To allow a destination, add it to `network.allow_outbound` in `.pmg/ci.yml`.

### Observed destinations

| Destination | Program | Count | Proposal |
|---|---|---|---|
| `pastebin.com:443` | node | 3 | refused |

### Network profile

`.pmg/ci.yml` does not allow 1 destination(s) that this job tried to reach. PMG proposes no rule for them, because the job did not reach them. Add a rule by hand only when the job needs the destination.

