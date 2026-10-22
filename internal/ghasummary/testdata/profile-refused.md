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
| `gist.github.com:443` | curl | 3 | rule `gist.github.com:443` denies it |
| `bad host:443` | curl | 3 | not a valid rule |

### Network profile

`.pmg/ci.yml` refused 1 destination(s) that this job tried to reach. PMG proposes no rule for them, because the job did not reach them. Add a rule by hand only when the job needs the destination.

A deny rule in the profile chain of `.pmg/ci.yml` matches 1 destination(s). PMG keeps the deny rule, because a maintainer wrote it.

PMG cannot write a rule for 1 destination(s), because the name is not a valid host and port.

