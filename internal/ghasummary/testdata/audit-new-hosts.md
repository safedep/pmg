## PMG

**Passed.** PMG blocked no package and denied no connection.

| Packages blocked | Network mode | Network profile | Destinations observed |
|---|---|---|---|
| 0 | audit | `github-actions < ci` | 2 |

### Connections the profile would deny

| Destination | Rule | Program | Count |
|---|---|---|---|
| `api.example.com:443` | `*:*` | curl | 1 |

To allow a destination, add it to `network.allow_outbound` in `.pmg/ci.yml`.

### Observed destinations

| Destination | Program | Count | Proposal |
|---|---|---|---|
| `registry.npmjs.org:443` | node | 3 | parent rule `registry.npmjs.org:443` allows it |
| `api.example.com:443` | curl | 3 | add `api.example.com:443` |
| `pastebin.com:443` | curl | 3 | refused |

### Network profile

`.pmg/ci.yml` refused 1 destination(s) that this job tried to reach. PMG proposes no rule for them, because the job did not reach them. Add a rule by hand only when the job needs the destination.

This job reached 2 destination(s) that `.pmg/ci.yml` does not allow. Review each one before you add it:

- `api.example.com:443`
- `cdn.example.com:443`

<details><summary>Proposed `.pmg/ci.yml`</summary>

```yaml
name: network
inherits: github-actions

network:
  allow_outbound:
    - api.example.com:443
  deny_outbound:
    - "*:*"
```

</details>

Add the profile to CODEOWNERS, so that a security reviewer approves each change to it.
