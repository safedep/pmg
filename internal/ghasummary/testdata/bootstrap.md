## PMG

**Passed.** PMG blocked no package and denied no connection.

| Packages blocked | Network mode | Network profile | Destinations observed |
|---|---|---|---|
| 0 | off | `none` | 2 |

### Observed destinations

| Destination | Program | Count | Proposal |
|---|---|---|---|
| `registry.npmjs.org:443` | node | 3 | parent rule `registry.npmjs.org:443` allows it |
| `api.example.com:443` | curl | 3 | add `api.example.com:443` |

### Network profile

PMG proposes a network profile from the 2 destination(s) this job reached. Review each rule. Save the file as `.pmg/network.yml` and commit it. Then set `network-profile: .pmg/network.yml` on the PMG step. Later runs report each destination the profile does not name. Set `network-mode: enforce` to refuse them.

<details><summary>Proposed `.pmg/network.yml`</summary>

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
