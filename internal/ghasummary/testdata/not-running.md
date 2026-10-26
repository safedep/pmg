## PMG

**Failed.** No PMG proxy ran at the end of the job. A step stopped it or removed its state file, so the job has no verdict. When a step of the job stops PMG, set `auto-stop: false`.

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

Add the profile to CODEOWNERS, so that a security reviewer approves each change to it. Set `baseline: false` on the PMG step to leave this section out.
