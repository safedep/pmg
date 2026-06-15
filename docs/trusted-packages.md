# Trusted Packages

`pmg` allows you to trust a package. A trusted package bypasses **every**
control PMG enforces: it is not scanned for malware, it is exempt from the
[dependency cooldown](dependency-cooldown.md) window, and it will be exempted
from any future controls PMG adds. Use this list for packages you fully vouch
for — typically first-party packages or vendored internal dependencies.

If you only want to waive a single control (for example, install a package
immediately without waiting out the cooldown, but still have it analyzed for
malware), use the per-control skip list for that control instead — e.g.
[`dependency_cooldown.skip`](dependency-cooldown.md#exempting-specific-packages).

## Configuration

Trusted packages are configured in the `config.yml` file. See [config template](../config/config.template.yml) for the configuration schema.
If you don't have a `config.yml` file, you can create one by running `pmg setup install`.

### Example

```yaml
trusted_packages:
  - purl: pkg:npm/@safedep/pmg
    reason: "All versions of PMG are trusted"
  - purl: pkg:npm/express@4.18.0
    reason: "Version 4.18.0 of Express is a trusted package"
```
