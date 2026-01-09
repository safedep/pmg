# Trusted Packages

`pmg` allows you to trust a package. Trusted packages are not scanned and always allowed to be installed.

## Configuration

Trusted packages are configured in the `config.yml` file. See [config template](../config/config.template.yml) for the configuration schema.
If you don't have a `config.yml` file, you can create one by running `pmg setup install`.

### Example

```yaml
trusted_packages:
  - purl: pkg:npm/safedep/pmg
    reason: "All versions of PMG are trusted"
  - purl: pkg:npm/express@4.18.0
    reason: "Version 4.18.0 of Express is a trusted package"
```

