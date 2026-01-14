# Trust

PMG exists to protect developers from malicious open source packages. This effectively means:

1. Open source packages are not *implicitly* trusted
2. PMG need to be trusted to block malicious packages

The assertion in [2] cannot be *implicit*. If so, it breaks the entire security and trust model. 

## Security Goals

- Adopt software supply chain security best practices so that PMG users can *verify* and only then trust PMG
- PMG is open source, built in public and reviewed by the community for trust in code
- PMG leverages GitHub build attestation to verify the integrity of the PMG binary with source provenance
- PMG npm package has build attestation to verify the integrity of the PMG binary and build environment with source provenance
- PMG security model is multi-layered without single point of failure

## Verified Installation

Zero-friction installation options are available in [README](../README.md). However, for more control, you can install PMG manually
after verifying the integrity of the PMG binary. Verified installations allow you to:

- Verify the integrity of the PMG binary and identify the exact source code that was used to build the binary
- Manually review the source code for trust
- Build your own binary from source or download a pre-built binary with source provenance guarantee

### GitHub Release

Get the latest attested version of PMG release binaries using GitHub CLI:

```bash
gh release verify -R safedep/pmg
```

Optionally, you can checkout the source code from which the binary was built and review the code for trust.

```bash
export RELEASE_TAG=$(gh release view -R safedep/pmg --json tagName --jq .tagName)

gh repo clone safedep/pmg && \
cd pmg && \
git checkout $RELEASE_TAG
```

Install verified binary for your platform:

```bash
gh release download $RELEASE_TAG -R safedep/pmg --dir ./pmg-$RELEASE_TAG 
```

Install the platform specific binary from `./$pmg-$RELEASE_TAG`. To see binary specific attestation metadata, run:

```bash
gh attestation verify pmg_Linux_x86_64.tar.gz -R safedep/pmg --format json
```

### npm Release

Verify npm package was built on GitHub Actions:

```bash
npm view @safedep/pmg --json
```

Navigate to [npm package](https://www.npmjs.com/package/@safedep/pmg) to verify the package provenance.

## Security Model

PMG aims to provide a multi-layered security model to avoid single point of trust or failure. PMG's security
model consists of the following layers:

1. Threat Intelligence (provided by [SafeDep](https://safedep.io) with planned support for BYO adapters)
2. Policy as Code (Planned CEL policy based guardrails to prevent known bad practices)
3. Sandbox for enforcing least privilege and defense in depth protection

