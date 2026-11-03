# Trusting PMG

PMG exists to protect developers from malicious open source packages. This effectively means:

1. Open source packages are not *implicitly* trusted
2. PMG needs to be trusted to block malicious packages

The assertion in [2] cannot be *implicit*. If so, it breaks the entire security and trust model.

## Security Goals

- Adopt software supply chain security best practices so that PMG users can *verify* and only then trust PMG
- PMG is open source, built in public and reviewed by the community for verifiable source of truth
- Publish GitHub provenance for checksum-listed release archives and MSI assets
- Publish npm provenance for the launcher and platform packages
- Develop multiple security layers to reduce dependence on any one control

GitHub and npm attestations describe build provenance.
They do not replace OS code signing.
The current release pipeline has no Apple Developer ID, notarization, or Authenticode signing step.
The Homebrew cask removes quarantine on macOS.

## Verified Installation

Zero-friction installation options are available in [README](../README.md). However, for more control, you can install PMG manually
after verifying the integrity of the PMG binary. Verified installations allow you to:

- Verify the integrity of the PMG binary and identify the exact source code that was used to build the binary
- Manually review the source code for trust
- Build your own binary from source or download a pre-built archive with verified source provenance

Installation channels have different verification properties.

| Channel | Verification behavior |
| --- | --- |
| Manual GitHub archive or MSI | The release workflow publishes build provenance. Verify the downloaded asset before extraction or installation. |
| `install.sh` or GitHub Action | The installer checks the archive checksum from the same release over TLS. It does not perform GitHub provenance verification. |
| npm | The publish workflow requests provenance. Use `npm audit signatures` explicitly to verify installed local dependencies. |
| Homebrew, mise, Chocolatey, or winget | Follow that channel's verification rules. A channel install is not evidence that the GitHub provenance command below ran. |
| GHCR image | Buildx adds minimal registry provenance by default. The current container workflow has no GitHub artifact-attestation or explicit signing step. |
| Source build | Review the source and build settings. Provenance verification does not establish byte-for-byte reproducibility. |

The container `latest` tag also moves on main-branch pushes.
Pin a reviewed image digest when you need a stable image identity.
See [Docker build attestations](https://docs.docker.com/build/metadata/attestations/) for the registry provenance format.

For a local source build on Linux, disable cgo as the release build does.

```sh
CGO_ENABLED=0 go build -o ./bin/pmg ./main.go
```

### GitHub Release

`gh release verify` verifies a GitHub release attestation and prints asset digests.
It does not download or install the assets.
This release attestation is distinct from build provenance.

```sh
gh release verify -R safedep/pmg
```

Select a release and download only the asset for your platform.
This example uses Linux x86-64.

```sh
RELEASE_TAG=$(gh release view -R safedep/pmg --json tagName --jq .tagName)
gh release download "$RELEASE_TAG" -R safedep/pmg \
  -p pmg_Linux_x86_64.tar.gz --dir "./pmg-$RELEASE_TAG"
gh attestation verify "./pmg-$RELEASE_TAG/pmg_Linux_x86_64.tar.gz" \
  -R safedep/pmg --signer-workflow safedep/pmg/.github/workflows/goreleaser.yml \
  --source-ref "refs/tags/$RELEASE_TAG" --format json > "./pmg-$RELEASE_TAG/attestation.json"
```

To verify an edge release, set `RELEASE_TAG` to its edge tag.
PMG does not publish edge tags to npm or as container image tags.

Review the verified attestation's source commit and signer workflow.
Check out that exact commit before you review or rebuild the source.

```sh
SOURCE_COMMIT=$(jq -r '.[0].verificationResult.signature.certificate.sourceRepositoryDigest' \
  "./pmg-$RELEASE_TAG/attestation.json")
gh repo clone safedep/pmg
git -C pmg checkout "$SOURCE_COMMIT"
```

A tag checkout alone does not bind the reviewed tree to the attestation.
You can add `--source-digest <reviewed-commit>` to require that commit during verification.
See the [GitHub CLI options](https://cli.github.com/manual/gh_attestation_verify).
Install only after verification succeeds.
The attested subject is the archive or MSI, not a separate extracted binary.

Other assets are `pmg_Linux_arm64.tar.gz`, the universal `pmg_Darwin_all.tar.gz`, `pmg_Windows_x86_64.zip`, and `pmg_Windows_x86_64.msi`.
Use the actual downloaded path for each verification command.

### npm Release

`@safedep/pmg` is a launcher.
An optional platform package contains the executable.
Check both package layers.

```sh
npm view @safedep/pmg dist.attestations _npmUser
npm view @safedep/pmg-linux-x64 dist.attestations _npmUser
```

Other suffixes are `linux-arm64`, `darwin-x64`, `darwin-arm64`, and `win32-x64`.
These commands inspect registry metadata without verifying it cryptographically.
The provenance predicate type should identify `https://slsa.dev/provenance/v1`.
The publisher metadata can identify `GitHub Actions`.

For a cryptographic check, use an empty scratch project and review the result for the launcher and installed platform dependency.

```sh
pmg_verify_dir=$(mktemp -d)
cd "$pmg_verify_dir"
npm init -y
npm install --ignore-scripts @safedep/pmg
npm audit signatures
```

[`npm audit signatures`](https://docs.npmjs.com/cli/v11/commands/npm-audit/#audit-signatures) checks registry signatures and published provenance.
It does not support global installs.

Navigate to the [npm package](https://www.npmjs.com/package/@safedep/pmg) to inspect its published provenance.

## Security Model

PMG aims to provide a multi-layered security model to avoid single point of trust or failure. PMG's security
model consists of the following layers:

1. Threat intelligence provides malware verdicts.
2. Dependency cooldown applies a default 2-day age window. CEL policy guardrails are planned.
3. The experimental sandbox provides opt-in containment on macOS and Linux. It is disabled by default. See [sandboxing](sandbox.md) for its enforcement scope and platform limits.

PMG currently uses SafeDep as its threat intelligence source.
When the analyzer fails, PMG allows the artifact through the malware check.
Paranoid mode changes suspicious verdict handling but does not turn analyzer errors into blocks.
Other controls can still reject the request.
See [analysis behavior](proxy-mode.md#how-pmg-identifies-a-package).

Use [SECURITY.md](../SECURITY.md) to report a vulnerability.

## Certificate Authority

PMG uses a MITM CA to inspect HTTPS package downloads. See [Certificate Authority](cert.md)
for how it works and how to persist and OS-trust the CA.
Go on macOS and Windows requires it.
The enforcing Linux proxy also requires a root-owned system CA.
