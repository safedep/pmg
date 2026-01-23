<div align="center">
    <img src="./docs/assets/pmg-banner.png" width="900" alt="PMG GitHub Banner">
</div>
<br/>

<div align="center">
    <h1>Package Manager Guard (PMG)</h1>
</div>

<div align="center">

<a href="https://docs.safedep.io/pmg/quickstart"><img src="https://img.shields.io/badge/Docs-docs.safedep.io-2b9246?style=for-the-badge&logo=gitbook&logoColor=white" alt="Docs"></a>
<a href="https://safedep.io"><img src="https://img.shields.io/badge/Website-safedep.io-3b82f6?style=for-the-badge&logoColor=white" alt="Website"></a>

<a href="https://discord.gg/kAGEj25dCn"><img src="https://img.shields.io/discord/1090352019379851304?style=for-the-badge&logo=discord&logoColor=white&color=5865F2" alt="Discord"></a>


[![Go Report Card](https://goreportcard.com/badge/github.com/safedep/pmg)](https://goreportcard.com/report/github.com/safedep/pmg)
![License](https://img.shields.io/github/license/safedep/pmg)
![Release](https://img.shields.io/github/v/release/safedep/pmg)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/safedep/pmg/badge)](https://api.securityscorecards.dev/projects/github.com/safedep/pmg)
[![CodeQL](https://github.com/safedep/pmg/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/safedep/pmg/actions/workflows/codeql.yml)

</div>

---

<div align="center">
<h3>PMG protects developers from getting compromised by malicious packages.
See <a href="https://safedep.io/malicious-npm-package-express-cookie-parser/">example</a></h3>
</div>

---

<img src="./docs/demo/pmg-intro.gif" width="800" alt="pmg in action">

## Key Features

- Wraps your favorite package manager (eg. `npm`, `pnpm`, `pip` and more)
- Blocks malicious packages at install time
- No configuration required, just install and use
- Maintains package installation event log for transparency and audit trail
- Enforces least privilege and defense in depth using OS native sandboxing

PMG guarantees its own artifact integrity using GitHub and npm attestations. Users can cryptographically prove that the binary they run
matches the source code they reviewed, eliminating the risk of tampered or malicious builds. See [why and how to trust PMG](docs/trust.md).

## Quick Start

Install `pmg` using your favorite package manager:

```shell
# MacOS/Linux with Homebrew
brew install safedep/tap/pmg

# Other platforms
npm install -g @safedep/pmg
```

**Note**: More [installation options](#installation) are available. See [why and how to trust PMG](docs/trust.md).

Set up `pmg` to protect your development environment from malicious packages:

```
pmg setup install
```

> **Note:** Make sure to restart your terminal or source your shell's config file.

Continue using your favorite package manager as usual:

```shell
npm install <package-name>
```

```shell
uv pip install <package-name>
```

## Features

- Malicious package identification using [SafeDep Cloud](https://docs.safedep.io/cloud/malware-analysis) with realtime threat detection
- Deep dependency analysis and transitive dependency resolution
- Fast and efficient package verification
- Defense in depth using OS native sandboxing
- Seamless integration with existing package managers
- Automated shell integration with cross-shell support
- Package installation tracking and event logging

## Supported Package Managers

PMG supports the following package managers:

| Package Manager | Status | Command                                                  |
| --------------- | ------ | -------------------------------------------------------- |
| `npm`           | ✅      | `pmg npm install <package>`                              |
| `pnpm`          | ✅      | `pmg pnpm add <package>`                                 |
| `bun`           | ✅      | `pmg bun add <package>`                                  |
| `yarn`          | ✅      | `pmg yarn add <package>`                                 |
| `pip`           | ✅      | `pmg pip install <package>`                              |
| `uv`            | ✅      | `pmg uv add <package>` or `pmg uv pip install <package>` |
| `poetry`        | ✅      | `pmg poetry add <package>`                               |
| `npx`           | ✅      | `pmg npx <package> <action>`                             |
| `pnpx`          | ✅      | `pmg pnpx <package> <action>`                            |

> Want us to support your favorite package manager? [Open an issue](https://github.com/safedep/pmg/issues) and let us know!

## Installation

### Homebrew

You can install `pmg` using `homebrew` in MacOS and Linux

```bash
brew tap safedep/tap
brew install safedep/tap/pmg
```

### Binaries

Download the latest binary from the [releases page](https://github.com/safedep/pmg/releases).

### Build from Source

> Ensure $(go env GOPATH)/bin is in your $PATH

```bash
go install github.com/safedep/pmg@latest
```

## Setup

PMG provides built-in commands to automatically configure shell aliases for seamless integration:

### Install Aliases

Set up PMG to intercept package manager commands:

```bash
pmg setup install
```

<details>
<summary>Custom config directory</summary>

```bash
PMG_CONFIG_DIR=/path/to/config pmg setup install
```
</details>

The setup command will:

- Create a `~/.pmg.rc` file containing package manager aliases
- Automatically add a source line to your shell configuration files
- Create a default config file. See [config template](config/config.template.yml)

> **Note**: After running `pmg setup install`, restart your terminal or run `source ~/.zshrc` (or your shell's config file) to activate the aliases.

### Remove Aliases

To remove PMG aliases and restore original package manager behavior:

```bash
pmg setup remove
```

This will:

- Remove the source line from your shell configuration files
- Delete the `~/.pmg.rc` file

> ⚠️ Note: Aliases might still be active in your **current terminal session**. Restart your terminal or use `unalias <cmd>` to remove them instantly.

## Usage

<details>
<summary>Active Scanning</summary>

Use the `--paranoid` flag to perform active malware scanning on unknown packages (requires [SafeDep Cloud credentials](https://docs.safedep.io/cloud/authentication#api-key-authentication)):

```bash
pmg --paranoid npm install <package-name>
```

</details>

<details>
<summary>Silent Mode</summary>

Use the `--silent` flag to run PMG in silent mode:

```bash
pmg --silent npm install <package-name>
```

</details>

<details>
<summary>Dry Run</summary>

Use the `--dry-run` flag to skip actual package installation. When enabled `pmg` will not execute
package manager commands. Useful for checking packages and their transitive dependencies for malware.

```bash
pmg --dry-run npm install <package-name>
```

</details>

<details>
<summary>Verbose Mode</summary>

Use the `--verbose` flag to run PMG in verbose mode:

```bash
pmg --verbose npm install <package-name>
```

</details>

<details>
<summary>Debugging</summary>

Use the `--debug` flag to enable debug mode:

```bash
pmg --debug npm install <package-name>
```

Store the debug logs in a file:

```bash
pmg --debug --log /tmp/debug.json npm install <package-name>
```

</details>

<details>
<summary>Insecure Installation</summary>

Allows bypassing the blocking behavior when malicious packages are detected during installation.

> ⚠️ **Warning**: This is a security feature bypass. Use with extreme caution and only when you understand the risks.

```bash
export PMG_INSECURE_INSTALLATION=true
pmg npm install <package-name>
```

</details>

## Advanced

- [Trusted Packages](docs/trusted-packages.md)
- [Proxy Mode](docs/proxy-mode.md)
- [Sandbox](docs/sandbox.md)

## Contributing

Refer to [CONTRIBUTING.md](CONTRIBUTING.md)

## Limitations

<details>
<summary>Approximate dependency version resolution</summary>

`pmg` resolves the transitive dependencies of a package to be installed. It does it by querying
package registry APIs such as `npmjs` and `pypi`. However, almost always, dependency versions are
specified as ranges instead of specific version. Different package managers have different ways of
resolving these ranges. It also depends on peer or host dependencies already available in the application.

`pmg` is required to block a malicious package _before_ it is installed. Hence it applies its own heuristic
to choose a version from a version range for evaluation. This is fine when all versions of a given package
is malicious. However, there is a possibility of inconsistency when a specific version of a package is malicious.

</details>

<details>
<summary>PyPI registry scanning only</summary>

`pmg` only scans packages available in the PyPI registry when using any python package manager. Packages installed from
alternative sources such as Git URLs, local file paths, or private registries are not analyzed for
malware detection. This limitation applies to direct installations and transitive dependencies sourced
from non-PyPI locations.

</details>

## Telemetry

`pmg` collects anonymous telemetry to help us understand how it is used and
improve the product. To disable telemetry, set `PMG_DISABLE_TELEMETRY` environment
variable to `true`.

```bash
export PMG_DISABLE_TELEMETRY=true
```
