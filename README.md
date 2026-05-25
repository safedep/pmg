<div align="center">
    <h1>Package Manager Guard (PMG)</h1>
</div>

<p align="center">
    <strong>Block malicious npm and pip packages before they install.</strong><br>
    Defense in depth for the package managers you already use.
</p>

<div align="center">
  <img src="./docs/demo/pmg-intro.gif" width="800" alt="pmg in action">
</div>

<br>

<div align="center">

[![Docs](https://img.shields.io/badge/Docs-docs.safedep.io-2b9246?style=flat-square)](https://docs.safedep.io/pmg/quickstart)
[![Website](https://img.shields.io/badge/Website-safedep.io-3b82f6?style=flat-square)](https://safedep.io)
[![Discord](https://img.shields.io/discord/1090352019379851304?style=flat-square)](https://discord.gg/kAGEj25dCn)

[![Go Report Card](https://goreportcard.com/badge/github.com/safedep/pmg)](https://goreportcard.com/report/github.com/safedep/pmg)
![License](https://img.shields.io/github/license/safedep/pmg)
![Release](https://img.shields.io/github/v/release/safedep/pmg)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/safedep/pmg/badge)](https://api.securityscorecards.dev/projects/github.com/safedep/pmg)
[![CodeQL](https://github.com/safedep/pmg/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/safedep/pmg/actions/workflows/codeql.yml)

</div>

## Why PMG?

Developers and AI coding agents install packages every day. Each `npm install` or `pip install` executes thousands of lines of code that nobody reviews.

Recent compromises in popular ecosystems:

- [**Mini Shai-Hulud**](https://safedep.io/mini-shai-hulud-strikes-again-314-npm-packages-compromised/) - 300+ popular packages compromised
- [**litellm 1.82.8**](https://safedep.io/malicious-litellm-1-82-8-analysis/) - a popular AI proxy library compromised to exfiltrate credentials
- [**telnyx 4.87.2**](https://safedep.io/malicious-telnyx-pypi-compromise/) - a legitimate telecom SDK hijacked on PyPI
- [**pino-sdk-v2**](https://safedep.io/malicious-npm-package-pino-sdk-v2-env-exfiltration/) - a typosquat package disguised as the popular pino logger

PMG intercepts every package install and checks it for malware **before** code executes. Install it once, and PMG covers every `npm install`, `pip install`, and `poetry add` after that.

> Featured in [tl;dr sec](https://tldrsec.com/p/tldr-sec-316).

## How PMG Works

PMG takes a defense in depth approach. Each install passes through the enabled protection layers before code runs, plus an audit trail after.

- **Transparent Interception** - PMG wraps `npm`, `pip`, and other package managers. Developers and AI agents use the same commands. No workflow changes.
- **Layer 1: Threat Intelligence** - PMG checks every package against [SafeDep's real-time threat intelligence](https://safedep.io) before install. Known-malicious packages never reach disk.
- **Layer 2: Policy (Dependency Cooldown)** - PMG blocks package versions published inside a configurable cooldown window, so freshly compromised versions cannot land before the ecosystem has had time to flag them.
- **Layer 3: Optional Sandbox** - When sandboxing is enabled and configured, PMG runs installs inside OS-native sandboxes (macOS Seatbelt, Linux Landlock by default, or Bubblewrap fallback) so install scripts have restricted system access even if a threat slips past the first two layers.
- **Audit Logging** - PMG logs every install (what, when, from where) for a verifiable audit trail.

## Quick Start

### 1. Install

```bash
curl -fsSL https://raw.githubusercontent.com/safedep/pmg/main/install.sh | sh
```

> See [Installation](#installation) for Homebrew, npm, and other install methods.

### 2. Setup

Wire PMG into your shell so it intercepts package managers.

```bash
pmg setup install
# Restart your terminal to apply changes
```

> **Tip:** Re-run `pmg setup install` after upgrading PMG to pick up new configuration options.

Validate your installation and verify protection is working:

```bash
pmg setup doctor
```

### 3. Use

Run your package managers as usual, or let your AI coding agent run them. PMG sits in the path.

```bash
npm install express
# or
pip install requests
```

## Features

| Feature                  | Description                                                                                                  |
| ------------------------ | ------------------------------------------------------------------------------------------------------------ |
| **AI Agent Safety Net**  | Catches malicious packages installed by AI coding agents (Claude Code, Cursor, Copilot, Windsurf).           |
| **Dependency Cooldown**  | Blocks package versions published within a configurable time window, reducing exposure to supply chain attacks. |
| **Zero Config**          | Works out of the box with sensible security defaults.                                                        |
| **Cross-Shell**          | Integrates with Zsh, Bash, Fish, and more.                                                                   |

## Supported Package Managers

PMG supports the tools you already use:

| Ecosystem   | Tools    | Command Example     |
| ----------- | -------- | ------------------- |
| **Node.js** | `npm`    | `npm install <pkg>` |
|             | `pnpm`   | `pnpm add <pkg>`    |
|             | `yarn`   | `yarn add <pkg>`    |
|             | `bun`    | `bun add <pkg>`     |
|             | `npx`    | `npx <pkg>`         |
|             | `pnpx`   | `pnpx <pkg>`        |
| **Python**  | `pip`    | `pip install <pkg>` |
|             | `poetry` | `poetry add <pkg>`  |
|             | `uv`     | `uv add <pkg>`      |

## Installation

<details>
<summary><strong>Install Script (MacOS/Linux)</strong></summary>

Downloads the latest release from GitHub, verifies its SHA-256 checksum, and installs to `$HOME/.local/bin` (if on `PATH`) or `/usr/local/bin`.

```bash
curl -fsSL https://raw.githubusercontent.com/safedep/pmg/main/install.sh | sh
```

</details>

<details>
<summary><strong>Homebrew (MacOS/Linux)</strong></summary>

```bash
brew tap safedep/tap
brew install safedep/tap/pmg
```

</details>

<details>
<summary><strong>NPM (Cross-Platform)</strong></summary>

```bash
npm install -g @safedep/pmg
```

> **Note:** NPM-based installs can be fragile when Node.js is managed by version managers like [`mise`](https://mise.jdx.dev/) or [`asdf`](https://asdf-vm.com/). The global `npm` bin path changes with the active Node version, so switching versions can leave `pmg` unavailable on `PATH` (or pointing to an old install). For these setups, prefer the install script or Homebrew.

</details>

<details>
<summary><strong>Go (Build from Source)</strong></summary>

```bash
# Ensure $(go env GOPATH)/bin is in your $PATH
go install github.com/safedep/pmg@latest
```

</details>

<details>
<summary><strong>Binary Download</strong></summary>

Download the latest binary for your platform from the [Releases Page](https://github.com/safedep/pmg/releases).
</details>

## GitHub Actions

Protect CI workflows with one step. PMG analyzes every `npm install`,
`pip install`, etc. in the job.

```yaml
# Consider pinning third-party Actions to a full commit SHA
- uses: actions/setup-node@v6
  with:
    node-version: 24
- uses: safedep/pmg@v1
- run: npm ci
```

By default you get malware blocking and dependency cooldown. Sandbox isolation
is opt-in via the `sandbox` input. Tune behavior via inputs (`paranoid`,
`sandbox`, `cooldown-days`, ...) or point
`config-file` at a YAML in the repo. See
[docs/github-action.md](docs/github-action.md) for the full reference.

## Uninstallation

Remove shell integration:

```bash
pmg setup remove
```

To also remove the PMG configuration file:

```bash
pmg setup remove --config-file
```

Then uninstall PMG itself:

```bash
# Homebrew
brew uninstall safedep/tap/pmg

# NPM
npm uninstall -g @safedep/pmg
```

## Trust and Security

PMG builds are reproducible and signed.

- **Attestations**: GitHub and npm attestations guarantee artifact integrity.
- **Verification**: You can cryptographically prove the binary matches the source code.
- See [Trusting PMG](docs/trust.md) for verification steps.

## User Guide

- [Trusted Packages Configuration](docs/trusted-packages.md)
- [Dependency Cooldown](docs/dependency-cooldown.md)
- [Proxy Mode Architecture](docs/proxy-mode.md)
- [Sandboxing Details](docs/sandbox.md)

## Support

If PMG saved you from a bad package, [star this repo](https://github.com/safedep/pmg). It helps others find it.

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for build and test instructions.

## Telemetry

PMG collects anonymous usage data. To disable, either:

- Set `disable_telemetry: true` in your PMG config file, or
- Export `PMG_DISABLE_TELEMETRY=true`.
