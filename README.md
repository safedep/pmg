
# PMG (Package Manager Guard)

PMG is a security-focused wrapper for package managers that helps detect and prevent the installation of potentially malicious packages.


## 📑 Table of Contents
- [Features](#features)
- [Supported Ecosystems](#supported-ecosystems)
- [Installation](#installation)
- [Prerequisites](#prerequisites)
- [Configuration](#configuration)
- [Usage](#usage)
  - [NPM Packages](#npm-packages)
  - [PNPM Packages](#pnpm-packages)
  - [Common Flags](#common-flags)
- [Contributing](#contributing)

## Features
- 🚫 Malware detection and prevention
- 🌲 Deep dependency analysis
- ⚡ Fast and efficient package verification
- 🔄 Seamless integration with existing package managers

## Supported Ecosystems
Currently, PMG supports the following package ecosystems:

| Ecosystem | Status | Command |
|-----------|--------|---------|
| NPM       | ✅ Active | `pmg npm install <package>` |
| PNPM      | ✅ Active | `pmg pnpm add <package>` |
| PyPI      | 🚧 Planned | Coming soon |
| Go        | 🚧 Planned | Coming soon |

## Installation
- Build from source

> Ensure $(go env GOPATH)/bin is in your $PATH

```bash
go install github.com/safedep/pmg@latest
```

## Prerequisites
- Go 1.24
- SafeDep API credentials (SAFEDEP_API_KEY and SAFEDEP_TENANT_ID)

## Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `SAFEDEP_API_KEY` | Your SafeDep API key | Yes |
| `SAFEDEP_TENANT_ID` | Your SafeDep tenant ID | Yes |

Get your API credentials by visiting [SafeDep Quickstart Guide](https://docs.safedep.io/cloud/quickstart).

## Usage

### Security in Action

#### Malicious Package Detection
![pmg scan malicious package](./docs/assets/pmg-malicious-pkg.png)

#### Bulk Package Analysis
![pmg scan & install multiple package](./docs/assets/pmg-scan-multiple-pkgs.png)

### NPM Packages
Install a package:
```bash
pmg npm install <package-name>
```

Alternative commands:
```bash
pmg npm i <package-name>     # Short form
pmg npm add <package-name>   # Alternative syntax
```

### PNPM Packages
Install a package:
```bash
pmg pnpm add <package-name>
```

### Common Flags
All standard package manager flags are supported:
```bash
pmg npm install --save-dev <package-name>    # Install as dev dependency
pmg pnpm add -D <package-name>               # Install as dev dependency
```

## Contributing
Please feel free to submit a Pull Request.
