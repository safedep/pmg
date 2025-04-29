
# PMG (Package Manager Guard)

PMG is a security-focused wrapper for package managers that helps detect and prevent the installation of potentially malicious packages.


## 📑 Table of Contents
- [Supported Ecosystems](#supported-ecosystems)
- [Installation](#installation)
- [Prerequisites](#prerequisites)
- [Environment Variables](#environment-variables)
- [Usage](#usage)
- [Contributing](#contributing)


## Supported Ecosystems
Currently, PMG supports the following package ecosystems:

| Ecosystem | Status | Command |
|-----------|--------|---------|
| NPM       | ✅ Active | `pmg npm install <package>` |
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

## Environment Variables

- `SAFEDEP_API_KEY`: Your SafeDep API key
- `SAFEDEP_TENANT_ID`: Your SafeDep tenant ID

Visit https://docs.safedep.io/cloud/quickstart for instructions on obtaining your API Key and Tenant ID.

## Usage

### Scanning NPM packages
```bash
pmg npm install <package-name>
```

OR
```bash
pmg npm i <package-name>
```
OR
```bash
pmg npm add <package-name>
```

## Contributing

Please feel free to submit a Pull Request.
