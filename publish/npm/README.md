<div align="center">
  <img src="https://raw.githubusercontent.com/safedep/pmg/main/docs/assets/pmg-banner.png" alt="PMG banner">
</div>

# Package Manager Guard (PMG)

PMG intercepts package installs and checks them for malware before code executes. Install it once, and your usual package manager workflows can stay the same.

This package is the npm distribution of PMG. The main project README at [`github.com/safedep/pmg`](https://github.com/safedep/pmg) is the source of truth for full documentation.

## Why PMG?

- Protects developers and AI coding agents from malicious packages
- Wraps tools like `npm`, `pnpm`, `yarn`, `pip`, `poetry`, and `uv`
- Adds sandboxing and install-time security checks with minimal workflow changes

## Install

```bash
npm install -g @safedep/pmg
```

You can also install PMG with Homebrew:

```bash
brew tap safedep/tap
brew install safedep/tap/pmg
```

## Quick Start

Set up PMG so your normal package manager commands are protected automatically:

```bash
pmg setup install
```

After setup, restart your terminal and keep using your tools as usual:

```bash
npm install express
pnpm add react
pip install requests
```

If you prefer, you can also run package manager commands through PMG directly:

```bash
pmg npm install express
pmg pnpm add react
pmg pip install requests
```

## Platform Support

- macOS
- Linux
- Windows

Requires Node.js 14 or higher.

## Learn More

For complete documentation, installation options, troubleshooting, and project updates, see:

- [Main README](https://github.com/safedep/pmg)
- [Quickstart Docs](https://docs.safedep.io/pmg/quickstart)
