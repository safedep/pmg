# PMG - Package Manager Guard


🤖 PMG protects developers from getting compromised by malicious open source packages.

This is the npm distribution of PMG, a tool that wraps your favorite package manager (e.g., `npm`) and blocks malicious packages at install time.

## Installation

Install PMG globally via npm:

```bash
npm install -g @safedep/pmg
```

Or using Homebrew:

```bash
brew tap safedep/tap
brew install safedep/tap/pmg
```

## Usage

Set up PMG to automatically protect your package installations:

```bash
# Recommended: Set up automatic protection
pmg setup install
```

After setup, use your package managers normally:

```bash
# Your regular commands are now protected
npm install express
pnpm add react
pip install requests
```

Or use PMG manually without setup:

```bash
# Manual protection (alternative)
pmg npm install express
pmg pnpm add react
pmg pip install requests
```

## Platform Support

- ✅ **macOS** (Intel & Apple Silicon)
- ✅ **Linux** (x86_64, ARM64, i386)
- ✅ **Windows** (x86_64, ARM64, i386)

Requires Node.js 14 or higher.

---

For complete documentation, advanced usage, troubleshooting, and more information, please visit: **[github.com/safedep/pmg](https://github.com/safedep/pmg)**
