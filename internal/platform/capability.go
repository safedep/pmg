package platform

import "runtime"

// Capability is a platform trait feature code asks about instead of naming an
// OS. Supports answers whether the current platform has it.
type Capability int

const (
	// ShellAliases is the shell alias layer PMG writes into rc files. Windows
	// has none: the .cmd shims on PATH are the whole interception layer there.
	ShellAliases Capability = iota
	// SystemInstall is a machine-wide `pmg setup install --system`.
	SystemInstall
	// MachineWidePath means a system install reaches every user through the
	// machine PATH, not a login-shell profile.
	MachineWidePath
	// EnforcingProxy is a root proxy daemon under kernel enforcement
	// (`pmg proxy start --enforce`). It is the only reader of the system CA
	// keypair.
	EnforcingProxy
)

// Supports reports whether the current platform has the capability.
func Supports(c Capability) bool { return supports(c) }

// OSName is the runtime OS, for a diagnostic message or to key OS-specific
// data. Do not branch on it to decide behavior: ask Supports.
func OSName() string { return runtime.GOOS }
