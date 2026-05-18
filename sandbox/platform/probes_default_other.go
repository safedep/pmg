//go:build !darwin && !linux
// +build !darwin,!linux

package platform

import "github.com/safedep/pmg/sandbox"

// DefaultProbes returns no probes on unsupported platforms.
func DefaultProbes() []sandbox.Probe { return nil }
