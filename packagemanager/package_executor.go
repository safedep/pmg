package packagemanager

import packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"

// PackageExecutor is the contract for implementing a package executor
type PackageExecutor interface {
	// Name of the package executor implementation
	Name() string

	// ParseCommand parses the command and returns a parsed command
	// specific to the package executor implementation
	ParsedCommand(args []string) (*ParsedCommand, error)

	// Ecosystem of the package manager
	Ecosystem() packagev1.Ecosystem
}
