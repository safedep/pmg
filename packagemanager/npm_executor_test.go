package packagemanager

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNpxExecutorParseCommand(t *testing.T) {
	cases := []struct {
		name    string
		command string
		assert  func(t *testing.T, parsed *ParsedCommand, err error)
	}{
		{
			name:    "bare npx invocation",
			command: "npx",
			assert: func(t *testing.T, parsed *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, parsed)
				assert.Equal(t, 0, len(parsed.InstallTargets))
			},
		},
		{
			name:    "scoped package via -p flag",
			command: "npx -p @types/node",
			assert: func(t *testing.T, parsed *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 1, len(parsed.InstallTargets))
				assert.Equal(t, "@types/node", parsed.InstallTargets[0].PackageVersion.Package.Name)
				assert.Empty(t, parsed.InstallTargets[0].PackageVersion.Version)
			},
		},
		{
			name:    "scoped package with version",
			command: "npx @types/node@1.2.3",
			assert: func(t *testing.T, parsed *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 1, len(parsed.InstallTargets))
				assert.Equal(t, "@types/node", parsed.InstallTargets[0].PackageVersion.Package.Name)
				assert.Equal(t, "1.2.3", parsed.InstallTargets[0].PackageVersion.Version)
			},
		},
		{
			name:    "package as first positional arg",
			command: "npx create-react-app my-app",
			assert: func(t *testing.T, parsed *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 1, len(parsed.InstallTargets))
				assert.Equal(t, "create-react-app", parsed.InstallTargets[0].PackageVersion.Package.Name)
				assert.Equal(t, []string{"create-react-app", "my-app"}, parsed.Command.Args)
			},
		},
		{
			name:    "package with version as first positional arg",
			command: "npx cowsay@1.6.0 hello",
			assert: func(t *testing.T, parsed *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 1, len(parsed.InstallTargets))
				assert.Equal(t, "cowsay", parsed.InstallTargets[0].PackageVersion.Package.Name)
				assert.Equal(t, "1.6.0", parsed.InstallTargets[0].PackageVersion.Version)
			},
		},
		{
			name:    "package via -p flag with different binary",
			command: "npx -p typescript tsc --version",
			assert: func(t *testing.T, parsed *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 1, len(parsed.InstallTargets))
				assert.Equal(t, "typescript", parsed.InstallTargets[0].PackageVersion.Package.Name)
				assert.Empty(t, parsed.InstallTargets[0].PackageVersion.Version)
				// tsc is the binary, not a package
				assert.Equal(t, []string{"-p", "typescript", "tsc", "--version"}, parsed.Command.Args)
			},
		},
		{
			name:    "single package using -p flag npx command with binary",
			command: "npx -p tsx my-app",
			assert: func(t *testing.T, parsed *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 1, len(parsed.InstallTargets))
				assert.Equal(t, "tsx", parsed.InstallTargets[0].PackageVersion.Package.Name)
				assert.Empty(t, parsed.InstallTargets[0].PackageVersion.Version)
			},
		},
		{
			name:    "single package using --package flag npx command with binary",
			command: "npx --package=tsx my-app",
			assert: func(t *testing.T, parsed *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 1, len(parsed.InstallTargets))
				assert.Equal(t, "tsx", parsed.InstallTargets[0].PackageVersion.Package.Name)
				assert.Empty(t, parsed.InstallTargets[0].PackageVersion.Version)
			},
		},
		{
			name:    "multiple scoped packages via flags and args",
			command: "npx -p @types/node @react@2.0.0",
			assert: func(t *testing.T, parsed *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 2, len(parsed.InstallTargets))
				assert.Equal(t, "@types/node", parsed.InstallTargets[0].PackageVersion.Package.Name)
				assert.Empty(t, parsed.InstallTargets[0].PackageVersion.Version)
				assert.Equal(t, "@react", parsed.InstallTargets[1].PackageVersion.Package.Name)
				assert.Equal(t, "2.0.0", parsed.InstallTargets[1].PackageVersion.Version)
			},
		},
		{
			name:    "multiple packages via flags and scoped",
			command: "npx @types/node -p react@2.0.0",
			assert: func(t *testing.T, parsed *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 2, len(parsed.InstallTargets))
				assert.Equal(t, "@types/node", parsed.InstallTargets[1].PackageVersion.Package.Name)
				assert.Empty(t, parsed.InstallTargets[1].PackageVersion.Version)
				assert.Equal(t, "react", parsed.InstallTargets[0].PackageVersion.Package.Name)
				assert.Equal(t, "2.0.0", parsed.InstallTargets[0].PackageVersion.Version)
			},
		},
		{
			name:    "multiple packages via flags and args",
			command: "npx -p node -p react@2.0.0",
			assert: func(t *testing.T, parsed *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 2, len(parsed.InstallTargets))
				assert.Equal(t, "node", parsed.InstallTargets[0].PackageVersion.Package.Name)
				assert.Empty(t, parsed.InstallTargets[0].PackageVersion.Version)
				assert.Equal(t, "react", parsed.InstallTargets[1].PackageVersion.Package.Name)
				assert.Equal(t, "2.0.0", parsed.InstallTargets[1].PackageVersion.Version)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exec := &npmPackageExecutor{Config: DefaultNpxPackageExecutorConfig()}
			parsed, err := exec.ParseCommand(strings.Split(tc.command, " "))
			tc.assert(t, parsed, err)
		})
	}
}

func TestPnpxExecutorParseCommand(t *testing.T) {
	cases := []struct {
		name    string
		command string
		assert  func(t *testing.T, parsed *ParsedCommand, err error)
	}{
		{
			name:    "bare pnpx invocation",
			command: "pnpx",
			assert: func(t *testing.T, parsed *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, parsed)
				assert.Equal(t, 0, len(parsed.InstallTargets))
			},
		},
		{
			name:    "scoped package via package flag",
			command: "pnpx --package=@types/node",
			assert: func(t *testing.T, parsed *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 1, len(parsed.InstallTargets))
				assert.Equal(t, "@types/node", parsed.InstallTargets[0].PackageVersion.Package.Name)
				assert.Empty(t, parsed.InstallTargets[0].PackageVersion.Version)
			},
		},
		{
			name:    "scoped package with version",
			command: "pnpx @types/node@1.2.3",
			assert: func(t *testing.T, parsed *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 1, len(parsed.InstallTargets))
				assert.Equal(t, "@types/node", parsed.InstallTargets[0].PackageVersion.Package.Name)
				assert.Equal(t, "1.2.3", parsed.InstallTargets[0].PackageVersion.Version)
			},
		},
		{
			name:    "single package command",
			command: "pnpx tsx my-app",
			assert: func(t *testing.T, parsed *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 1, len(parsed.InstallTargets))
				assert.Equal(t, "tsx", parsed.InstallTargets[0].PackageVersion.Package.Name)
				assert.Empty(t, parsed.InstallTargets[0].PackageVersion.Version)
			},
		},
		{
			name:    "multiple scoped packages via flags and args",
			command: "pnpx --package @types/node @react@2.0.0",
			assert: func(t *testing.T, parsed *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 2, len(parsed.InstallTargets))
				assert.Equal(t, "@types/node", parsed.InstallTargets[0].PackageVersion.Package.Name)
				assert.Empty(t, parsed.InstallTargets[0].PackageVersion.Version)
				assert.Equal(t, "@react", parsed.InstallTargets[1].PackageVersion.Package.Name)
				assert.Equal(t, "2.0.0", parsed.InstallTargets[1].PackageVersion.Version)
			},
		},
		{
			name:    "multiple packages via flags and scoped",
			command: "pnpx @types/node --package react@2.0.0",
			assert: func(t *testing.T, parsed *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 2, len(parsed.InstallTargets))
				assert.Equal(t, "@types/node", parsed.InstallTargets[1].PackageVersion.Package.Name)
				assert.Empty(t, parsed.InstallTargets[1].PackageVersion.Version)
				assert.Equal(t, "react", parsed.InstallTargets[0].PackageVersion.Package.Name)
				assert.Equal(t, "2.0.0", parsed.InstallTargets[0].PackageVersion.Version)
			},
		},
		{
			name:    "multiple packages via flags and args",
			command: "pnpx --package node --package react@2.0.0",
			assert: func(t *testing.T, parsed *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 2, len(parsed.InstallTargets))
				assert.Equal(t, "node", parsed.InstallTargets[0].PackageVersion.Package.Name)
				assert.Empty(t, parsed.InstallTargets[0].PackageVersion.Version)
				assert.Equal(t, "react", parsed.InstallTargets[1].PackageVersion.Package.Name)
				assert.Equal(t, "2.0.0", parsed.InstallTargets[1].PackageVersion.Version)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exec := &npmPackageExecutor{Config: DefaultPnpxPackageExecutorConfig()}
			parsed, err := exec.ParseCommand(strings.Split(tc.command, " "))
			tc.assert(t, parsed, err)
		})
	}
}
