package packagemanager

import (
	"io"
	"slices"
	"strings"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/spf13/pflag"
)

type GoPackageManagerConfig struct {
	InstallCommands     []string
	NonDownloadCommands []string
	CommandName         string
}

func DefaultGoPackageManagerConfig() GoPackageManagerConfig {
	return GoPackageManagerConfig{
		// go get and go install are primary install commands
		// go mod download and go mod tidy are manifest-based
		InstallCommands: []string{"get", "install", "download", "tidy"},
		NonDownloadCommands: []string{
			"build", "test", "run", "vet", "fmt", "doc", "env", "version", "help",
			"tool", "bug", "fix", "generate", "list", "work",
		},
		CommandName: "go",
	}
}

type goPackageManager struct {
	Config GoPackageManagerConfig
}

func NewGoPackageManager(config GoPackageManagerConfig) (*goPackageManager, error) {
	return &goPackageManager{
		Config: config,
	}, nil
}

var _ PackageManager = &goPackageManager{}

func (g *goPackageManager) Name() string {
	return g.Config.CommandName
}

func (g *goPackageManager) Ecosystem() packagev1.Ecosystem {
	return packagev1.Ecosystem_ECOSYSTEM_GO
}

func (g *goPackageManager) ParseCommand(args []string) (*ParsedCommand, error) {
	if len(args) > 0 && args[0] == g.Config.CommandName {
		args = args[1:]
	}

	command := Command{Exe: g.Config.CommandName, Args: args}

	if len(args) < 1 {
		return &ParsedCommand{Command: command}, nil
	}

	subCommand := args[0]
	
	// Special handling for 'go mod' subcommands
	if subCommand == "mod" && len(args) > 1 {
		modSubCmd := args[1]
		if modSubCmd == "download" || modSubCmd == "tidy" {
			return &ParsedCommand{
				Command:           command,
				IsManifestInstall: true,
				ManifestFiles:     []string{"go.mod"},
			}, nil
		}
	}

	if !slices.Contains(g.Config.InstallCommands, subCommand) {
		return &ParsedCommand{
			Command:                   command,
			IsKnownNonDownloadCommand: IsFirstNonFlagArgInList(args, g.Config.NonDownloadCommands),
		}, nil
	}

	// For go get and go install
	var packages []string
	flagSet := pflag.NewFlagSet("go", pflag.ContinueOnError)
	flagSet.SetOutput(io.Discard)
	flagSet.ParseErrorsAllowlist.UnknownFlags = true

	// go get common flags
	flagSet.BoolP("u", "u", false, "update")
	flagSet.BoolP("t", "t", false, "test")
	flagSet.BoolP("d", "d", false, "download only")

	err := flagSet.Parse(args[1:])
	if err != nil {
		return &ParsedCommand{Command: command}, nil
	}

	packages = flagSet.Args()

	// If no packages specified for go get/install, it might be working on the current module
	if len(packages) == 0 {
		if subCommand == "get" || subCommand == "install" {
			return &ParsedCommand{
				Command:           command,
				IsManifestInstall: true,
				ManifestFiles:     []string{"go.mod"},
			}, nil
		}
	}

	var installTargets []*PackageInstallTarget
	for _, pkg := range packages {
		packageName, version := goParsePackageInfo(pkg)
		installTargets = append(installTargets, &PackageInstallTarget{
			IsExplicitVersion: version != "",
			PackageVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_GO,
					Name:      packageName,
				},
				Version: version,
			},
		})
	}

	return &ParsedCommand{
		Command:           command,
		InstallTargets:    installTargets,
		IsManifestInstall: false,
		ManifestFiles:     []string{},
	}, nil
}

func goParsePackageInfo(input string) (packageName, version string) {
	// go get package@version
	parts := strings.Split(input, "@")
	if len(parts) == 2 {
		return parts[0], parts[1]
	}

	return input, ""
}
