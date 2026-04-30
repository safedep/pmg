package packagemanager

import (
	"fmt"
	"strings"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
)

type GoPackageManagerConfig struct {
	CommandName string
}

func DefaultGoPackageManagerConfig() GoPackageManagerConfig {
	return GoPackageManagerConfig{
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
	if len(args) == 0 {
		return &ParsedCommand{Command: command}, nil
	}

	subcmdIndex := goFirstNonFlagArgIndex(args)
	if subcmdIndex == -1 {
		return &ParsedCommand{Command: command}, nil
	}

	switch args[subcmdIndex] {
	case "build", "test", "fmt", "fix", "generate", "tool", "version", "env", "vet":
		return &ParsedCommand{
			Command:                   command,
			IsKnownNonDownloadCommand: true,
		}, nil
	case "install":
		return g.parseGoInstall(command, args[subcmdIndex+1:])
	case "run":
		return g.parseGoRun(command, args[subcmdIndex+1:])
	case "get":
		return g.parseGoGet(command, args[subcmdIndex+1:])
	case "mod":
		return g.parseGoMod(command, args[subcmdIndex+1:])
	default:
		return &ParsedCommand{Command: command}, nil
	}
}

func (g *goPackageManager) parseGoInstall(command Command, args []string) (*ParsedCommand, error) {
	targets, err := goParseRemoteModuleTargets(args, true)
	if err != nil {
		return nil, err
	}

	return &ParsedCommand{
		Command:        command,
		InstallTargets: targets,
	}, nil
}

func (g *goPackageManager) parseGoRun(command Command, args []string) (*ParsedCommand, error) {
	targets, err := goParseRemoteModuleTargets(args, false)
	if err != nil {
		return nil, err
	}

	return &ParsedCommand{
		Command:        command,
		InstallTargets: targets,
	}, nil
}

func (g *goPackageManager) parseGoGet(command Command, args []string) (*ParsedCommand, error) {
	targets, err := goParseRemoteModuleTargets(args, false)
	if err != nil {
		return nil, err
	}

	return &ParsedCommand{
		Command:        command,
		InstallTargets: targets,
	}, nil
}

func (g *goPackageManager) parseGoMod(command Command, args []string) (*ParsedCommand, error) {
	if len(args) == 0 {
		return &ParsedCommand{Command: command}, nil
	}

	subcmdIndex := goFirstNonFlagArgIndex(args)
	if subcmdIndex == -1 {
		return &ParsedCommand{Command: command}, nil
	}

	switch args[subcmdIndex] {
	case "tidy":
		return &ParsedCommand{
			Command:           command,
			IsManifestInstall: true,
			ManifestFiles:     []string{"go.mod", "go.sum"},
		}, nil
	case "download":
		targets, err := goParseRemoteModuleTargets(args[subcmdIndex+1:], false)
		if err != nil {
			return nil, err
		}

		return &ParsedCommand{
			Command:           command,
			InstallTargets:    targets,
			IsManifestInstall: len(targets) == 0,
			ManifestFiles:     []string{"go.mod", "go.sum"},
		}, nil
	default:
		return &ParsedCommand{Command: command}, nil
	}
}

func goFirstNonFlagArgIndex(args []string) int {
	for i, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		return i
	}

	return -1
}

func goParseRemoteModuleTargets(args []string, requireVersion bool) ([]*PackageInstallTarget, error) {
	var targets []*PackageInstallTarget

	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}

		if !isGoRemoteModuleTarget(arg) {
			continue
		}

		name, version, err := goParseModuleSpec(arg)
		if err != nil {
			return nil, ErrFailedToParsePackage.Wrap(err)
		}

		if requireVersion && version == "" {
			continue
		}

		targets = append(targets, &PackageInstallTarget{
			PackageVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_GO,
					Name:      name,
				},
				Version: version,
			},
		})
	}

	return targets, nil
}

func goParseModuleSpec(input string) (string, string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", "", fmt.Errorf("module target cannot be empty")
	}

	if !isGoRemoteModuleTarget(input) {
		return "", "", fmt.Errorf("not a remote module target: %s", input)
	}

	lastAt := strings.LastIndex(input, "@")
	if lastAt <= 0 {
		return input, "", nil
	}

	name := strings.TrimSpace(input[:lastAt])
	version := strings.TrimSpace(input[lastAt+1:])
	if name == "" {
		return "", "", fmt.Errorf("module name cannot be empty")
	}
	if version == "" {
		return "", "", fmt.Errorf("module version cannot be empty")
	}

	return name, version, nil
}

func isGoRemoteModuleTarget(target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}

	if strings.HasPrefix(target, "-") {
		return false
	}

	if target == "." || target == ".." {
		return false
	}

	if strings.HasPrefix(target, "./") || strings.HasPrefix(target, "../") || strings.HasPrefix(target, "/") {
		return false
	}

	if strings.Contains(target, `\`) {
		return false
	}

	firstSegment := target
	if slash := strings.Index(target, "/"); slash >= 0 {
		firstSegment = target[:slash]
	}

	if firstSegment == "..." {
		return false
	}

	return strings.Contains(firstSegment, ".")
}
