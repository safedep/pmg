package packagemanager

import (
	"slices"
	"strings"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"golang.org/x/mod/semver"
)

type GoPackageManagerConfig struct {
	CommandName string

	// InstallCommands accept module@version args on the command line, used to
	// extract pinned versions for cooldown reporting.
	InstallCommands []string

	// NonDownloadCommands never load packages and therefore never fetch
	// modules. Deliberately minimal: fmt/clean/vet/fix/doc/mod-graph load
	// packages and can download already-required modules on a cold cache even
	// under -mod=readonly, so they are excluded on purpose and run with the
	// proxy.
	NonDownloadCommands []string
}

func DefaultGoPackageManagerConfig() GoPackageManagerConfig {
	return GoPackageManagerConfig{
		CommandName:         "go",
		InstallCommands:     []string{"get", "install", "run"},
		NonDownloadCommands: []string{"version", "env", "help"},
	}
}

type goPackageManager struct {
	Config GoPackageManagerConfig
}

func NewGoPackageManager(config GoPackageManagerConfig) (*goPackageManager, error) {
	return &goPackageManager{Config: config}, nil
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

	parsed := &ParsedCommand{Command: Command{Exe: g.Config.CommandName, Args: args}}

	subcmd, rest := FirstNonFlagArg(args, nil)
	if subcmd == "" {
		return parsed, nil
	}

	if slices.Contains(g.Config.NonDownloadCommands, subcmd) {
		parsed.IsKnownNonDownloadCommand = true
		return parsed, nil
	}

	if slices.Contains(g.Config.InstallCommands, subcmd) {
		parsed.InstallTargets = goRemoteModuleTargets(rest)
		return parsed, nil
	}

	if subcmd == "mod" {
		modCmd, modRest := FirstNonFlagArg(rest, nil)
		switch modCmd {
		case "tidy":
			parsed.IsManifestInstall = true
		case "download":
			parsed.InstallTargets = goRemoteModuleTargets(modRest)
			if len(parsed.InstallTargets) == 0 {
				parsed.IsManifestInstall = true
			}
		}
	}

	return parsed, nil
}

// goRemoteModuleTargets extracts remote module targets (module[@version]) from
// command args, skipping flags, local paths and meta-patterns. Version queries
// (@latest, branch names, commit hashes) are passed through for go to resolve;
// only canonical semver counts as an explicit version for cooldown reporting.
func goRemoteModuleTargets(args []string) []*PackageInstallTarget {
	var targets []*PackageInstallTarget

	for _, arg := range args {
		if strings.HasPrefix(arg, "-") || !isGoRemoteModuleTarget(arg) {
			continue
		}

		name, version := arg, ""
		if at := strings.LastIndex(arg, "@"); at > 0 {
			name, version = arg[:at], arg[at+1:]
		}

		targets = append(targets, &PackageInstallTarget{
			PackageVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_GO,
					Name:      name,
				},
				Version: version,
			},
			IsExplicitVersion: semver.IsValid(version) && semver.Canonical(version) == version,
		})
	}

	return targets
}

// isGoRemoteModuleTarget discriminates a remote module target from a local
// path or meta-pattern: a remote target's first path segment is a domain
// (contains a dot), so `go install ./cmd/foo` and `go build ./...` yield no
// targets while `go get github.com/x/y@v1.2.3` does.
func isGoRemoteModuleTarget(target string) bool {
	target = strings.TrimSpace(target)
	if target == "" || target == "." || target == ".." {
		return false
	}

	if strings.HasPrefix(target, "./") || strings.HasPrefix(target, "../") || strings.HasPrefix(target, "/") {
		return false
	}

	if strings.Contains(target, `\`) {
		return false
	}

	firstSegment, _, _ := strings.Cut(target, "/")
	if firstSegment == "..." {
		return false
	}

	return strings.Contains(firstSegment, ".")
}
