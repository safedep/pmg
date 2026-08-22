package packagemanager

import (
	"regexp"
	"slices"
	"strings"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
)

type CargoPackageManagerConfig struct {
	CommandName string

	// InstallCommands accept crate[@version] args on the command line, used to
	// extract pinned versions for cooldown reporting.
	InstallCommands []string

	// ManifestCommands resolve and download dependencies from Cargo.toml /
	// Cargo.lock without naming crates on the command line. Unlike npm/pip,
	// cargo executes third-party code (build scripts, proc macros) at build
	// time, so build/run/test are dependency-installing commands, not
	// pass-throughs.
	ManifestCommands []string

	// NonDownloadCommands never resolve dependencies and therefore never fetch
	// crates. Deliberately minimal: metadata/tree/fmt resolve the dependency
	// graph and can fetch the index on a cold cache, so they are excluded on
	// purpose and run with the proxy.
	NonDownloadCommands []string
}

func DefaultCargoPackageManagerConfig() CargoPackageManagerConfig {
	return CargoPackageManagerConfig{
		CommandName:     "cargo",
		InstallCommands: []string{"add", "install"},
		ManifestCommands: []string{
			"build", "b", "check", "c", "run", "r", "test", "t", "bench",
			"doc", "d", "fetch", "update", "generate-lockfile", "vendor",
			"package", "publish", "clippy",
		},
		NonDownloadCommands: []string{"version", "help", "clean", "new", "init", "locate-project"},
	}
}

type cargoPackageManager struct {
	Config CargoPackageManagerConfig
}

func NewCargoPackageManager(config CargoPackageManagerConfig) (*cargoPackageManager, error) {
	return &cargoPackageManager{Config: config}, nil
}

var _ PackageManager = &cargoPackageManager{}

func (c *cargoPackageManager) Name() string {
	return c.Config.CommandName
}

func (c *cargoPackageManager) Ecosystem() packagev1.Ecosystem {
	return packagev1.Ecosystem_ECOSYSTEM_CARGO
}

func (c *cargoPackageManager) ParseCommand(args []string) (*ParsedCommand, error) {
	if len(args) > 0 && args[0] == c.Config.CommandName {
		args = args[1:]
	}

	parsed := &ParsedCommand{Command: Command{Exe: c.Config.CommandName, Args: args}}

	subcmd, rest := cargoFirstNonFlagArg(args)
	if subcmd == "" {
		return parsed, nil
	}

	if slices.Contains(c.Config.NonDownloadCommands, subcmd) {
		parsed.IsKnownNonDownloadCommand = true
		return parsed, nil
	}

	if slices.Contains(c.Config.ManifestCommands, subcmd) {
		parsed.IsManifestInstall = true
		return parsed, nil
	}

	if slices.Contains(c.Config.InstallCommands, subcmd) {
		parsed.InstallTargets = cargoCrateTargets(rest)
		if len(parsed.InstallTargets) == 0 {
			// `cargo install --path .` builds a local crate; its dependencies
			// still come from the registry.
			parsed.IsManifestInstall = true
		}
	}

	return parsed, nil
}

func cargoFirstNonFlagArg(args []string) (string, []string) {
	for i, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		return arg, args[i+1:]
	}
	return "", nil
}

// cargoValueFlags are add/install flags that consume the next argument, so
// their values are not mistaken for crate names.
var cargoValueFlags = map[string]bool{
	"--version": true, "--vers": true,
	"--features": true, "-F": true,
	"--registry": true, "--index": true,
	"--path": true, "--git": true, "--branch": true, "--tag": true, "--rev": true,
	"--rename": true, "--package": true, "-p": true,
	"--manifest-path": true, "--target-dir": true, "--root": true,
	"--target": true, "--profile": true, "--config": true,
	"--jobs": true, "-j": true, "--color": true, "-Z": true,
}

// cargoExactVersion matches a fully-specified semver version. Anything else
// (^1.0, ~1, 1.0, wildcard requirements) is a range cargo resolves, so it does
// not count as an explicit version for cooldown reporting.
var cargoExactVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)

// cargoCrateName matches valid crates.io package names. Local paths and git
// URLs (values of flags not on the skip list) never match.
var cargoCrateName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

// cargoCrateTargets extracts crate targets (crate[@version-req]) from add/install
// args. A version requirement is stripped of leading =; only an exact semver
// counts as explicit. `cargo install crate --version <v>` is folded into every
// versionless target, matching cargo's semantics for the flag.
func cargoCrateTargets(args []string) []*PackageInstallTarget {
	var targets []*PackageInstallTarget
	flagVersion := ""

	for i := 0; i < len(args); i++ {
		arg := args[i]

		if strings.HasPrefix(arg, "-") {
			if flag, value, hasValue := strings.Cut(arg, "="); cargoValueFlags[flag] {
				if (flag == "--version" || flag == "--vers") && hasValue {
					flagVersion = strings.TrimPrefix(value, "=")
				}
				if !hasValue && i+1 < len(args) {
					if flag == "--version" || flag == "--vers" {
						flagVersion = strings.TrimPrefix(args[i+1], "=")
					}
					i++
				}
			}
			continue
		}

		name, version := arg, ""
		if at := strings.LastIndex(arg, "@"); at > 0 {
			name, version = arg[:at], strings.TrimPrefix(arg[at+1:], "=")
		}

		if !cargoCrateName.MatchString(name) {
			continue
		}

		targets = append(targets, &PackageInstallTarget{
			PackageVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_CARGO,
					Name:      name,
				},
				Version: version,
			},
			IsExplicitVersion: cargoExactVersion.MatchString(version),
		})
	}

	if flagVersion != "" {
		for _, target := range targets {
			if !target.HasVersion() {
				target.PackageVersion.SetVersion(flagVersion)
				target.IsExplicitVersion = cargoExactVersion.MatchString(flagVersion)
			}
		}
	}

	return targets
}
